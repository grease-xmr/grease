//! State object for a channel undergoing a force close / dispute resolution.
//!
//! This state is entered when a cooperative close fails and one party initiates
//! a force close via the KES (Key Encryption Server). The channel can be in
//! dispute until either:
//! - The dispute window expires and the claimant can claim
//! - The defendant proves a more recent state
//! - The parties reach consensus

use crate::channel_id::ChannelId;
use crate::channel_metadata::ChannelMetadata;
use crate::cryptography::keys::Curve25519PublicKey;
use crate::cryptography::zk_objects::KesProof;
use crate::grease_protocol::force_close_channel::{
    ClaimChannelRequest, ConsensusCloseRequest, DisputeChannelState as DisputeMessage, DisputeResolution,
    ForceCloseProtocolClaimant, ForceCloseProtocolCommon, ForceCloseProtocolDefendant, ForceCloseProtocolError,
    ForceCloseRequest, ForceCloseResponse, PendingChannelClose, PendingCloseStatus,
};
use crate::lifecycle_impl;
use crate::monero::data_objects::{TransactionId, TransactionRecord};
use crate::multisig::MultisigWalletData;
use crate::payment_channel::{ChannelRole, HasRole};
use crate::state_machine::closed_channel::{ChannelClosedReason, ClosedChannelState};
use crate::state_machine::error::LifeCycleError;
use crate::state_machine::open_channel::UpdateRecord;
use crate::XmrScalar;
use monero::Network;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Default dispute window duration in seconds (24 hours).
pub const DEFAULT_DISPUTE_WINDOW_SECS: u64 = 24 * 60 * 60;

/// State for a channel undergoing force close / dispute resolution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisputingChannelState {
    pub(crate) metadata: ChannelMetadata,
    /// The reason this dispute was initiated
    pub(crate) reason: DisputeReason,
    /// Wallet data needed for transaction creation
    pub(crate) multisig_wallet: MultisigWalletData,
    /// Funding transaction records
    pub(crate) funding_transactions: HashMap<TransactionId, TransactionRecord>,
    /// KES proof data
    pub(crate) kes_proof: KesProof,
    /// Last update record from the open channel state
    pub(crate) last_update: UpdateRecord,
    /// Status of the pending close operation
    pub(crate) status: PendingCloseStatus,
    /// Pending close notification (if we are the defendant)
    pub(crate) pending_close: Option<PendingChannelClose>,
    /// Dispute window end timestamp (unix seconds)
    pub(crate) dispute_window_end: Option<u64>,
    /// Final transaction ID once resolved
    pub(crate) final_tx: Option<TransactionId>,
}

/// Reason for entering the disputing state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DisputeReason {
    /// We initiated a force close because cooperative close failed
    ForceCloseInitiated,
    /// Peer initiated a force close against us
    PeerForceClose,
    /// Channel timed out waiting for peer response
    Timeout,
}

impl DisputingChannelState {
    /// Create a new disputing state from an established channel.
    pub fn from_open_channel(
        metadata: ChannelMetadata,
        reason: DisputeReason,
        multisig_wallet: MultisigWalletData,
        funding_transactions: HashMap<TransactionId, TransactionRecord>,
        kes_proof: KesProof,
        last_update: UpdateRecord,
    ) -> Self {
        Self {
            metadata,
            reason,
            multisig_wallet,
            funding_transactions,
            kes_proof,
            last_update,
            status: PendingCloseStatus::Pending,
            pending_close: None,
            dispute_window_end: None,
            final_tx: None,
        }
    }

    pub fn to_channel_state(self) -> ChannelState {
        ChannelState::Disputing(self)
    }

    pub fn multisig_address(&self, _network: Network) -> Option<String> {
        // TODO: Implement multisig address retrieval
        None
    }

    pub fn status(&self) -> PendingCloseStatus {
        self.status
    }

    pub fn reason(&self) -> &DisputeReason {
        &self.reason
    }

    pub fn dispute_window_end(&self) -> Option<u64> {
        self.dispute_window_end
    }

    /// Returns the keys needed to reconstruct the multisig wallet.
    /// Warning! The result of this function contains wallet secrets!
    pub fn wallet_data(&self) -> MultisigWalletData {
        let mut data = self.multisig_wallet.clone();
        self.funding_transactions.values().for_each(|rec| {
            data.known_outputs.push(rec.serialized.clone());
        });
        data
    }

    pub fn with_final_tx(&mut self, final_tx: TransactionId) {
        let prev = self.final_tx.take();
        if prev.is_some() {
            log::warn!(
                "Overwriting existing final transaction {} in DisputingChannelState",
                prev.as_ref().unwrap().id
            );
        }
        self.final_tx = Some(final_tx);
    }

    /// Check if the dispute can transition to closed state.
    pub fn requirements_met(&self) -> bool {
        matches!(
            self.status,
            PendingCloseStatus::ForceClosed | PendingCloseStatus::ConsensusClosed | PendingCloseStatus::DisputeSuccessful
        ) && self.final_tx.is_some()
    }

    #[allow(clippy::result_large_err)]
    pub fn next(self) -> Result<ClosedChannelState, (Self, LifeCycleError)> {
        if !self.requirements_met() {
            return Err((self, LifeCycleError::InvalidStateTransition));
        }

        let reason = match self.status {
            PendingCloseStatus::ForceClosed => ChannelClosedReason::ForceClosed,
            PendingCloseStatus::ConsensusClosed => ChannelClosedReason::Normal,
            PendingCloseStatus::DisputeSuccessful => ChannelClosedReason::Disputed,
            _ => return Err((self, LifeCycleError::InvalidStateTransition)),
        };

        let closed_state = ClosedChannelState::new(reason, self.metadata.clone());
        Ok(closed_state)
    }
}

use crate::state_machine::lifecycle::{ChannelState, LifeCycle, LifecycleStage};

lifecycle_impl!(DisputingChannelState, Disputing);

// --- Protocol Trait Implementations ---

impl HasRole for DisputingChannelState {
    fn role(&self) -> ChannelRole {
        self.metadata.role()
    }
}

impl ForceCloseProtocolCommon for DisputingChannelState {
    fn channel_id(&self) -> ChannelId {
        self.metadata.channel_id().name()
    }

    fn public_key(&self) -> &Curve25519PublicKey {
        &self.multisig_wallet.my_public_key
    }

    fn peer_public_key(&self) -> &Curve25519PublicKey {
        // The peer is the other key in sorted_pubkeys
        let my_key = self.public_key();
        if &self.multisig_wallet.sorted_pubkeys[0] == my_key {
            &self.multisig_wallet.sorted_pubkeys[1]
        } else {
            &self.multisig_wallet.sorted_pubkeys[0]
        }
    }

    fn dispute_window_secs(&self) -> u64 {
        DEFAULT_DISPUTE_WINDOW_SECS
    }

    fn update_count(&self) -> u64 {
        self.metadata.update_count()
    }

    fn sign_for_kes(&self, _message: &[u8]) -> Result<Vec<u8>, ForceCloseProtocolError> {
        // Signing requires wallet integration with the secret key.
        // The actual implementation would use self.multisig_wallet.my_spend_key
        Err(ForceCloseProtocolError::SignatureCreationFailed(
            "Signing requires external wallet integration".into(),
        ))
    }

    fn verify_peer_signature(&self, _message: &[u8], _sig: &[u8]) -> Result<(), ForceCloseProtocolError> {
        // Signature verification against peer_public_key
        // This would use standard Ed25519 verification
        Err(ForceCloseProtocolError::InvalidSignature(
            "Signature verification requires external wallet integration".into(),
        ))
    }
}

impl ForceCloseProtocolClaimant for DisputingChannelState {
    fn create_force_close_request(&self) -> Result<ForceCloseRequest, ForceCloseProtocolError> {
        // Create the request payload
        let channel_id = self.metadata.channel_id().name();
        let claimant = *self.public_key();
        let defendant = *self.peer_public_key();
        let update_count_claimed = self.update_count();

        // Sign the request (placeholder - actual signing needs wallet integration)
        let message = format!("{channel_id}:{update_count_claimed}");
        let signature = self.sign_for_kes(message.as_bytes())?;

        Ok(ForceCloseRequest { channel_id, claimant, defendant, update_count_claimed, signature })
    }

    fn handle_force_close_response(&mut self, response: ForceCloseResponse) -> Result<(), ForceCloseProtocolError> {
        match response {
            ForceCloseResponse::Accepted { dispute_window_end } => {
                self.dispute_window_end = Some(dispute_window_end);
                self.status = PendingCloseStatus::Pending;
                Ok(())
            }
            ForceCloseResponse::Rejected { reason } => Err(ForceCloseProtocolError::KesRejected(reason)),
        }
    }

    fn create_claim_request(&self) -> Result<ClaimChannelRequest, ForceCloseProtocolError> {
        // Verify dispute window has passed
        if let Some(end) = self.dispute_window_end {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            if now < end {
                return Err(ForceCloseProtocolError::DisputeWindowActive);
            }
        } else {
            return Err(ForceCloseProtocolError::NoPendingForceClose);
        }

        let channel_id = self.metadata.channel_id().name();
        let claimant = *self.public_key();

        // Sign the claim request
        let message = format!("claim:{channel_id}");
        let signature = self.sign_for_kes(message.as_bytes())?;

        Ok(ClaimChannelRequest { channel_id, claimant, signature })
    }

    fn process_claimed_offset(&mut self, _encrypted: &[u8]) -> Result<XmrScalar, ForceCloseProtocolError> {
        // Decrypt the offset using our secret key
        // This requires KES decryption with our channel key
        Err(ForceCloseProtocolError::DecryptionFailed(
            "Offset decryption requires KES integration".into(),
        ))
    }

    fn complete_closing_tx(&self, _peer_offset: &XmrScalar) -> Result<Vec<u8>, ForceCloseProtocolError> {
        // Create the closing transaction using the combined offsets
        // This requires Monero transaction creation
        Err(ForceCloseProtocolError::TransactionCreationFailed(
            "Transaction creation requires wallet integration".into(),
        ))
    }

    fn broadcast_closing_tx(&self, _tx: &[u8]) -> Result<TransactionId, ForceCloseProtocolError> {
        // Broadcast the transaction to the Monero network
        Err(ForceCloseProtocolError::BroadcastFailed(
            "Transaction broadcast requires network integration".into(),
        ))
    }
}

impl ForceCloseProtocolDefendant for DisputingChannelState {
    fn receive_force_close_notification(&mut self, notif: PendingChannelClose) -> Result<(), ForceCloseProtocolError> {
        if self.pending_close.is_some() {
            return Err(ForceCloseProtocolError::ForceCloseAlreadyPending);
        }

        // Validate the notification is for our channel
        if notif.channel_id != self.metadata.channel_id().name() {
            return Err(ForceCloseProtocolError::ChannelNotFound(
                "Channel ID mismatch in notification".into(),
            ));
        }

        self.pending_close = Some(notif.clone());
        self.dispute_window_end = Some(notif.dispute_window_end);
        self.status = PendingCloseStatus::Pending;
        Ok(())
    }

    fn has_more_recent_state(&self, claimed_count: u64) -> bool {
        self.update_count() > claimed_count
    }

    fn create_consensus_close(&self) -> Result<ConsensusCloseRequest, ForceCloseProtocolError> {
        use ciphersuite::group::ff::PrimeField;

        let pending = self.pending_close.as_ref().ok_or(ForceCloseProtocolError::NoPendingForceClose)?;

        let channel_id = self.metadata.channel_id().name();
        let claimant = pending.claimant;
        let defendant = *self.public_key();
        let update_count_claimed = pending.update_count_claimed;

        // Encrypt our offset for the KES
        let offset = &self.last_update.my_proofs.private_outputs.witness_i;
        let encrypted_offset = offset.to_repr().to_vec();

        // Sign the consensus close
        let message = format!("consensus:{channel_id}:{update_count_claimed}");
        let signature = self.sign_for_kes(message.as_bytes())?;

        Ok(ConsensusCloseRequest {
            channel_id,
            claimant,
            defendant,
            update_count_claimed,
            encrypted_offset,
            signature,
        })
    }

    fn create_dispute(&self) -> Result<DisputeMessage, ForceCloseProtocolError> {
        let pending = self.pending_close.as_ref().ok_or(ForceCloseProtocolError::NoPendingForceClose)?;

        // Verify we have a more recent state
        if !self.has_more_recent_state(pending.update_count_claimed) {
            return Err(ForceCloseProtocolError::UpdateCountTooLow {
                claimed: pending.update_count_claimed,
                actual: self.update_count(),
            });
        }

        let channel_id = self.metadata.channel_id().name();
        let claimant = pending.claimant;
        let defendant = *self.public_key();
        let update_count = self.update_count();

        // Serialize the update record as proof
        let update_record =
            ron::to_string(&self.last_update).map_err(|e| ForceCloseProtocolError::SerializationError(e.to_string()))?;

        // Sign the dispute
        let message = format!("dispute:{channel_id}:{update_count}");
        let signature = self.sign_for_kes(message.as_bytes())?;

        Ok(DisputeMessage {
            channel_id,
            claimant,
            defendant,
            update_count,
            update_record: update_record.into_bytes(),
            signature,
        })
    }

    fn handle_dispute_resolution(&mut self, resolution: DisputeResolution) -> Result<(), ForceCloseProtocolError> {
        match resolution {
            DisputeResolution::ClaimantWins { encrypted_offset: _ } => {
                // We lost the dispute - claimant's state was valid
                self.status = PendingCloseStatus::ForceClosed;
                Ok(())
            }
            DisputeResolution::DefendantWins { penalty_applied: _ } => {
                // We won the dispute - our state was more recent
                self.status = PendingCloseStatus::DisputeSuccessful;
                Ok(())
            }
        }
    }
}
