//! State object for a channel undergoing a force close / dispute resolution.
//!
//! This state is entered when a cooperative close fails and one party initiates
//! a force close via the KES (Key Encryption Server). The channel can be in
//! dispute until either:
//! - The dispute window expires and the claimant can claim
//! - The defendant proves a more recent state
//! - The parties reach consensus

use crate::balance::Balances;
use crate::channel_id::ChannelId;
use crate::channel_metadata::{DynamicChannelMetadata, StaticChannelMetadata};
use crate::cryptography::adapter_signature::SchnorrSignature;
use crate::cryptography::dleq::Dleq;
use crate::cryptography::keys::Curve25519PublicKey;
use crate::cryptography::CrossCurveScalar;
use crate::grease_protocol::force_close_channel::{
    ClaimChannelRequest, ConsensusCloseRequest, DisputeChannelState as DisputeMessage, DisputeResolution,
    ForceCloseProtocolClaimant, ForceCloseProtocolCommon, ForceCloseProtocolDefendant, ForceCloseProtocolError,
    ForceCloseRequest, ForceCloseResponse, PendingChannelClose, PendingCloseStatus,
};
use crate::monero::data_objects::{TransactionId, TransactionRecord};
use crate::payment_channel::{ChannelRole, HasRole};
use crate::state_machine::closed_channel::{ChannelClosedReason, ClosedChannelState};
use crate::state_machine::error::LifeCycleError;
use crate::state_machine::open_channel::UpdateRecord;
use crate::XmrScalar;
use ciphersuite::{Ciphersuite, Ed25519};
use modular_frost::curve::Curve as FrostCurve;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

/// Default dispute window duration in seconds (24 hours).
pub const DEFAULT_DISPUTE_WINDOW: Duration = Duration::from_hours(24);

/// State for a channel undergoing force close / dispute resolution.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct DisputingChannelState<SF: Ciphersuite = grease_grumpkin::Grumpkin, KC: Ciphersuite = Ed25519> {
    pub(crate) metadata: StaticChannelMetadata<KC>,
    pub(crate) dynamic: DynamicChannelMetadata,
    /// The reason this dispute was initiated
    pub(crate) reason: DisputeReason,
    /// Wallet data needed for transaction creation
    pub(crate) multisig_wallet: MultisigWallet,
    /// Funding transaction records
    pub(crate) funding_transactions: HashMap<TransactionId, TransactionRecord>,
    /// Last update record from the open channel state
    pub(crate) last_update: UpdateRecord<SF>,
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

impl<SF: Ciphersuite, KC: Ciphersuite> DisputingChannelState<SF, KC> {
    /// Create a new disputing state from an established channel.
    pub fn from_open_channel(
        metadata: StaticChannelMetadata<KC>,
        dynamic: DynamicChannelMetadata,
        reason: DisputeReason,
        multisig_wallet: MultisigWallet,
        funding_transactions: HashMap<TransactionId, TransactionRecord>,
        last_update: UpdateRecord<SF>,
    ) -> Self {
        Self {
            metadata,
            dynamic,
            reason,
            multisig_wallet,
            funding_transactions,
            last_update,
            status: PendingCloseStatus::Pending,
            pending_close: None,
            dispute_window_end: None,
            final_tx: None,
        }
    }

    pub fn multisig_address(&self) -> Option<String> {
        Some(self.multisig_wallet.address().to_string())
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

    /// Returns a reference to the multisig wallet.
    pub fn wallet(&self) -> &MultisigWallet {
        // Do we need to copy over the funding tx outputs?
        &self.multisig_wallet
    }

    pub fn with_final_tx(&mut self, final_tx: TransactionId) {
        if let Some(prev) = self.final_tx.take() {
            log::warn!("Overwriting existing final transaction {} in DisputingChannelState", prev.id);
        }
        self.final_tx = Some(final_tx);
    }

    /// Check if the dispute can transition to closed state.
    pub fn requirements_met(&self) -> bool {
        matches!(
            self.status,
            PendingCloseStatus::ForceClosed
                | PendingCloseStatus::ConsensusClosed
                | PendingCloseStatus::DisputeSuccessful
        ) && self.final_tx.is_some()
    }

    #[allow(clippy::result_large_err)]
    pub fn next(self) -> Result<ClosedChannelState<SF, KC>, (Self, LifeCycleError)>
    where
        SF: FrostCurve,
        KC: FrostCurve,
        Ed25519: Dleq<SF> + Dleq<KC>,
    {
        if !self.requirements_met() {
            return Err((self, LifeCycleError::InvalidStateTransition));
        }

        let reason = match self.status {
            PendingCloseStatus::ForceClosed => ChannelClosedReason::ForceClosed,
            PendingCloseStatus::ConsensusClosed => ChannelClosedReason::Normal,
            PendingCloseStatus::DisputeSuccessful => ChannelClosedReason::Disputed,
            _ => return Err((self, LifeCycleError::InvalidStateTransition)),
        };

        let closed_state = ClosedChannelState::new(reason, self.metadata.clone(), self.dynamic.current_balances);
        Ok(closed_state)
    }
}

use crate::state_machine::lifecycle::{ChannelState, LifeCycle, LifecycleStage};
use crate::wallet::multisig_wallet::MultisigWallet;

impl<SF: FrostCurve, KC: FrostCurve> DisputingChannelState<SF, KC>
where
    Ed25519: Dleq<SF> + Dleq<KC>,
{
    pub fn to_channel_state(self) -> ChannelState<SF, KC> {
        ChannelState::Disputing(self)
    }
}

impl<SF: FrostCurve, KC: Ciphersuite> LifeCycle<KC> for DisputingChannelState<SF, KC>
where
    Ed25519: Dleq<SF>,
{
    fn stage(&self) -> LifecycleStage {
        LifecycleStage::Disputing
    }

    fn metadata(&self) -> &StaticChannelMetadata<KC> {
        &self.metadata
    }

    fn balance(&self) -> Balances {
        self.dynamic.current_balances
    }

    fn wallet_address(&self) -> Option<String> {
        self.multisig_address()
    }
}

// --- Protocol Trait Implementations ---

impl<SF: FrostCurve, KC: Ciphersuite> HasRole for DisputingChannelState<SF, KC>
where
    Ed25519: Dleq<SF>,
{
    fn role(&self) -> ChannelRole {
        self.metadata.role()
    }
}

impl<SF: FrostCurve, KC: Ciphersuite, K: Ciphersuite> ForceCloseProtocolCommon<K> for DisputingChannelState<SF, KC>
where
    Ed25519: Dleq<SF>,
{
    fn channel_id(&self) -> ChannelId {
        self.metadata.channel_id().name()
    }

    fn public_key(&self) -> &Curve25519PublicKey {
        &self.multisig_wallet.my_public_key()
    }

    fn peer_public_key(&self) -> &Curve25519PublicKey {
        &self.multisig_wallet.peer_public_key()
    }

    fn dispute_window(&self) -> Duration {
        DEFAULT_DISPUTE_WINDOW
    }

    fn update_count(&self) -> u64 {
        self.dynamic.update_count
    }

    fn sign_for_kes(&self, _message: &[u8]) -> Result<SchnorrSignature<K>, ForceCloseProtocolError> {
        // Signing requires wallet integration with the secret key.
        // The actual implementation would use self.multisig_wallet.partial_spend_key
        Err(ForceCloseProtocolError::SignatureCreationFailed(
            "Signing requires external wallet integration".into(),
        ))
    }

    fn verify_peer_signature(
        &self,
        _message: &[u8],
        _sig: &SchnorrSignature<K>,
    ) -> Result<(), ForceCloseProtocolError> {
        // Signature verification against peer_public_key
        // This would use standard Ed25519 verification
        Err(ForceCloseProtocolError::InvalidSignature(
            "Signature verification requires external wallet integration".into(),
        ))
    }
}

impl<SF: FrostCurve, KC: Ciphersuite, K: Ciphersuite> ForceCloseProtocolClaimant<SF, K>
    for DisputingChannelState<SF, KC>
where
    Ed25519: Dleq<SF>,
{
    fn create_force_close_request(&self) -> Result<ForceCloseRequest<K>, ForceCloseProtocolError> {
        let channel_id = self.metadata.channel_id().name();
        let claimant = self.multisig_wallet.my_public_key().clone();
        let defendant = self.multisig_wallet.peer_public_key().clone();
        let update_count_claimed = self.dynamic.update_count;

        // Sign the request (placeholder - actual signing needs wallet integration)
        let message = format!("{channel_id}:{update_count_claimed}");
        let signature = <Self as ForceCloseProtocolCommon<K>>::sign_for_kes(self, message.as_bytes())?;

        Ok(ForceCloseRequest { channel_id, claimant, defendant, update_count_claimed, signature })
    }

    fn handle_force_close_response(&mut self, response: ForceCloseResponse) -> Result<(), ForceCloseProtocolError> {
        match response {
            ForceCloseResponse::Accepted { dispute_window_end } => {
                self.dispute_window_end = Some(dispute_window_end.into());
                self.status = PendingCloseStatus::Pending;
                Ok(())
            }
            ForceCloseResponse::Rejected { reason } => Err(ForceCloseProtocolError::KesRejected(reason)),
        }
    }

    fn create_claim_request(&self) -> Result<ClaimChannelRequest<K>, ForceCloseProtocolError> {
        // Verify dispute window has passed
        if let Some(end) = self.dispute_window_end {
            let now =
                std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
            if now < end {
                return Err(ForceCloseProtocolError::DisputeWindowActive);
            }
        } else {
            return Err(ForceCloseProtocolError::NoPendingForceClose);
        }

        let channel_id = self.metadata.channel_id().name();
        let claimant = self.multisig_wallet.my_public_key().clone();

        // Sign the claim request
        let message = format!("claim:{channel_id}");
        let signature = <Self as ForceCloseProtocolCommon<K>>::sign_for_kes(self, message.as_bytes())?;

        Ok(ClaimChannelRequest { channel_id, claimant, signature })
    }

    fn process_claimed_offset(&mut self, _encrypted: &[u8]) -> Result<CrossCurveScalar<SF>, ForceCloseProtocolError> {
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

impl<SF: FrostCurve, KC: Ciphersuite, K: Ciphersuite> ForceCloseProtocolDefendant<SF, K>
    for DisputingChannelState<SF, KC>
where
    Ed25519: Dleq<SF>,
{
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
        self.dispute_window_end = Some(notif.dispute_window_end.into());
        self.status = PendingCloseStatus::Pending;
        Ok(())
    }

    fn has_more_recent_state(&self, claimed_count: u64) -> bool {
        self.dynamic.update_count > claimed_count
    }

    fn create_consensus_close(&self) -> Result<ConsensusCloseRequest<SF, K>, ForceCloseProtocolError> {
        let pending = self.pending_close.as_ref().ok_or(ForceCloseProtocolError::NoPendingForceClose)?;

        let channel_id = self.metadata.channel_id().name();
        let claimant = pending.claimant;
        let defendant = self.multisig_wallet.my_public_key().clone();
        let update_count_claimed = pending.update_count_claimed;

        // Create witness from our offset
        let encrypted_offset = self.last_update.my_offset.clone();
        // Sign the consensus close
        let message = format!("consensus:{channel_id}:{update_count_claimed}");
        let signature = <Self as ForceCloseProtocolCommon<K>>::sign_for_kes(self, message.as_bytes())?;

        Ok(
            ConsensusCloseRequest {
                channel_id,
                claimant,
                defendant,
                update_count_claimed,
                encrypted_offset,
                signature,
            },
        )
    }

    fn create_dispute(&self) -> Result<DisputeMessage, ForceCloseProtocolError> {
        use modular_frost::sign::Writable;
        let pending = self.pending_close.as_ref().ok_or(ForceCloseProtocolError::NoPendingForceClose)?;

        // Verify we have a more recent state (use direct field access)
        let my_update_count = self.dynamic.update_count;
        if my_update_count <= pending.update_count_claimed {
            return Err(ForceCloseProtocolError::UpdateCountTooLow {
                claimed: pending.update_count_claimed,
                actual: my_update_count,
            });
        }

        let channel_id = self.metadata.channel_id().name();
        let claimant = pending.claimant;
        let defendant = self.multisig_wallet.my_public_key().clone();

        // Serialize the update record as proof
        let update_record = ron::to_string(&self.last_update)
            .map_err(|e| ForceCloseProtocolError::SerializationError(e.to_string()))?;

        // Sign the dispute
        let message = format!("dispute:{channel_id}:{my_update_count}");
        let signature = <Self as ForceCloseProtocolCommon<K>>::sign_for_kes(self, message.as_bytes())?;

        // Serialize signature to bytes using Writable trait
        let mut sig_bytes = Vec::new();
        signature.write(&mut sig_bytes).map_err(|e| ForceCloseProtocolError::SerializationError(e.to_string()))?;

        Ok(DisputeMessage {
            channel_id,
            claimant,
            defendant,
            update_count: my_update_count,
            update_record: update_record.into_bytes(),
            signature: sig_bytes,
        })
    }

    fn handle_dispute_resolution(&mut self, resolution: DisputeResolution<SF>) -> Result<(), ForceCloseProtocolError> {
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
