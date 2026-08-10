//! State object for a channel undergoing a force close / dispute resolution.
//!
//! This state is entered when a cooperative close fails and one party presents its latest cross-signed record to
//! the *arbiter* (`docs/src/40_arbiter.typ` §`disputeFlow`). The channel stays in dispute until the arbiter's
//! adjudication window elapses, at which point exactly one of two things is true of this party:
//!
//! - the high-water mark is the state we hold, the arbiter attested it, and we can unseal the counterparty's
//!   offset and complete our close ([`PendingCloseStatus::Claimable`]); or
//! - a higher record superseded ours, the window restarted at that state, and the arbiter will attest *that*
//!   statement instead — so nothing of ours is ever unsealed ([`PendingCloseStatus::Frozen`]).
//!
//! There is no third branch in which value moves as a result of the dispute. Nothing is escrowed, nothing is
//! released to a winner, and no penalty is charged to the party that presented the stale record: its close is
//! simply frozen.

use crate::arbiter::client::DisputeStateView;
use crate::balance::Balances;
use crate::channel_id::ChannelId;
use crate::channel_metadata::{DynamicChannelMetadata, StaticChannelMetadata};
use crate::cryptography::adapter_signature::{AdaptedSignature, SchnorrSignature};
use crate::cryptography::attestation::G2Point;
use crate::cryptography::binding_proof::BindingProof;
use crate::grease_protocol::force_close_channel::{
    ForceCloseProtocolClaimant, ForceCloseProtocolCommon, ForceCloseProtocolDefendant, ForceCloseProtocolError,
    PendingCloseStatus,
};
use crate::grease_protocol::update_record::UpdateRecord;
use crate::monero::data_objects::{TransactionId, TransactionRecord};
use crate::payment_channel::{ChannelRole, HasRole};
use crate::state_machine::closed_channel::{ChannelClosedReason, ClosedChannelState};
use crate::state_machine::error::LifeCycleError;
use crate::state_machine::open_channel::AppliedUpdate;
use crate::XmrPoint;
use async_trait::async_trait;
use crate::Ed25519;
use ciphersuite::Ciphersuite;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

/// Default dispute window duration in seconds (24 hours).
pub const DEFAULT_DISPUTE_WINDOW: Duration = Duration::from_hours(24);

/// State for a channel undergoing force close / dispute resolution.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct DisputingChannelState<KC: Ciphersuite = Ed25519> {
    pub(crate) metadata: StaticChannelMetadata<KC>,
    pub(crate) dynamic: DynamicChannelMetadata,
    /// The reason this dispute was initiated
    pub(crate) reason: DisputeReason,
    /// Wallet data needed for transaction creation
    pub(crate) multisig_wallet: MultisigWallet,
    /// Funding transaction records
    pub(crate) funding_transactions: HashMap<TransactionId, TransactionRecord>,
    /// Last update record from the open channel state — the record we present, and the material we close with
    pub(crate) last_update: AppliedUpdate,
    /// Status of the pending close operation
    pub(crate) status: PendingCloseStatus,
    /// The highest update count the arbiter has seen presented, as of our last poll
    pub(crate) high_water: Option<u64>,
    /// When the arbiter's adjudication window closes, in *consensus* seconds — never a local clock reading
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

impl<KC: Ciphersuite> DisputingChannelState<KC> {
    /// Create a new disputing state from an established channel.
    pub fn from_open_channel(
        metadata: StaticChannelMetadata<KC>,
        dynamic: DynamicChannelMetadata,
        reason: DisputeReason,
        multisig_wallet: MultisigWallet,
        funding_transactions: HashMap<TransactionId, TransactionRecord>,
        last_update: AppliedUpdate,
    ) -> Self {
        Self {
            metadata,
            dynamic,
            reason,
            multisig_wallet,
            funding_transactions,
            last_update,
            status: PendingCloseStatus::Idle,
            high_water: None,
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

    /// The highest update count the arbiter had seen at our last poll.
    pub fn high_water(&self) -> Option<u64> {
        self.high_water
    }

    /// The state we hold and would close on.
    pub fn last_update(&self) -> &AppliedUpdate {
        &self.last_update
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

    /// Abandon the dispute — a cooperative close intervened before the window elapsed.
    pub fn abandon(&mut self) {
        self.status = PendingCloseStatus::Abandoned;
    }

    /// Check if the dispute can transition to closed state.
    ///
    /// Both terminal statuses qualify, because a frozen party's channel is still settled — by the
    /// counterparty's broadcast rather than its own — and the closing transaction is what proves it either way.
    pub fn requirements_met(&self) -> bool {
        matches!(self.status, PendingCloseStatus::ForceClosed | PendingCloseStatus::Frozen) && self.final_tx.is_some()
    }

    #[allow(clippy::result_large_err)]
    pub fn next(self) -> Result<ClosedChannelState<KC>, (Self, LifeCycleError)>
    where
        KC: Ciphersuite,
    {
        if !self.requirements_met() {
            return Err((self, LifeCycleError::InvalidStateTransition));
        }

        let reason = match self.status {
            PendingCloseStatus::ForceClosed => ChannelClosedReason::ForceClosed,
            PendingCloseStatus::Frozen => ChannelClosedReason::Disputed,
            _ => return Err((self, LifeCycleError::InvalidStateTransition)),
        };

        let closed_state = ClosedChannelState::new(reason, self.metadata.clone(), self.dynamic.current_balances);
        Ok(closed_state)
    }
}

use crate::state_machine::lifecycle::{ChannelState, LifeCycle, LifecycleStage};
use crate::wallet::multisig_wallet::MultisigWallet;

impl<KC: Ciphersuite> DisputingChannelState<KC>
where
{
    pub fn to_channel_state(self) -> ChannelState<KC> {
        ChannelState::Disputing(self)
    }
}

impl<KC: Ciphersuite> LifeCycle<KC> for DisputingChannelState<KC> {
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

impl<KC: Ciphersuite> HasRole for DisputingChannelState<KC> {
    fn role(&self) -> ChannelRole {
        self.metadata.role()
    }
}

impl<KC: Ciphersuite> ForceCloseProtocolCommon for DisputingChannelState<KC> {
    fn channel_id(&self) -> ChannelId {
        self.metadata.channel_id().name()
    }

    fn public_key(&self) -> XmrPoint {
        self.multisig_wallet.my_public_key().as_point()
    }

    fn peer_public_key(&self) -> XmrPoint {
        self.multisig_wallet.peer_public_key().as_point()
    }

    fn dispute_window(&self) -> Duration {
        self.metadata.dispute_window()
    }

    fn update_count(&self) -> u64 {
        self.last_update.record.update_count()
    }

    fn state_amounts(&self) -> (u64, u64) {
        let balances = self.dynamic.current_balances;
        (balances.customer.to_piconero(), balances.merchant.to_piconero())
    }

    fn arbiter_master_public_key(&self) -> G2Point {
        *self.metadata.arbiter_configuration().master_public_key()
    }

    fn latest_record(&self) -> Result<&UpdateRecord, ForceCloseProtocolError> {
        Ok(&self.last_update.record)
    }

    fn peer_binding_proof(&self) -> Result<&BindingProof, ForceCloseProtocolError> {
        Ok(&self.last_update.peer_binding_proof)
    }

    fn peer_presignature(&self) -> Result<&AdaptedSignature<Ed25519>, ForceCloseProtocolError> {
        // Retained proof and retained pre-signature must describe the same offset, or recovery yields a scalar
        // that adapts nothing. The update protocol guarantees it; a dispute is where a violation would cost
        // money, so it is re-checked here rather than assumed of local storage.
        match self.last_update.proof_matches_presignature() {
            true => Ok(&self.last_update.peer_adapted_signature),
            false => Err(ForceCloseProtocolError::OffsetTargetMismatch),
        }
    }

    fn status(&self) -> PendingCloseStatus {
        self.status
    }

    fn set_status(&mut self, status: PendingCloseStatus) {
        self.status = status;
    }

    fn note_dispute_state(&mut self, view: &DisputeStateView) {
        self.high_water = Some(view.high_water);
        self.dispute_window_end = Some(view.window_expiry);
    }
}

#[async_trait]
impl<KC: Ciphersuite> ForceCloseProtocolClaimant for DisputingChannelState<KC> {
    async fn broadcast_closing_tx(
        &mut self,
        _signature: &SchnorrSignature<Ed25519>,
    ) -> Result<TransactionId, ForceCloseProtocolError> {
        // Assembling and submitting the Monero transaction needs the wallet and an RPC connection, neither of
        // which this state object owns.
        Err(ForceCloseProtocolError::BroadcastFailed(
            "Transaction broadcast requires network integration".into(),
        ))
    }
}

impl<KC: Ciphersuite> ForceCloseProtocolDefendant for DisputingChannelState<KC> {}
