//! State object for an open / established payment channel.
//!
//! There are three events that are allowed in this state:
//! - `UpdateChannel`: This is used to update the channel state with new information.
//!   The channel remains in the `Established` state.
//! - `ChannelClose`: This indicates a co-operative close of the channel. The channel will move to the `Closing` state.
//! - `ChannelForceClose`: This indicates a force close of the channel, and will move the channel to the `Disputed` state.
//!

use crate::amount::{MoneroAmount, MoneroDelta};
use crate::balance::Balances;
use crate::channel_metadata::{DynamicChannelMetadata, StaticChannelMetadata};
use crate::cryptography::adapter_signature::AdaptedSignature;
use crate::cryptography::binding_proof::BindingProof;
use crate::grease_protocol::update_record::UpdateRecord;
use crate::monero::data_objects::{TransactionId, TransactionRecord};
use crate::payment_channel::{ChannelRole, HasRole};
use crate::state_machine::closing_channel::{ChannelCloseRecord, ClosingChannelState};
use crate::state_machine::error::LifeCycleError;
use crate::cryptography::keys::Curve25519Secret;
use crate::state_machine::ChannelClosedReason;
use crate::XmrPoint;
use crate::Ed25519;
use ciphersuite::Ciphersuite;
use log::*;
use monero::Address;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::fmt::{Debug, Formatter};

/// Everything a party retains locally about one applied channel update.
///
/// The cross-signed [`UpdateRecord`] is the only part that is *shared* evidence — it is what a party presents to
/// the arbiter in a dispute, and it is the single source of truth for which state the channel is in. The rest is
/// this party's own material for that state: the fresh offset `ω` it drew, the two pre-signatures, the peer's
/// sealed offset, and the FROST preprocessing needed to rebuild the commitment transaction.
///
/// # Why the peer's binding proof is retained
///
/// A dispute close is completed by recovering the *peer's* offset from the *peer's* sealed offset under the
/// arbiter's attestation, so the disputing party must still hold the proof at dispute time — nothing else
/// carries the sealed shares. Under K-6's construction those share ciphertexts **are** the verifiably encrypted
/// offset; there is no separate ciphertext to keep instead.
///
/// Which *states* are retained is [`UpdateHistory`]'s business, and its documentation is blunt about what an
/// older retained proof is and is not good for. Dispute only ever reads the newest entry.
///
/// The proof and the pre-signature it goes with must describe the same offset, which is the invariant
/// [`AppliedUpdate::proof_matches_presignature`] states: the proof's target `Q` is the adaptor point of
/// `peer_adapted_signature`, so recovering `ω` from the proof is exactly what completes that pre-signature.
/// Holding them in one struct that is swapped atomically by [`EstablishedChannelState::store_update`] is what
/// keeps them from drifting apart.
#[derive(Clone, Serialize, Deserialize)]
pub struct AppliedUpdate {
    /// The cross-signed record for this state.
    pub record: UpdateRecord,
    /// Our fresh, independent offset `ω` for this state — the secret the peer needs to complete its own close.
    pub my_offset: Curve25519Secret,
    /// Our pre-signature over the *peer's* commitment transaction, adapted by `my_offset`.
    pub my_adapted_signature: AdaptedSignature<Ed25519>,
    /// The peer's pre-signature over *our* commitment transaction.
    pub peer_adapted_signature: AdaptedSignature<Ed25519>,
    /// The peer's offset for this state, verifiably encrypted to `m = (channel_id, update_count)`. This is what
    /// a dispute close feeds to [`recover_offset`](crate::cryptography::binding_proof::recover_offset) once the
    /// arbiter attests `m`.
    pub peer_binding_proof: BindingProof,
    // Data needed to reconstruct the Monero transaction for this update.
    pub my_preprocess: Vec<u8>,
    pub peer_preprocess: Vec<u8>,
}

impl AppliedUpdate {
    /// The adaptor point `Q` of the pre-signature a dispute close completes — and the point the recovered peer
    /// offset must be the discrete log of.
    pub fn peer_adaptor_point(&self) -> XmrPoint {
        self.peer_adapted_signature.adapter_commitment()
    }

    /// Whether the retained proof is the one that opens the pre-signature we hold.
    ///
    /// This holds by construction when the update protocol built the struct — `verify_update_package` checks the
    /// sealed offset against the adaptor point of the very signature in the same package — but a dispute is
    /// where a mismatch would cost money, so the claimant re-checks it rather than trusting local storage.
    pub fn proof_matches_presignature(&self) -> bool {
        *self.peer_binding_proof.q() == self.peer_adaptor_point()
    }
}

impl Debug for AppliedUpdate {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "AppliedUpdate(state {})", self.record.update_count())
    }
}

/// How many of the most recent applied updates a channel retains, over and above the first one.
pub const DEFAULT_PROOF_HISTORY_DEPTH: usize = 5;

const fn default_proof_history_depth() -> usize {
    DEFAULT_PROOF_HISTORY_DEPTH
}

/// The applied updates a party keeps: the **first** one, plus the most recent `depth`.
///
/// # What dispute uses, and what the rest is worth
///
/// Dispute reads exactly one entry, [`UpdateHistory::latest`], and nothing else in this type is on that path.
/// That is forced by the arbiter, not by a choice made here: the arbiter attests the *high-water* statement
/// `m = (channel_id, high_water)` once and then tombstones the channel, so an attestation for an earlier `m_i`
/// never comes into existence. The sealed shares in an older entry's `peer_binding_proof` are therefore
/// undecryptable for the lifetime of the protocol — [`recover_offset`] on one cannot be made to succeed, as
/// `tests::force_close_protocol` demonstrates by trying it with the only attestation that exists.
///
/// So the retained history is *local evidence*, not dispute material: an audit trail of the records this party
/// countersigned and the offsets it drew, useful for reconstructing what was agreed and for diagnosing a
/// disagreement about state. It is not a second chance at a close. Keeping the first entry has no rationale in
/// `docs/src/40_arbiter.typ` or anywhere else in the protocol that could be found — it is retained because the
/// ticket asks for it, and it is a plausible anchor for such an audit trail (the opening state is the one a
/// balance reconciliation starts from), but nothing in the dispute path or the spec depends on it.
///
/// It is not free: the binding proof is 23,641 bytes at production parameters, so the default depth costs
/// roughly 142 KB of retained proof material per channel, all of it unopenable except the newest.
///
/// # Storage shape
///
/// `recent` holds the last `depth` updates, oldest first. `first` stays empty until the opening update is
/// evicted from that window, so no update is ever stored twice; [`UpdateHistory::first`] reads whichever place
/// currently holds it. `depth` is clamped to at least one, because dispute needs `latest` to exist.
///
/// [`recover_offset`]: crate::cryptography::binding_proof::recover_offset
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateHistory {
    /// The channel's first applied update, held here only once it has aged out of `recent`.
    first: Option<AppliedUpdate>,
    /// The most recent applied updates, oldest first. The back is the state a dispute closes on.
    recent: VecDeque<AppliedUpdate>,
    /// `config::proof_history_depth`: how many recent updates to keep. Never less than one.
    #[serde(default = "default_proof_history_depth")]
    depth: usize,
}

impl Default for UpdateHistory {
    fn default() -> Self {
        UpdateHistory::new(DEFAULT_PROOF_HISTORY_DEPTH)
    }
}

impl UpdateHistory {
    /// An empty history retaining the first update and the last `depth`. A `depth` of zero is raised to one.
    pub fn new(depth: usize) -> Self {
        UpdateHistory { first: None, recent: VecDeque::new(), depth: depth.max(1) }
    }

    /// How many recent updates are retained alongside the first.
    pub fn depth(&self) -> usize {
        self.depth
    }

    /// Change the retention depth, discarding anything the new depth no longer covers.
    pub fn set_depth(&mut self, depth: usize) {
        self.depth = depth.max(1);
        self.trim();
    }

    /// Adopt a newly applied update as the latest state.
    ///
    /// The [`AppliedUpdate`] moves in whole, which is what keeps the peer's binding proof and the pre-signature
    /// it opens from drifting apart — see [`AppliedUpdate::proof_matches_presignature`].
    pub fn push(&mut self, update: AppliedUpdate) {
        self.recent.push_back(update);
        self.trim();
    }

    /// The newest applied update: **the only entry a dispute reads**.
    pub fn latest(&self) -> Option<&AppliedUpdate> {
        self.recent.back()
    }

    /// The newest applied update, consuming the history — what a close carries forward.
    pub fn into_latest(mut self) -> Option<AppliedUpdate> {
        self.recent.pop_back()
    }

    /// The channel's first applied update, wherever it currently lives.
    pub fn first(&self) -> Option<&AppliedUpdate> {
        self.first.as_ref().or_else(|| self.recent.front())
    }

    /// Every retained update, oldest first: the opening state, then the recent window.
    pub fn iter(&self) -> impl Iterator<Item = &AppliedUpdate> {
        let separate_first = self.first.iter();
        separate_first.chain(self.recent.iter())
    }

    /// The `update_count` of every retained state, oldest first. Diagnostics, and what the retention tests pin.
    pub fn retained_counts(&self) -> Vec<u64> {
        self.iter().map(|update| update.record.update_count()).collect()
    }

    /// How many updates are retained in total.
    pub fn len(&self) -> usize {
        self.first.iter().len() + self.recent.len()
    }

    pub fn is_empty(&self) -> bool {
        self.first.is_none() && self.recent.is_empty()
    }

    /// Evict from the front of the recent window, promoting the opening update to `first` on its way out.
    fn trim(&mut self) {
        while self.recent.len() > self.depth {
            let evicted = self.recent.pop_front();
            if self.first.is_none() {
                self.first = evicted;
            }
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct EstablishedChannelState<KC: Ciphersuite = Ed25519> {
    pub(crate) metadata: StaticChannelMetadata<KC>,
    pub(crate) dynamic: DynamicChannelMetadata,
    /// Information needed to reconstruct the multisig wallet.
    pub(crate) multisig_wallet: MultisigWallet,
    pub(crate) funding_transactions: HashMap<TransactionId, TransactionRecord>,
    /// The updates applied to this channel that are still retained: the first, and the last
    /// [`UpdateHistory::depth`]. Dispute reads only [`UpdateHistory::latest`].
    #[serde(default)]
    pub(crate) updates: UpdateHistory,
}

impl<KC: Ciphersuite> Debug for EstablishedChannelState<KC> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "EstablishedChannelState({} updates, role: {}, channel_id: {})",
            self.dynamic.update_count,
            self.metadata.role(),
            self.metadata.channel_id().name(),
        )
    }
}

impl<KC: Ciphersuite> EstablishedChannelState<KC> {
    pub fn to_channel_state(self) -> ChannelState<KC>
    where
        KC: Ciphersuite,
    {
        ChannelState::Open(self)
    }

    pub fn update_count(&self) -> u64 {
        self.dynamic.update_count
    }

    /// Returns the current witness for the channel.
    ///
    /// # Panics
    /// Panics if no updates have been made yet. Use `has_updates()` to check first.
    pub fn current_witness(&self) -> &Curve25519Secret {
        &self.current_update().expect("No updates have been made yet").my_offset
    }

    /// Returns true if any updates have been made to this channel.
    pub fn has_updates(&self) -> bool {
        !self.updates.is_empty()
    }

    /// The latest applied update — the state a close or a dispute acts on, and the only entry of
    /// [`EstablishedChannelState::update_history`] either of them reads.
    pub fn current_update(&self) -> Option<&AppliedUpdate> {
        self.updates.latest()
    }

    /// Everything still retained about this channel's applied updates. See [`UpdateHistory`] for what the
    /// non-latest entries are, and are not, good for.
    pub fn update_history(&self) -> &UpdateHistory {
        &self.updates
    }

    /// Set how many recent updates are retained (`config::proof_history_depth`), dropping anything the new
    /// depth no longer covers. Purely a local storage policy — it is not negotiated with the peer and cannot
    /// affect a close, because dispute reads only the latest entry.
    pub fn set_proof_history_depth(&mut self, depth: usize) {
        self.updates.set_depth(depth);
    }

    /// The latest cross-signed [`UpdateRecord`] — what a dispute presents to the arbiter.
    pub fn current_record(&self) -> Option<&UpdateRecord> {
        self.current_update().map(|update| &update.record)
    }

    pub fn multisig_address(&self) -> Option<String> {
        Some(self.multisig_wallet.address().to_string())
    }

    /// Returns the keys to be able to reconstruct the multisig wallet.
    /// Warning! The result of this function contains wallet secrets!
    pub fn wallet(&self) -> MultisigWallet {
        self.multisig_wallet.clone()
    }

    pub fn funding_transactions(&self) -> impl Iterator<Item = &TransactionRecord> {
        self.funding_transactions.values()
    }

    /// Returns a vector of payments to be made to the merchant and customer using the current channel state.
    /// NOTE: This does NOT take fees into account.
    pub fn get_payments_after_spending(&self, delta: MoneroDelta) -> Option<[(Address, MoneroAmount); 2]> {
        let new_balance = self.dynamic.current_balances.apply_delta(delta)?;
        let merchant_address = self.metadata.channel_id().closing_addresses().merchant;
        let customer_address = self.metadata.channel_id().closing_addresses().customer;
        Some([(merchant_address, new_balance.merchant), (customer_address, new_balance.customer)])
    }

    /// Return the record to send to the peer to co-operatively close the channel.
    /// Note that this record contains the secret that will allow the peer to publish closing transaction to the
    /// blockchain.
    pub fn get_close_record(&self) -> ChannelCloseRecord {
        ChannelCloseRecord {
            final_balance: self.dynamic.current_balances,
            update_count: self.dynamic.update_count,
            witness: self.current_witness().clone(),
        }
    }

    /// Adopt an applied update as the channel's new latest state.
    pub fn store_update(&mut self, delta: MoneroDelta, update: AppliedUpdate) -> u64 {
        self.dynamic.apply_delta(delta);
        self.updates.push(update);
        self.update_count()
    }

    #[allow(clippy::result_large_err)]
    pub fn close(
        self,
        close_record: ChannelCloseRecord,
    ) -> Result<ClosingChannelState<KC>, (Self, LifeCycleError)> {
        let final_balance = self.dynamic.current_balances;
        if final_balance != close_record.final_balance {
            return Err((self, LifeCycleError::mismatch("closing balances")));
        }
        if self.update_count() != close_record.update_count {
            return Err((self, LifeCycleError::mismatch("update counts")));
        }
        let name = self.metadata.channel_id().name();
        info!(
            "{}: Initiating channel close on {name}. Final balances: Merchant={} / Customer={}",
            self.metadata.role(),
            final_balance.merchant,
            final_balance.customer
        );
        if self.updates.is_empty() {
            let err = LifeCycleError::InvalidState("Cannot close channel without any updates".to_string());
            return Err((self, err));
        }
        let last_update = self.updates.into_latest().expect("the history was just checked to be non-empty");
        let closing_state = ClosingChannelState {
            peer_witness: close_record.witness,
            metadata: self.metadata.clone(),
            dynamic: self.dynamic,
            reason: ChannelClosedReason::Normal,
            multisig_wallet: self.multisig_wallet,
            funding_transactions: self.funding_transactions,
            last_update,
            final_tx: None,
        };
        Ok(closing_state)
    }
}

use crate::state_machine::lifecycle::{ChannelState, LifeCycle, LifecycleStage};
use crate::wallet::multisig_wallet::MultisigWallet;

impl<KC: Ciphersuite> LifeCycle<KC> for EstablishedChannelState<KC> {
    fn stage(&self) -> LifecycleStage {
        LifecycleStage::Open
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

impl<KC: Ciphersuite> HasRole for EstablishedChannelState<KC> {
    fn role(&self) -> ChannelRole {
        self.metadata.role()
    }
}
