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
use ciphersuite::{Ciphersuite, Ed25519};
use log::*;
use monero::Address;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::{Debug, Formatter};

/// Everything a party retains locally about one applied channel update.
///
/// The cross-signed [`UpdateRecord`] is the only part that is *shared* evidence — it is what a party presents to
/// the arbiter in a dispute, and it is the single source of truth for which state the channel is in. The rest is
/// this party's own material for that state: the fresh offset `ω` it drew, the two pre-signatures, the peer's
/// sealed offset, and the FROST preprocessing needed to rebuild the commitment transaction.
///
/// # Why the peer's binding proof is retained, and only the latest one
///
/// A dispute close is completed by recovering the *peer's* offset from the *peer's* sealed offset under the
/// arbiter's attestation, so the disputing party must still hold the proof at dispute time — nothing else
/// carries the sealed shares. Under K-6's construction those share ciphertexts **are** the verifiably encrypted
/// offset; there is no separate ciphertext to keep instead.
///
/// Exactly one proof is retained — this state's — and it is replaced wholesale on every update, because a
/// retained older proof could never be opened anyway: the arbiter attests the *high-water* statement once and
/// then tombstones the channel, so no attestation for an earlier `m_i` will ever exist. Keeping a history would
/// cost ~23.6 KB per update for material that is unopenable by construction.
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

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct EstablishedChannelState<KC: Ciphersuite = Ed25519> {
    pub(crate) metadata: StaticChannelMetadata<KC>,
    pub(crate) dynamic: DynamicChannelMetadata,
    /// Information needed to reconstruct the multisig wallet.
    pub(crate) multisig_wallet: MultisigWallet,
    pub(crate) funding_transactions: HashMap<TransactionId, TransactionRecord>,
    pub(crate) current_update: Option<AppliedUpdate>,
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
        &self.current_update.as_ref().expect("No updates have been made yet").my_offset
    }

    /// Returns true if any updates have been made to this channel.
    pub fn has_updates(&self) -> bool {
        self.current_update.is_some()
    }

    /// The latest cross-signed [`UpdateRecord`] — what a dispute presents to the arbiter.
    pub fn current_record(&self) -> Option<&UpdateRecord> {
        self.current_update.as_ref().map(|update| &update.record)
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

    pub fn store_update(&mut self, delta: MoneroDelta, update: AppliedUpdate) -> u64 {
        self.dynamic.apply_delta(delta);
        self.current_update = Some(update);
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
        let last_update = match self.current_update {
            Some(update) => update,
            None => {
                return Err((
                    self,
                    LifeCycleError::InvalidState("Cannot close channel without any updates".to_string()),
                ))
            }
        };
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
