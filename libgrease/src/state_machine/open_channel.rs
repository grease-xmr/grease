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
use crate::cryptography::dleq::Dleq;
use crate::cryptography::ChannelWitness;
use crate::monero::data_objects::{TransactionId, TransactionRecord};
use crate::multisig::MultisigWalletData;
use crate::payment_channel::{ChannelRole, HasRole};
use crate::state_machine::closing_channel::{ChannelCloseRecord, ClosingChannelState};
use crate::state_machine::error::LifeCycleError;
use crate::state_machine::ChannelClosedReason;
use ciphersuite::{Ciphersuite, Ed25519};
use log::*;
use modular_frost::curve::Curve as FrostCurve;
use monero::{Address, Network};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::{Debug, Formatter};

/// Container struct carrying all the information needed to record a payment channel update.
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct UpdateRecord<SF: Ciphersuite = grease_grumpkin::Grumpkin> {
    // My half of the spend authority for this transaction.
    pub my_offset: ChannelWitness<SF>,
    pub my_adapted_signature: AdaptedSignature<Ed25519>,
    pub peer_adapted_signature: AdaptedSignature<Ed25519>,
    // Data needed to reconstruct the Monero transaction for this update.
    pub my_preprocess: Vec<u8>,
    pub peer_preprocess: Vec<u8>,
}

impl<SF: Ciphersuite> Debug for UpdateRecord<SF> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "UpdateRecord(...)")
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct EstablishedChannelState<SF: Ciphersuite = grease_grumpkin::Grumpkin, KC: Ciphersuite = Ed25519> {
    pub(crate) metadata: StaticChannelMetadata<KC>,
    pub(crate) dynamic: DynamicChannelMetadata,
    /// Information needed to reconstruct the multisig wallet.
    pub(crate) multisig_wallet: MultisigWalletData,
    pub(crate) funding_transactions: HashMap<TransactionId, TransactionRecord>,
    pub(crate) current_update: Option<UpdateRecord<SF>>,
    /// The per-channel KES public key ($P_g$) derived during establishment.
    ///
    /// Needed for force-close and dispute communication with the KES.
    #[serde(
        serialize_with = "crate::helpers::option_serialize_ge",
        deserialize_with = "crate::helpers::option_deserialize_ge",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub(crate) kes_channel_pubkey: Option<KC::G>,
}

impl<SF: Ciphersuite, KC: Ciphersuite> Debug for EstablishedChannelState<SF, KC> {
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

impl<SF: FrostCurve, KC: Ciphersuite> EstablishedChannelState<SF, KC>
where
    Ed25519: Dleq<SF>,
{
    pub fn to_channel_state(self) -> ChannelState<SF, KC>
    where
        KC: FrostCurve,
        Ed25519: Dleq<KC>,
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
    pub fn current_witness(&self) -> &ChannelWitness<SF> {
        &self.current_update.as_ref().expect("No updates have been made yet").my_offset
    }

    /// Returns true if any updates have been made to this channel.
    pub fn has_updates(&self) -> bool {
        self.current_update.is_some()
    }

    /// Returns the per-channel KES public key ($P_g$), if set during establishment.
    pub fn kes_channel_pubkey(&self) -> Option<&KC::G> {
        self.kes_channel_pubkey.as_ref()
    }

    pub fn multisig_address(&self, network: Network) -> Option<String> {
        let addr = self.multisig_wallet.address(network).to_string();
        Some(addr)
    }

    /// Returns the keys to be able to reconstruct the multisig wallet.
    /// Warning! The result of this function contains wallet secrets!
    pub fn wallet_data(&self) -> MultisigWalletData {
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
    pub fn get_close_record(&self) -> ChannelCloseRecord<SF> {
        ChannelCloseRecord {
            final_balance: self.dynamic.current_balances,
            update_count: self.dynamic.update_count,
            witness: self.current_witness().clone(),
        }
    }

    pub fn store_update(&mut self, delta: MoneroDelta, update: UpdateRecord<SF>) -> u64 {
        self.dynamic.apply_delta(delta);
        self.current_update = Some(update);
        self.update_count()
    }

    #[allow(clippy::result_large_err)]
    pub fn close(
        self,
        close_record: ChannelCloseRecord<SF>,
    ) -> Result<ClosingChannelState<SF, KC>, (Self, LifeCycleError)> {
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

impl<SF: FrostCurve, KC: Ciphersuite> LifeCycle<KC> for EstablishedChannelState<SF, KC>
where
    Ed25519: Dleq<SF>,
{
    fn stage(&self) -> LifecycleStage {
        LifecycleStage::Open
    }

    fn metadata(&self) -> &StaticChannelMetadata<KC> {
        &self.metadata
    }

    fn balance(&self) -> Balances {
        self.dynamic.current_balances
    }

    fn wallet_address(&self, network: Network) -> Option<String> {
        self.multisig_address(network)
    }
}

// --- Protocol Trait Implementations ---

impl<SF: FrostCurve, KC: Ciphersuite> HasRole for EstablishedChannelState<SF, KC>
where
    Ed25519: Dleq<SF>,
{
    fn role(&self) -> ChannelRole {
        self.metadata.role()
    }
}
