use crate::amount::MoneroAmount;
use crate::balance::Balances;
use crate::channel_metadata::ChannelMetadata;
use crate::crypto::keys::{Curve25519Secret, KeyError};
use crate::crypto::zk_objects::{GenericScalar, KesProof, Proofs0, PublicProof0, ShardInfo};
use crate::lifecycle_impl;
use crate::monero::data_objects::{MultisigWalletData, TransactionId, TransactionRecord};
use crate::state_machine::closed_channel::{ChannelClosedReason, ClosedChannelState};
use crate::state_machine::error::LifeCycleError;
use monero::{Address, Network};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelCloseRecord {
    pub final_balance: Balances,
    pub update_count: u64,
    pub witness: GenericScalar,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClosingChannelState {
    pub(crate) metadata: ChannelMetadata,
    pub(crate) reason: ChannelClosedReason,
    pub(crate) shards: ShardInfo,
    pub(crate) multisig_wallet: MultisigWalletData,
    pub(crate) funding_transactions: HashMap<TransactionId, TransactionRecord>,
    pub(crate) peer_witness: GenericScalar,
    pub(crate) my_proof0: Proofs0,
    pub(crate) peer_proof0: PublicProof0,
    pub(crate) kes_proof: KesProof,
    pub(crate) last_update: UpdateRecord,
    pub(crate) update_count: u64,
    pub(crate) final_tx: Option<TransactionId>,
}

impl ClosingChannelState {
    pub fn to_channel_state(self) -> ChannelState {
        ChannelState::Closing(self)
    }
    pub fn final_balances(&self) -> Balances {
        self.metadata.balances()
    }

    pub fn multisig_address(&self, _network: Network) -> Option<String> {
        todo!("Implement multisig address retrieval for closing channel state")
    }

    /// Returns the keys to be able to reconstruct the multisig wallet.
    /// Warning! The result of this function contains wallet secrets!
    ///
    /// This function also includes all outputs from funding transactions
    pub fn wallet_data(&self) -> MultisigWalletData {
        let mut data = self.multisig_wallet.clone();
        self.funding_transactions.values().for_each(|rec| {
            data.known_outputs.push(rec.serialized.clone());
        });
        data
    }

    pub fn final_update(&self) -> UpdateRecord {
        self.last_update.clone()
    }

    pub fn peer_witness(&self) -> Result<Curve25519Secret, KeyError> {
        Curve25519Secret::from_generic_scalar(&self.peer_witness)
    }

    pub fn reason(&self) -> &ChannelClosedReason {
        &self.reason
    }

    pub fn requirements_met(&self) -> bool {
        // Check if the commitment transaction is valid and if the final transaction is set
        self.final_tx.is_some()
    }

    pub fn get_closing_payments(&self) -> [(Address, MoneroAmount); 2] {
        let balance = self.final_balances();
        let merchant_address = self.metadata.channel_id().closing_addresses().merchant;
        let customer_address = self.metadata.channel_id().closing_addresses().customer;
        [(merchant_address, balance.merchant), (customer_address, balance.customer)]
    }

    pub fn with_final_tx(&mut self, final_tx: TransactionId) {
        let prev = self.final_tx.take();
        if prev.is_some() {
            log::warn!(
                "Overwriting existing final transaction {} in ClosingChannelState",
                prev.as_ref().unwrap().id
            );
        }
        self.final_tx = Some(final_tx);
    }

    #[allow(clippy::result_large_err)]
    pub fn next(self) -> Result<ClosedChannelState, (Self, LifeCycleError)> {
        if !self.requirements_met() {
            return Err((self, LifeCycleError::InvalidStateTransition));
        }

        let closed_state = ClosedChannelState::new(ChannelClosedReason::Normal, self.metadata.clone());
        Ok(closed_state)
    }
}

use crate::state_machine::lifecycle::{ChannelState, LifeCycle, LifecycleStage};
use crate::state_machine::open_channel::UpdateRecord;

lifecycle_impl!(ClosingChannelState, Closing);
