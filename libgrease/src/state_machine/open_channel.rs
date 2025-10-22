//! State object for an open / established payment channel.
//!
//! There are three events that are allowed in this state:
//! - `UpdateChannel`: This is used to update the channel state with new information.
//!   The channel remains in the `Established` state.
//! - `ChannelClose`: This indicates a co-operative close of the channel. The channel will move to the `Closing` state.
//! - `ChannelForceClose`: This indicates a force close of the channel, and will move the channel to the `Disputed` state.
//!

use crate::adapter_signature::AdaptedSignature;
use crate::amount::{MoneroAmount, MoneroDelta};
use crate::channel_metadata::ChannelMetadata;
use crate::crypto::zk_objects::{
    GenericPoint, GenericScalar, KesProof, PrivateUpdateOutputs, Proofs0, PublicProof0, PublicUpdateOutputs,
    PublicUpdateProof, ShardInfo, UpdateProofs,
};
use crate::lifecycle_impl;
use crate::monero::data_objects::{TransactionId, TransactionRecord};
use crate::multisig::MultisigWalletData;
use crate::state_machine::closing_channel::{ChannelCloseRecord, ClosingChannelState};
use crate::state_machine::error::LifeCycleError;
use crate::state_machine::ChannelClosedReason;
use ciphersuite::Ed25519;
use log::*;
use monero::{Address, Network};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::{Debug, Formatter};

/// Container struct carrying all the information needed to record a payment channel update.
#[derive(Clone, Serialize, Deserialize)]
pub struct UpdateRecord {
    // My half of the spend authority for this transaction.
    pub my_signature: Vec<u8>,
    pub my_adapted_signature: AdaptedSignature<Ed25519>,
    pub peer_adapted_signature: AdaptedSignature<Ed25519>,
    // Data needed to reconstruct the Monero transaction for this update.
    pub my_preprocess: Vec<u8>,
    pub peer_preprocess: Vec<u8>,
    // ZK proof data for this update.
    pub my_proofs: UpdateProofs,
    pub peer_proofs: PublicUpdateProof,
}

impl Debug for UpdateRecord {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "UpdateRecord(...)")
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct EstablishedChannelState {
    pub(crate) metadata: ChannelMetadata,
    /// The shards of the multisig wallet, containing the split secrets for the multisig wallet.
    /// Getting hold of both parts gives full control of the wallet.
    pub(crate) shards: ShardInfo,
    /// Information needed to reconstruct the multisig wallet.
    pub(crate) multisig_wallet: MultisigWalletData,
    pub(crate) funding_transactions: HashMap<TransactionId, TransactionRecord>,
    pub(crate) my_proof0: Proofs0,
    pub peer_proof0: PublicProof0,
    pub(crate) kes_proof: KesProof,
    pub(crate) current_update: Option<UpdateRecord>,
}

impl Debug for EstablishedChannelState {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "EstablishedChannelState({} updates, role: {}, channel_id: {})",
            self.metadata.update_count(),
            self.metadata.role(),
            self.metadata.channel_id().name(),
        )
    }
}

impl EstablishedChannelState {
    pub fn to_channel_state(self) -> ChannelState {
        ChannelState::Open(self)
    }

    pub fn update_count(&self) -> u64 {
        self.metadata.update_count()
    }

    /// Returns the current witness for the channel. If no updates have been made, it returns the initial witness.
    pub fn current_witness(&self) -> GenericScalar {
        self.current_update
            .as_ref()
            .map(|update| update.my_proofs.private_outputs.witness_i)
            .unwrap_or(self.my_proof0.private_outputs.witness_0)
    }

    pub fn multisig_address(&self, network: Network) -> Option<String> {
        let addr = self.multisig_wallet.address(network).to_string();
        Some(addr)
    }

    pub fn current_peer_commitment(&self) -> GenericPoint {
        self.current_update
            .as_ref()
            .map(|update| update.peer_proofs.public_outputs.T_current)
            .unwrap_or(self.peer_proof0.public_outputs.T_0)
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
        let new_balance = self.balance().apply_delta(delta)?;
        let merchant_address = self.metadata.channel_id().closing_addresses().merchant;
        let customer_address = self.metadata.channel_id().closing_addresses().customer;
        Some([(merchant_address, new_balance.merchant), (customer_address, new_balance.customer)])
    }

    /// Return the record to send to the peer to co-operatively close the channel.
    /// Note that this record contains the secret that will allow the peer to publish closing transaction to the
    /// blockchain.
    pub fn get_close_record(&self) -> ChannelCloseRecord {
        ChannelCloseRecord {
            final_balance: self.metadata.balances(),
            update_count: self.metadata.update_count(),
            witness: self.current_witness(),
        }
    }

    pub fn store_update(&mut self, delta: MoneroDelta, update: UpdateRecord) -> u64 {
        self.metadata.apply_delta(delta);
        self.current_update = Some(update);
        self.update_count()
    }

    fn finalize_with_no_updates(&mut self) {
        // If the proofs are already set, we can skip this step.
        if self.current_update.is_some() {
            return;
        }
        // If no updates have been made, we set the current outputs to the initial outputs.
        // Essentially, only witness_0 is important here, and maybe T_0. which is witness_0.G.
        // The proofs are only needed in a dispute, but when update count is 0, there's no future state to prove in a
        // dispute anyway.
        let pvt_out = PrivateUpdateOutputs {
            witness_i: self.my_proof0.private_outputs.witness_0,
            ..PrivateUpdateOutputs::default()
        };
        let pub_out =
            PublicUpdateOutputs { T_current: self.my_proof0.public_outputs.T_0, ..PublicUpdateOutputs::default() };
        let peer_pub_out =
            PublicUpdateOutputs { T_current: self.peer_proof0.public_outputs.T_0, ..PublicUpdateOutputs::default() };
        todo!("Finalize the channel if no updates have been made");
    }

    #[allow(clippy::result_large_err)]
    pub fn close(mut self, close_record: ChannelCloseRecord) -> Result<ClosingChannelState, (Self, LifeCycleError)> {
        let final_balance = self.metadata.balances();
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
        if self.update_count() == 0 {
            Self::finalize_with_no_updates(&mut self);
        }
        let closing_state = ClosingChannelState {
            peer_witness: close_record.witness,
            metadata: self.metadata.clone(),
            reason: ChannelClosedReason::Normal,
            shards: self.shards,
            multisig_wallet: self.multisig_wallet,
            funding_transactions: self.funding_transactions,
            my_proof0: self.my_proof0,
            peer_proof0: self.peer_proof0,
            kes_proof: self.kes_proof,
            last_update: self.current_update.unwrap(),
            final_tx: None,
        };
        Ok(closing_state)
    }
}

use crate::state_machine::lifecycle::{ChannelState, LifeCycle, LifecycleStage};
lifecycle_impl!(EstablishedChannelState, Open);
