use crate::amount::MoneroAmount;
use crate::balance::Balances;
use crate::channel_metadata::ChannelMetadata;
use crate::crypto::zk_objects::{
    GenericScalar, KesProof, PrivateUpdateOutputs, Proofs0, PublicProof0, PublicUpdateOutputs, ShardInfo,
};
use crate::lifecycle_impl;
use crate::monero::data_objects::{MultisigWalletData, TransactionId};
use crate::state_machine::closed_channel::{ChannelClosedReason, ClosedChannelState};
use crate::state_machine::error::LifeCycleError;
use monero::Network;
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
    pub(crate) funding_transactions: HashMap<TransactionId, MoneroAmount>,
    pub(crate) peer_witness: GenericScalar,
    pub(crate) my_proof0: Proofs0,
    pub(crate) peer_proof0: PublicProof0,
    pub(crate) kes_proof: KesProof,
    pub(crate) last_private_outputs: PrivateUpdateOutputs,
    pub(crate) last_public_outputs: PublicUpdateOutputs,
    pub(crate) last_peer_public_outputs: PublicUpdateOutputs,
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

    pub fn reason(&self) -> &ChannelClosedReason {
        &self.reason
    }

    pub fn requirements_met(&self) -> bool {
        // Check if the commitment transaction is valid and if the final transaction is set
        self.final_tx.is_some()
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
lifecycle_impl!(ClosingChannelState, Closing);
