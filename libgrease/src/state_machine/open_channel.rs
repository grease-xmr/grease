//! State object for an open / established payment channel.
//!
//! There are three events that are allowed in this state:
//! - `UpdateChannel`: This is used to update the channel state with new information.
//!   The channel remains in the `Established` state.
//! - `ChannelClose`: This indicates a co-operative close of the channel. The channel will move to the `Closing` state.
//! - `ChannelForceClose`: This indicates a force close of the channel, and will move the channel to the `Disputed` state.
//!

use crate::amount::MoneroAmount;
use crate::channel_metadata::ChannelMetadata;
use crate::crypto::zk_objects::{
    GenericScalar, KesProof, PrivateUpdateOutputs, Proofs0, PublicProof0, PublicUpdateOutputs, ShardInfo, UpdateInfo,
    UpdateProofs,
};
use crate::lifecycle_impl;
use crate::monero::data_objects::{MultisigWalletData, TransactionId};
use crate::state_machine::closing_channel::ClosingChannelState;
use crate::state_machine::commitment_tx::CommitmentTransaction;
use crate::state_machine::error::LifeCycleError;
use crate::state_machine::ChannelClosedReason;
use log::info;
use monero::Network;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::Debug;

#[derive(Clone, Serialize, Deserialize)]
pub struct EstablishedChannelState {
    pub(crate) metadata: ChannelMetadata,
    pub(crate) shards: ShardInfo,
    pub(crate) multisig_wallet: MultisigWalletData,
    pub(crate) funding_transactions: HashMap<TransactionId, MoneroAmount>,
    pub(crate) my_proof0: Proofs0,
    pub(crate) peer_proof0: PublicProof0,
    pub(crate) kes_proof: KesProof,
    pub(crate) current_private_outputs: Option<PrivateUpdateOutputs>,
    pub(crate) current_public_outputs: Option<PublicUpdateOutputs>,
    pub(crate) current_peer_public_outputs: Option<PublicUpdateOutputs>,
    pub(crate) update_count: u64,
}

impl Debug for EstablishedChannelState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "EstablishedChannelState({} updates, role: {}, channel_id: {})",
            self.update_count,
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
        self.update_count
    }

    /// Returns the current witness for the channel. If no updates have been made, it returns the initial witness.
    pub fn current_witness(&self) -> GenericScalar {
        self.current_private_outputs.as_ref().map(|o| o.witness_i).unwrap_or(self.my_proof0.private_outputs.witness_0)
    }

    pub fn multisig_address(&self, network: Network) -> Option<String> {
        let addr = self.multisig_wallet.address(network).to_string();
        Some(addr)
    }

    pub fn store_update(&mut self, my_proofs: UpdateProofs, peer_update: UpdateInfo) -> u64 {
        let delta = peer_update.delta;
        self.update_count = my_proofs.private_outputs.update_count;
        self.current_private_outputs = Some(my_proofs.private_outputs);
        self.current_public_outputs = Some(my_proofs.public_outputs.clone());
        self.current_peer_public_outputs = Some(peer_update.proof.public_outputs);
        self.metadata.apply_delta(delta);
        self.update_count
    }

    #[allow(clippy::result_large_err)]
    pub fn close(self) -> Result<ClosingChannelState, (Self, LifeCycleError)> {
        let final_balance = self.metadata.balances();
        let name = self.metadata.channel_id().name();
        info!(
            "Initiating channel close on {name}. Final balance: {} / {}",
            final_balance.merchant, final_balance.customer
        );
        let closing_state = ClosingChannelState {
            metadata: self.metadata.clone(),
            commitment_tx: CommitmentTransaction {}, // TODO!!
            final_tx: None,
            reason: ChannelClosedReason::Normal,
        };
        Ok(closing_state)
    }
}

use crate::state_machine::lifecycle::{ChannelState, LifeCycle, LifecycleStage};
lifecycle_impl!(EstablishedChannelState, Open);
