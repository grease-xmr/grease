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
    GenericPoint, GenericScalar, KesProof, PrivateUpdateOutputs, Proofs0, PublicProof0, PublicUpdateOutputs, ShardInfo,
    UpdateInfo, UpdateProofs,
};
use crate::lifecycle_impl;
use crate::monero::data_objects::{MultisigWalletData, TransactionId};
use crate::state_machine::closing_channel::{ChannelCloseRecord, ClosingChannelState};
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
    pub peer_proof0: PublicProof0,
    pub(crate) kes_proof: KesProof,
    pub(crate) current_private_outputs: Option<PrivateUpdateOutputs>,
    pub current_public_outputs: Option<PublicUpdateOutputs>,
    pub current_peer_public_outputs: Option<PublicUpdateOutputs>,
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

    pub fn current_peer_commitment(&self) -> GenericPoint {
        self.current_peer_public_outputs.as_ref().map(|o| o.T_current).unwrap_or(self.peer_proof0.public_outputs.T_0)
    }

    /// Return the record to send to the peer to co-operatively close the channel.
    /// Note that this record contains the secret that will allow the peer to publish closing transaction to the
    /// blockchain.
    pub fn get_close_record(&self) -> ChannelCloseRecord {
        ChannelCloseRecord {
            final_balance: self.metadata.balances(),
            update_count: self.update_count,
            witness: self.current_witness(),
        }
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

    fn finalize_with_no_updates(&mut self) {
        // If the proofs are already set, we can skip this step.
        if self.current_private_outputs.is_some()
            && self.current_public_outputs.is_some()
            && self.current_peer_public_outputs.is_some()
        {
            return;
        }
        // If no updates have been made, we set the current outputs to the initial outputs.
        // Essentially, only witness_0 is important here, and maybe T_0. which is witness_0.G.
        // The proofs are only needed in a dispute, but when update count is 0, there's no future state to prove in a
        // dispute anyway.
        let mut pvt_out = PrivateUpdateOutputs::default();
        pvt_out.witness_i = self.my_proof0.private_outputs.witness_0;
        let mut pub_out = PublicUpdateOutputs::default();
        pub_out.T_current = self.my_proof0.public_outputs.T_0;
        let mut peer_pub_out = PublicUpdateOutputs::default();
        peer_pub_out.T_current = self.peer_proof0.public_outputs.T_0;
        self.current_private_outputs = Some(pvt_out);
        self.current_public_outputs = Some(pub_out);
        self.current_peer_public_outputs = Some(peer_pub_out);
    }

    #[allow(clippy::result_large_err)]
    pub fn close(mut self, close_record: ChannelCloseRecord) -> Result<ClosingChannelState, (Self, LifeCycleError)> {
        let final_balance = self.metadata.balances();
        if final_balance != close_record.final_balance {
            return Err((self, LifeCycleError::mismatch("closing balances")));
        }
        if self.update_count != close_record.update_count {
            return Err((self, LifeCycleError::mismatch("update counts")));
        }
        let name = self.metadata.channel_id().name();
        info!(
            "Initiating channel close on {name}. Final balance: {} / {}",
            final_balance.merchant, final_balance.customer
        );
        if self.update_count == 0 {
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
            last_private_outputs: self.current_private_outputs.unwrap(),
            last_public_outputs: self.current_public_outputs.unwrap(),
            last_peer_public_outputs: self.current_peer_public_outputs.unwrap(),
            update_count: self.update_count,
            final_tx: None,
        };
        Ok(closing_state)
    }
}

use crate::state_machine::lifecycle::{ChannelState, LifeCycle, LifecycleStage};
lifecycle_impl!(EstablishedChannelState, Open);
