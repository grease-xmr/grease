//! State object for an open / established payment channel.
//!
//! There are three events that are allowed in this state:
//! - `ChannelUpdate`: This is used to update the channel state with new information. The channel remains in the `Established` state.
//! - `ChannelClose`: This indicates a co-operative close of the channel. The channel will move to the `Closing` state.
//! - `ChannelForceClose`: This indicates a force close of the channel, and will move the channel to the `Disputed` state.
//!
//! ## Updates
//!
//! ```mermaid
//! sequenceDiagram
//!         actor I as Initiator
//!         actor R as Responder
//!         I->>I: Generate proofs_i
//!         I->>R: UpdateChannel<br/>(balances_i, proofs_Ii, partial_sig_Ii, tx_i)
//!         R->>R: Verify proofs_i<br/>Generate tx_i
//!         alt verification passes
//!           R->>I: AcceptUpdate<br/>(balances_i, proofs_Ri, tx_i, partial_sig_Ri)
//!         else verification fails
//!           R->>I: UpdateFailed<br/>(reason, balance_Ri-1, proofs_Ri-1)
//!         end
//!         R->>R: Generate proofs_Ri
//!         R->>I: UpdateChannel(ProofsR)
//! ```
//!
//!

use crate::channel_metadata::ChannelMetadata;
use crate::kes::{KesInitializationResult, ShardInfo};
use crate::lifecycle_impl;
use crate::monero::data_objects::{ChannelUpdate, MultisigSplitSecrets, MultisigWalletData, TransactionId};
use crate::state_machine::closing_channel::ClosingChannelState;
use crate::state_machine::commitment_tx::CommitmentTransaction;
use crate::state_machine::error::LifeCycleError;
use crate::state_machine::ChannelClosedReason;
use log::info;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

#[derive(Clone, Serialize, Deserialize)]
pub struct EstablishedChannelState {
    pub(crate) metadata: ChannelMetadata,
    pub(crate) shards: ShardInfo,
    pub(crate) multisig_wallet: MultisigWalletData,
    pub(crate) funding_transactions: Vec<TransactionId>,
    pub(crate) commitment_transaction0: CommitmentTransaction,
    #[serde(serialize_with = "crate::helpers::to_hex", deserialize_with = "crate::helpers::from_hex")]
    pub(crate) commitment_tx_proof: Vec<u8>,
    pub(crate) kes_details: KesInitializationResult,
    pub(crate) current_commitment_tx: CommitmentTransaction,
    #[serde(serialize_with = "crate::helpers::to_hex", deserialize_with = "crate::helpers::from_hex")]
    pub(crate) current_commitment_tx_proof: Vec<u8>,
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
    pub fn new_transfer(&mut self, update: ChannelUpdate) -> Result<u64, LifeCycleError> {
        if update.update_count != self.update_count + 1 {
            return Err(LifeCycleError::MismatchedUpdateCount {
                exp: self.update_count + 1,
                actual: update.update_count,
            });
        }
        if !self.metadata.apply_delta(update.delta) {
            return Err(LifeCycleError::NotEnoughFunds);
        }
        self.current_commitment_tx = update.commitment_tx;
        self.current_commitment_tx_proof = update.proofs;
        self.update_count += 1;
        Ok(self.update_count)
    }

    pub fn update_count(&self) -> u64 {
        self.update_count
    }

    pub fn close(self) -> Result<ClosingChannelState, (Self, LifeCycleError)> {
        let final_balance = self.metadata.balances();
        let name = self.metadata.channel_id().name();
        info!(
            "Initiating channel close on {name}. Final balance: {} / {}",
            final_balance.merchant, final_balance.customer
        );
        let closing_state = ClosingChannelState {
            metadata: self.metadata.clone(),
            commitment_tx: self.current_commitment_tx.clone(),
            final_tx: None,
            reason: ChannelClosedReason::Normal,
        };
        Ok(closing_state)
    }
}

use crate::state_machine::lifecycle::{ChannelState, LifeCycle, LifecycleStage};
lifecycle_impl!(EstablishedChannelState, Open);
