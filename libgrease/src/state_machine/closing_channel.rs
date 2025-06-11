use crate::balance::Balances;
use crate::channel_metadata::ChannelMetadata;
use crate::lifecycle_impl;
use crate::monero::data_objects::TransactionId;
use crate::state_machine::closed_channel::{ChannelClosedReason, ClosedChannelState};
use crate::state_machine::commitment_tx::CommitmentTransaction;
use crate::state_machine::error::LifeCycleError;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClosingChannelState {
    pub(crate) metadata: ChannelMetadata,
    pub(crate) commitment_tx: CommitmentTransaction,
    pub(crate) final_tx: Option<TransactionId>,
    pub(crate) reason: ChannelClosedReason,
}

impl ClosingChannelState {
    pub fn to_channel_state(self) -> ChannelState {
        ChannelState::Closing(self)
    }
    pub fn final_balances(&self) -> Balances {
        self.metadata.balances()
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
