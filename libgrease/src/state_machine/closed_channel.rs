use crate::balance::Balances;
use crate::channel_metadata::ChannelMetadata;
use crate::lifecycle_impl;
use crate::state_machine::new_channel::RejectNewChannelReason;
use crate::state_machine::timeouts::TimeoutReason;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClosedChannelState {
    reason: ChannelClosedReason,
    metadata: ChannelMetadata,
}

impl ClosedChannelState {
    /// Create a new closed channel state
    pub fn new(reason: ChannelClosedReason, metadata: ChannelMetadata) -> Self {
        ClosedChannelState { reason, metadata }
    }
    pub fn to_channel_state(self) -> ChannelState {
        ChannelState::Closed(self)
    }

    /// Get the reason for the channel being closed
    pub fn reason(&self) -> &ChannelClosedReason {
        &self.reason
    }

    pub fn final_balances(&self) -> Balances {
        self.metadata.balances()
    }
}
use crate::state_machine::lifecycle::{ChannelState, LifeCycle, LifecycleStage};
lifecycle_impl!(ClosedChannelState, Closed);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ChannelClosedReason {
    /// The channel was closed normally
    Normal,
    /// The channel was closed due to a timeout
    Timeout(TimeoutReason),
    /// The channel was closed following the dispute process
    //Dispute(DisputeResult),
    /// The channel was never opened because the terms were rejected
    Rejected(RejectNewChannelReason),
}

impl PartialEq for ChannelClosedReason {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (ChannelClosedReason::Normal, ChannelClosedReason::Normal) => true,
            (ChannelClosedReason::Timeout(_), ChannelClosedReason::Timeout(_)) => true,
            (ChannelClosedReason::Rejected(_), ChannelClosedReason::Rejected(_)) => true,
            _ => false,
        }
    }
}

impl Eq for ChannelClosedReason {}
