use crate::state_machine::lifecycle::LifecycleStage;
use crate::state_machine::new_channel::TimeoutReason;

pub struct ClosedChannelState {
    reason: ChannelClosedReason,
    from_stage: LifecycleStage,
}

impl ClosedChannelState {
    /// Create a new closed channel state
    pub fn new(reason: ChannelClosedReason, from_stage: LifecycleStage) -> Self {
        ClosedChannelState { reason, from_stage }
    }

    /// Get the reason for the channel being closed
    pub fn reason(&self) -> &ChannelClosedReason {
        &self.reason
    }
}

pub enum ChannelClosedReason {
    /// The channel was closed normally
    Normal,
    /// The channel was closed due to a timeout
    Timeout(TimeoutReason),
    /// The channel was closed following the dispute process
    Dispute,
}
