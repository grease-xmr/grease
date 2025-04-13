use crate::state_machine::lifecycle::LifecycleStage;

pub struct ClosedChannelState {
    reason: ChannelClosedReason,
}

pub enum ChannelClosedReason {
    /// The channel was closed normally
    Normal,
    /// The channel was closed due to a timeout
    Timeout(LifecycleStage),
    /// The channel was closed following the dispute process
    Dispute,
}
