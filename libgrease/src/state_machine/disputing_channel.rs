pub enum DisputingChannelState {
    StartingDispute,
    DisputeInProgress,
    DisputeResolved,
}

pub struct ForceCloseInfo;
pub struct AbandonedChannelInfo;
pub struct TriggerForceCloseInfo;
pub struct ForceCloseResolvedInfo;

impl DisputingChannelState {
    /// Create a new disputing channel state
    pub fn new() -> Self {
        DisputingChannelState::StartingDispute
    }
}

pub struct DisputeResolvedInfo {}
