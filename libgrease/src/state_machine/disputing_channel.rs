pub enum DisputingChannelState {
    StartingDispute,
    DisputeInProgress,
    DisputeResolved,
}

impl DisputingChannelState {
    /// Create a new disputing channel state
    pub fn new() -> Self {
        DisputingChannelState::StartingDispute
    }
}

pub struct DisputeResolvedInfo {}
