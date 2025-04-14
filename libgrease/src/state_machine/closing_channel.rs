pub struct ClosingChannelState {}

impl ClosingChannelState {
    /// Create a new closing channel state
    pub fn new() -> Self {
        ClosingChannelState {}
    }
}

pub struct StartCloseInfo {}

pub struct InvalidCloseInfo {
    pub reason: String,
}

pub struct SuccessfulCloseInfo {}
