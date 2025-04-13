pub enum NewChannelState {
    /// This party has initiated the process of creating a new channel
    Initiator,
    /// This party has received a request to create a new channel
    Initiatee,
}
