use crate::amount::MoneroAmount;
use crate::state_machine::lifecycle::ChannelRole;
use crate::state_machine::LifecycleStage;

pub enum NewChannelState {
    /// This party has initiated the process of creating a new channel
    Initiator,
    /// This party has received a request to create a new channel
    Initiatee,
}

pub struct NewChannelInfo<PublicKey> {
    role: ChannelRole,
    /// The initiator's public key
    pub merchant_pubkey: PublicKey,
    /// The initiatee's public key
    pub customer_pubkey: PublicKey,
    /// The amount of money in the channel
    pub amount: MoneroAmount,
}

pub struct TimeoutReason {
    /// The reason for the timeout
    pub reason: String,
    /// The phase of the lifecycle when the timeout occurred
    pub stage: LifecycleStage,
}
