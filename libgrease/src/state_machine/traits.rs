use crate::channel_id::ChannelId;
use crate::payment_channel::ChannelRole;

/// Common functionality for all channel states in the channel lifecycle
pub trait ChannelState {
    /// The channel ID, which can be used to generate a unique identifier for the channel. It is based on the public 
    /// keys of the parties involved in the channel, the initial balances, some salt, and the KES public key.
    fn channel_id(&self) -> &ChannelId;

    /// The channel name, which is always in the format `XGC<hex encoded channel id>`
    fn name(&self) -> String {
        let hash = self.channel_id().hash();
        format!("XGC{}", hex::encode(hash))
    }

    /// The role of the channel, which can be either customer or merchant.
    fn role(&self) -> ChannelRole;
}
