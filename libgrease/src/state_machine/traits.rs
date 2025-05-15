use crate::channel_id::ChannelId;
use crate::crypto::traits::PublicKey;
use crate::kes::KeyEscrowService;
use crate::monero::MultiSigService;
use crate::payment_channel::{ActivePaymentChannel, ChannelRole};
use crate::state_machine::ChannelLifeCycle;

/// Common functionality for all channel states in the channel lifecycle
pub trait ChannelState {
    /// The channel ID, which can be used to generate a unique identifier for the channel. It is based on the public
    /// keys of the parties involved in the channel, the initial balances, some salt, and the KES public key.
    fn channel_id(&self) -> &ChannelId;

    /// an alias for [`channel_id().name()`](ChannelId::name)
    fn name(&self) -> String {
        self.channel_id().name()
    }

    /// The role of the channel, which can be either customer or merchant.
    fn role(&self) -> ChannelRole;
}

pub trait StateStore<P, C, WS, KES>
where
    P: PublicKey,
    C: ActivePaymentChannel,
    WS: MultiSigService,
    KES: KeyEscrowService,
{
    fn write_channel(&mut self, state: &ChannelLifeCycle<P, C, WS, KES>) -> Result<(), anyhow::Error>;
    fn load_channel(&self, channel_name: &str) -> Result<ChannelLifeCycle<P, C, WS, KES>, anyhow::Error>;
}
