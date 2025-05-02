use crate::channel_id::ChannelId;
use crate::crypto::traits::PublicKey;
use crate::monero::MultiSigWallet;
use crate::payment_channel::{ChannelRole, ClosedPaymentChannel};
use crate::state_machine::new_channel::{NewChannelState, TimeoutReason};
use crate::state_machine::traits::ChannelState;

pub struct ClosedChannelState<W, C>
where
    W: MultiSigWallet,
    C: ClosedPaymentChannel,
{
    reason: ChannelClosedReason,
    wallet: Option<W>,
    channel: CloseType<C>,
}

enum CloseType<C: ClosedPaymentChannel> {
    Channel(C),
    NoChannel { channel_id: ChannelId, channel_role: ChannelRole },
}

impl<W, C> ClosedChannelState<W, C>
where
    W: MultiSigWallet,
    C: ClosedPaymentChannel,
{
    /// Create a new closed channel state
    pub fn new(reason: ChannelClosedReason, channel: C, wallet: W) -> Self {
        let channel = CloseType::Channel(channel);
        ClosedChannelState { reason, wallet: Some(wallet), channel }
    }

    pub fn empty(reason: ChannelClosedReason, channel_id: ChannelId, role: ChannelRole) -> Self {
        let channel = CloseType::NoChannel { channel_id, channel_role: role };
        ClosedChannelState { reason, wallet: None, channel }
    }

    /// Get the reason for the channel being closed
    pub fn reason(&self) -> &ChannelClosedReason {
        &self.reason
    }

    pub fn wallet(&self) -> Option<&W> {
        self.wallet.as_ref()
    }

    pub fn channel(&self) -> Option<&C> {
        match &self.channel {
            CloseType::Channel(ref channel) => Some(channel),
            CloseType::NoChannel { .. } => None,
        }
    }
}

impl<W, C> ChannelState for ClosedChannelState<W, C>
where
    W: MultiSigWallet,
    C: ClosedPaymentChannel,
{
    fn channel_id(&self) -> &ChannelId {
        match self.channel {
            CloseType::Channel(ref channel) => channel.channel_id(),
            CloseType::NoChannel { ref channel_id, .. } => channel_id,
        }
    }

    fn role(&self) -> ChannelRole {
        match self.channel {
            CloseType::Channel(ref channel) => channel.role(),
            CloseType::NoChannel { ref channel_role, .. } => *channel_role,
        }
    }
}

#[derive(Clone, Debug)]
pub enum ChannelClosedReason {
    /// The channel was closed normally
    Normal,
    /// The channel was closed due to a timeout
    Timeout(TimeoutReason),
    /// The channel was closed following the dispute process
    Dispute,
}
