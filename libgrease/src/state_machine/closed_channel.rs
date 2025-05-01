use crate::monero::MultiSigWallet;
use crate::payment_channel::ClosedPaymentChannel;
use crate::state_machine::new_channel::TimeoutReason;

pub struct ClosedChannelState<W, C>
where
    W: MultiSigWallet,
    C: ClosedPaymentChannel,
{
    reason: ChannelClosedReason,
    wallet: Option<W>,
    channel: Option<C>,
}

impl<W, C> ClosedChannelState<W, C>
where
    W: MultiSigWallet,
    C: ClosedPaymentChannel,
{
    /// Create a new closed channel state
    pub fn new(reason: ChannelClosedReason, channel: C, wallet: W) -> Self {
        ClosedChannelState { reason, wallet: Some(wallet), channel: Some(channel) }
    }

    pub fn empty(reason: ChannelClosedReason) -> Self {
        ClosedChannelState { reason, wallet: None, channel: None }
    }

    /// Get the reason for the channel being closed
    pub fn reason(&self) -> &ChannelClosedReason {
        &self.reason
    }

    pub fn wallet(&self) -> Option<&W> {
        self.wallet.as_ref()
    }

    pub fn channel(&self) -> Option<&C> {
        self.channel.as_ref()
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
