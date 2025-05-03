use crate::channel_id::ChannelId;
use crate::crypto::traits::PublicKey;
use crate::monero::MultiSigWallet;
use crate::payment_channel::{ChannelRole, ClosedPaymentChannel};
use crate::state_machine::disputing_channel::DisputeResult;
use crate::state_machine::new_channel::{RejectNewChannelReason, TimeoutReason};
use crate::state_machine::traits::ChannelState;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
#[serde(bound(deserialize = "C: ClosedPaymentChannel + for<'d> Deserialize<'d>"))]
pub struct ClosedChannelState<P, W, C>
where
    P: PublicKey,
    W: MultiSigWallet,
    C: ClosedPaymentChannel,
{
    reason: ChannelClosedReason<P>,
    wallet: Option<W>,
    channel: CloseType<C>,
}

#[derive(Serialize, Deserialize)]
#[serde(bound(deserialize = "C: ClosedPaymentChannel + for<'d> Deserialize<'d>"))]
enum CloseType<C: ClosedPaymentChannel> {
    Channel(C),
    NoChannel { channel_id: ChannelId, channel_role: ChannelRole },
}

impl<P, W, C> ClosedChannelState<P, W, C>
where
    P: PublicKey,
    W: MultiSigWallet,
    C: ClosedPaymentChannel,
{
    /// Create a new closed channel state
    pub fn new(reason: ChannelClosedReason<P>, channel: C, wallet: W) -> Self {
        let channel = CloseType::Channel(channel);
        ClosedChannelState { reason, wallet: Some(wallet), channel }
    }

    pub fn empty(reason: ChannelClosedReason<P>, channel_id: ChannelId, role: ChannelRole) -> Self {
        let channel = CloseType::NoChannel { channel_id, channel_role: role };
        ClosedChannelState { reason, wallet: None, channel }
    }

    /// Get the reason for the channel being closed
    pub fn reason(&self) -> &ChannelClosedReason<P> {
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

impl<P, W, C> ChannelState for ClosedChannelState<P, W, C>
where
    P: PublicKey,
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

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(deserialize = "P: PublicKey  + for<'d> Deserialize<'d>"))]
pub enum ChannelClosedReason<P: PublicKey> {
    /// The channel was closed normally
    Normal,
    /// The channel was closed due to a timeout
    Timeout(TimeoutReason),
    /// The channel was closed following the dispute process
    Dispute(DisputeResult<P>),
    /// The channel was never opened because the terms were rejected
    Rejected(RejectNewChannelReason),
}
