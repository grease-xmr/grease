use crate::channel_id::ChannelId;
use crate::crypto::traits::PublicKey;
use crate::monero::MultiSigWallet;
use crate::payment_channel::{ActivePaymentChannel, ChannelRole};
use crate::state_machine::traits::ChannelState;
use crate::state_machine::{ChannelMetadata, EstablishedChannelState};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(deserialize = "C: ActivePaymentChannel + for<'d> Deserialize<'d>"))]
pub struct ClosingChannelState<P, C, W>
where
    P: PublicKey,
    C: ActivePaymentChannel,
    W: MultiSigWallet,
{
    pub(crate) channel_info: ChannelMetadata<P>,
    pub(crate) payment_channel: C,
    pub(crate) wallet: W,
}

impl<P, C, W> ClosingChannelState<P, C, W>
where
    P: PublicKey,
    C: ActivePaymentChannel,
    W: MultiSigWallet,
{
    /// Create a new closing channel state
    pub fn from_open(open_state: EstablishedChannelState<P, C, W>) -> Self {
        ClosingChannelState {
            channel_info: open_state.channel_info,
            payment_channel: open_state.payment_channel,
            wallet: open_state.wallet,
        }
    }
}

impl<P, C, W> ChannelState for ClosingChannelState<P, C, W>
where
    P: PublicKey,
    C: ActivePaymentChannel,
    W: MultiSigWallet,
{
    fn channel_id(&self) -> &ChannelId {
        self.payment_channel.channel_id()
    }

    fn role(&self) -> ChannelRole {
        self.payment_channel.role()
    }
}

pub struct StartCloseInfo {}

pub struct SuccessfulCloseInfo {}
