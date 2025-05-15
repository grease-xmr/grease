use crate::channel_id::ChannelId;
use crate::crypto::traits::PublicKey;
use crate::kes::KeyEscrowService;
use crate::monero::MultiSigService;
use crate::payment_channel::{ActivePaymentChannel, ChannelRole};
use crate::state_machine::traits::ChannelState;
use crate::state_machine::EstablishedChannelState;
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(deserialize = "C: ActivePaymentChannel + for<'d> Deserialize<'d>"))]
pub struct ClosingChannelState<P, C, WS, KES>
where
    P: PublicKey,
    C: ActivePaymentChannel,
    WS: MultiSigService,
    KES: KeyEscrowService,
{
    pub(crate) secret: P::SecretKey,
    pub(crate) payment_channel: C,
    pub(crate) wallet: WS::Wallet,
    pub(crate) wallet_service: WS,
    pub(crate) kes: KES,
}

impl<P, C, WS, KES> ClosingChannelState<P, C, WS, KES>
where
    P: PublicKey,
    C: ActivePaymentChannel,
    WS: MultiSigService,
    KES: KeyEscrowService,
{
    /// Create a new closing channel state
    pub fn from_open(open_state: EstablishedChannelState<P, C, WS, KES>) -> Self {
        ClosingChannelState {
            secret: open_state.secret,
            payment_channel: open_state.payment_channel,
            wallet: open_state.wallet,
            wallet_service: open_state.wallet_service,
            kes: open_state.kes,
        }
    }
}

impl<P, C, WS, KES> ChannelState for ClosingChannelState<P, C, WS, KES>
where
    P: PublicKey,
    C: ActivePaymentChannel,
    WS: MultiSigService,
    KES: KeyEscrowService,
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
