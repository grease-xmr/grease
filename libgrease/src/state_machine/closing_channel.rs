use crate::crypto::traits::PublicKey;
use crate::kes::KeyEscrowService;
use crate::monero::MultiSigWallet;
use crate::payment_channel::ActivePaymentChannel;
use crate::state_machine::EstablishedChannelState;

pub struct ClosingChannelState<P, C, W, KES>
where
    P: PublicKey,
    C: ActivePaymentChannel,
    W: MultiSigWallet,
    KES: KeyEscrowService,
{
    pub(crate) secret: P::SecretKey,
    pub(crate) payment_channel: C,
    pub(crate) wallet: W,
    pub(crate) kes: KES,
}

impl<P, C, W, KES> ClosingChannelState<P, C, W, KES>
where
    P: PublicKey,
    C: ActivePaymentChannel,
    W: MultiSigWallet,
    KES: KeyEscrowService,
{
    /// Create a new closing channel state
    pub fn from_open(open_state: EstablishedChannelState<P, C, W, KES>) -> Self {
        ClosingChannelState {
            secret: open_state.secret,
            payment_channel: open_state.payment_channel,
            wallet: open_state.wallet,
            kes: open_state.kes,
        }
    }
}

pub struct StartCloseInfo {}

pub struct InvalidCloseInfo {
    pub reason: String,
}

pub struct SuccessfulCloseInfo {}
