use crate::channel_id::ChannelId;
use crate::crypto::traits::PublicKey;
use crate::kes::KeyEscrowService;
use crate::monero::MultiSigService;
use crate::payment_channel::{ActivePaymentChannel, ChannelRole};
use crate::state_machine::traits::ChannelState;
use crate::state_machine::{ClosingChannelState, EstablishedChannelState};
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Display, Formatter};

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(deserialize = "C: ActivePaymentChannel + for<'d> Deserialize<'d>"))]
pub struct DisputingChannelState<P, C, WS, KES>
where
    P: PublicKey,
    C: ActivePaymentChannel,
    WS: MultiSigService,
    KES: KeyEscrowService,
{
    pub(crate) origin: DisputeOrigin,
    pub(crate) reason: String,
    pub(crate) secret: P::SecretKey,
    pub(crate) payment_channel: C,
    pub(crate) wallet_service: WS,
    pub(crate) wallet: WS::Wallet,
    pub(crate) kes: KES,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DisputeOrigin {
    /// You have  initiated a force close.
    ForceCloseTriggered,
    /// The peer has initiated a force close, and you (might) need to respond
    ResponseToForceClose,
}

impl Display for DisputeOrigin {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            DisputeOrigin::ForceCloseTriggered => write!(f, "We triggered a force close"),
            DisputeOrigin::ResponseToForceClose => write!(f, "The peer triggered a force close"),
        }
    }
}

pub struct ForceCloseInfo {
    pub origin: DisputeOrigin,
    pub reason: String,
}

impl ForceCloseInfo {
    pub fn trigger(reason: impl Into<String>) -> Self {
        ForceCloseInfo { origin: DisputeOrigin::ForceCloseTriggered, reason: reason.into() }
    }

    pub fn respond(reason: impl Into<String>) -> Self {
        ForceCloseInfo { origin: DisputeOrigin::ResponseToForceClose, reason: reason.into() }
    }
}

impl<P, C, WS, KES> DisputingChannelState<P, C, WS, KES>
where
    P: PublicKey,
    C: ActivePaymentChannel,
    WS: MultiSigService,
    KES: KeyEscrowService,
{
    /// Create a new disputing channel state
    pub fn from_open(open_state: EstablishedChannelState<P, C, WS, KES>, info: ForceCloseInfo) -> Self {
        DisputingChannelState {
            origin: info.origin,
            reason: info.reason,
            secret: open_state.secret,
            payment_channel: open_state.payment_channel,
            wallet: open_state.wallet,
            wallet_service: open_state.wallet_service,
            kes: open_state.kes,
        }
    }

    pub fn from_closing(closing_state: ClosingChannelState<P, C, WS, KES>, info: ForceCloseInfo) -> Self {
        DisputingChannelState {
            origin: info.origin,
            reason: info.reason,
            secret: closing_state.secret,
            payment_channel: closing_state.payment_channel,
            wallet: closing_state.wallet,
            wallet_service: closing_state.wallet_service,
            kes: closing_state.kes,
        }
    }
}

impl<P, C, WS, KES> ChannelState for DisputingChannelState<P, C, WS, KES>
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DisputeLostInfo {
    pub(crate) reason: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct DisputeWonInfo<P: PublicKey> {
    pub(crate) reason: String,
    pub(crate) peer_spend_key: P::SecretKey,
}

impl<P: PublicKey> Debug for DisputeWonInfo<P> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "DisputeWonInfo {{ reason: {}, peer_spend_key: <hidden> }}", self.reason)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(deserialize = "P: PublicKey  + for<'d> Deserialize<'d>"))]
pub enum DisputeResult<P: PublicKey> {
    UncontestedForceClose,
    DisputeLost(DisputeLostInfo),
    DisputeWon(DisputeWonInfo<P>),
}

pub struct DisputeResolvedInfo<P: PublicKey> {
    pub(crate) result: DisputeResult<P>,
}

impl<P: PublicKey> DisputeResolvedInfo<P> {
    pub fn uncontested() -> Self {
        DisputeResolvedInfo { result: DisputeResult::UncontestedForceClose }
    }

    pub fn lost(reason: impl Into<String>) -> Self {
        let info = DisputeLostInfo { reason: reason.into() };
        DisputeResolvedInfo { result: DisputeResult::DisputeLost(info) }
    }

    pub fn won(reason: impl Into<String>, peer_spend_key: P::SecretKey) -> Self {
        let info = DisputeWonInfo { reason: reason.into(), peer_spend_key };
        DisputeResolvedInfo { result: DisputeResult::DisputeWon(info) }
    }
}
