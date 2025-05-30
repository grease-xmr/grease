use crate::balance::Balances;
use crate::channel_metadata::ChannelMetadata;
use crate::crypto::traits::PublicKey;
use crate::monero::MultiSigWallet;
use crate::state_machine::{ClosingChannelState, EstablishedChannelState};
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Display, Formatter};

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(deserialize = "P: PublicKey + for<'d> Deserialize<'d>"))]
pub struct DisputingChannelState<P, W>
where
    P: PublicKey,
    W: MultiSigWallet,
{
    pub(crate) origin: DisputeOrigin,
    pub(crate) reason: String,
    pub(crate) wallet: W,
    pub(crate) channel_info: ChannelMetadata<P>,
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

impl<P, W> DisputingChannelState<P, W>
where
    P: PublicKey,
    W: MultiSigWallet,
{
    /// Create a new disputing channel state
    pub fn from_open(open_state: EstablishedChannelState<P, W>, info: ForceCloseInfo) -> Self {
        DisputingChannelState {
            origin: info.origin,
            reason: info.reason,
            wallet: open_state.wallet,
            channel_info: open_state.channel_info,
        }
    }

    pub fn from_closing(closing_state: ClosingChannelState<P, W>, info: ForceCloseInfo) -> Self {
        DisputingChannelState {
            origin: info.origin,
            reason: info.reason,
            wallet: closing_state.wallet,
            channel_info: closing_state.channel_info,
        }
    }

    pub fn current_balances(&self) -> Balances {
        todo!("Implement current balances logic for closing channel state")
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
