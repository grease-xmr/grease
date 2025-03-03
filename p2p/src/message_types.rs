use crate::errors::PeerConnectionError;
use futures::channel::oneshot;
use libp2p::request_response::ResponseChannel;
use libp2p::{Multiaddr, PeerId};
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};

/// Requests that one peer can make to another peer in the Grease p2p network to create, update or close a payment
/// channel.
#[derive(Debug, Serialize, Deserialize)]
pub enum GreaseRequest {
    OpenChannel(NewChannelData),
    SendMoney,
    RequestMoney,
    CloseChannel,
}

/// The response to a [`GreaseRequest`] that the peer can return to the requester.
#[derive(Debug, Serialize, Deserialize)]
pub enum GreaseResponse {
    ChannelOpened(Result<OpenChannelSuccess, OpenChannelFailure>),
    MoneySent,
    MoneyRequested,
    ChannelClosed,
    Error(String),
}

#[derive(Debug)]
pub enum PeerConnectionCommand {
    StartListening {
        addr: Multiaddr,
        sender: oneshot::Sender<Result<(), PeerConnectionError>>,
    },
    Dial {
        peer_id: PeerId,
        peer_addr: Multiaddr,
        sender: oneshot::Sender<Result<(), PeerConnectionError>>,
    },
    OpenChannelRequest {
        peer_id: PeerId,
        data: NewChannelData,
        sender: oneshot::Sender<Result<OpenChannelSuccess, OpenChannelFailure>>,
    },
    OpenChannelResponse {
        res: Result<OpenChannelSuccess, OpenChannelFailure>,
        channel: ResponseChannel<GreaseResponse>,
    },
    ConnectedPeers {
        sender: oneshot::Sender<Vec<PeerId>>,
    },
    Shutdown(oneshot::Sender<bool>),
}

#[derive(Debug)]
pub enum PeerConnectionEvent {
    InboundRequest { request: GreaseRequest, channel: ResponseChannel<GreaseResponse> },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NewChannelData {
    pub our_amount: u64,
    pub their_amount: u64,
}

/// The result of a channel opening request.
#[derive(Debug, Serialize, Deserialize)]
pub struct OpenChannelSuccess {
    pub channel_id: u64,
    pub data: NewChannelData,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum OpenChannelFailure {
    NetworkError(String),
    InsufficientFunds(String),
    NegotiationFailed(String),
    Other(String),
}

impl Display for OpenChannelFailure {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            OpenChannelFailure::NetworkError(e) => write!(f, "Network error: {e}"),
            OpenChannelFailure::InsufficientFunds(e) => write!(f, "Insufficient funds: {e}"),
            OpenChannelFailure::NegotiationFailed(e) => write!(f, "Negotiation failed: {e}"),
            OpenChannelFailure::Other(e) => write!(f, "Other error: {e}"),
        }
    }
}
