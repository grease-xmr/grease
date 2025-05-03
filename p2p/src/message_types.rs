use crate::errors::PeerConnectionError;
use futures::channel::oneshot;
use libgrease::payment_channel::ChannelRole;
use libgrease::state_machine::error::InvalidProposal;
use libgrease::state_machine::Balances;
use libp2p::request_response::ResponseChannel;
use libp2p::{Multiaddr, PeerId};
use serde::{Deserialize, Serialize};

/// Requests that one peer can make to another peer in the Grease p2p network to create, update or close a payment
/// channel.
#[derive(Debug, Serialize, Deserialize)]
pub enum GreaseRequest {
    ProposeNewChannel(NewChannelProposal),
    SendMoney,
    RequestMoney,
    CloseChannel,
}

/// The response to a [`GreaseRequest`] that the peer can return to the requester.
#[derive(Debug, Serialize, Deserialize)]
pub enum GreaseResponse {
    ChannelProposalResult(Result<AckChannelProposal, RejectChannelProposal>),
    MoneySent,
    MoneyRequested,
    ChannelClosed,
    Error(String),
}

/// The set of commands that can be initiated by the user (via the `Client`) to the network event loop.
///
/// There is typically one method in the `Client` for each of these commands.
#[derive(Debug)]
pub enum ClientCommand {
    /// Start listening on a given address. Executed via [`crate::Client::start_listening`].
    StartListening {
        addr: Multiaddr,
        sender: oneshot::Sender<Result<(), PeerConnectionError>>,
    },
    /// Dial a peer at a given address. Executed via [`Client::dial`].
    Dial {
        peer_id: PeerId,
        peer_addr: Multiaddr,
        sender: oneshot::Sender<Result<(), PeerConnectionError>>,
    },
    /// Request with a proposal to open a payment channel with a peer. Executed via [`crate::Client::new_channel_proposal`].
    ProposeChannelRequest {
        peer_id: PeerId,
        data: NewChannelProposal,
        sender: oneshot::Sender<Result<AckChannelProposal, RejectChannelProposal>>,
    },
    /// Response to a channel opening request. It is either an [`AckChannelProposal`] or a [`RejectChannel`].
    ResponseToProposeChannel {
        res: Result<AckChannelProposal, RejectChannelProposal>,
        channel: ResponseChannel<GreaseResponse>,
    },
    MultiSigSetupRequest {
        peer_id: PeerId,
        multi_sig_setup: usize, // todo
        sender: oneshot::Sender<Result<AckChannelProposal, RejectChannelProposal>>,
    },
    ResponseToMultiSigSetup {
        res: MultiSigSetupResponse,
        channel: ResponseChannel<GreaseResponse>,
    },
    KesReadyNotification {
        peer_id: PeerId,
        kes_ready: usize, // todo
        sender: oneshot::Sender<Result<AckChannelProposal, RejectChannelProposal>>,
    },
    AckKesReadyNotification {
        res: AckKesNotification,
        channel: ResponseChannel<GreaseResponse>,
    },
    FundingTxRequestStart {
        peer_id: PeerId,
        funding_tx: usize, // todo
        sender: oneshot::Sender<Result<AckChannelProposal, RejectChannelProposal>>,
    },
    ResponseToFundingTxRequestStart {
        res: FundingTxStartResponse,
        channel: ResponseChannel<GreaseResponse>,
    },
    FundingTxFinalizeRequest {
        peer_id: PeerId,
        funding_tx: usize, // todo
        sender: oneshot::Sender<Result<AckChannelProposal, RejectChannelProposal>>,
    },
    ResponseToFundingTxFinalizeRequest {
        res: FundingTxFinalizeResponse,
        channel: ResponseChannel<GreaseResponse>,
    },
    FundingTxBroadcastNotification {
        peer_id: PeerId,
        funding_tx: usize, // todo
        sender: oneshot::Sender<Result<AckChannelProposal, RejectChannelProposal>>,
    },
    AckFundingTxBroadcastNotification {
        res: AckFundingTxBroadcast,
        channel: ResponseChannel<GreaseResponse>,
    },
    /// Request the list of connected peers. Executed via [`crate::Client::connected_peers`].
    ConnectedPeers {
        sender: oneshot::Sender<Vec<PeerId>>,
    },
    /// Shutdown the network event loop. Executed via [`crate::Client::shutdown`].
    Shutdown(oneshot::Sender<bool>),
}

#[derive(Debug)]
pub struct MultiSigSetupResponse;

#[derive(Debug)]
pub struct FundingTxStartResponse;

#[derive(Debug)]
pub struct FundingTxFinalizeResponse;

#[derive(Debug)]
pub struct AckFundingTxBroadcast;

#[derive(Debug)]
pub struct AckKesNotification;

#[derive(Debug)]
pub enum PeerConnectionEvent {
    InboundRequest { request: GreaseRequest, channel: ResponseChannel<GreaseResponse> },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NewChannelProposal {
    /// The role the proposer will take in the new payment channel. Is usually [`ChannelRole::Customer`].
    pub role: ChannelRole,
    /// Hexadecimal string representation of the public key of the peer that will be the merchant.
    pub merchant_pubkey: String,
    /// Hexadecimal string representation of the public key of the peer that will be the customer.
    pub customer_pubkey: String,
    /// Hexadecimal string representation of the public key of the Key Escrow Service.
    pub kes_public_key: String,
    /// The initial balances of the channel, in picoMonero.
    pub initial_balances: Balances,
    /// Salt used to derive the channel ID - customer portion
    pub customer_partial_channel_id: Vec<u8>,
    /// Salt used to derive the channel ID - merchant portion
    pub merchant_partial_channel_id: Vec<u8>,
    /// The deterministic name for the new channel. Also serves as a checksum for the information presented in this
    /// struct.
    pub channel_name: String,
}

/// The result of a channel opening request.
#[derive(Debug, Serialize, Deserialize)]
pub struct AckChannelProposal {
    pub data: NewChannelProposal,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RejectChannelProposal {
    pub reason: RejectReason,
    pub retry: RetryOptions,
}

impl RejectChannelProposal {
    pub fn new(reason: RejectReason, retry: RetryOptions) -> Self {
        RejectChannelProposal { reason, retry }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum RejectReason {
    /// The proposal contained invalid information.
    InvalidProposal(InvalidProposal),
    /// The proposal was rejected by the peer because it is unavailable to open a channel. Do not retry
    PeerUnavailable,
    /// The proposal was rejected by the peer because it is at capacity. You can retry later.
    AtCapacity,
    /// The proposal was not sent to the peer due to a local constraint.
    NotSent(String),
}

const RETRY: u64 = 1;
const CLOSE_CHANNEL: u64 = 2;
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct RetryOptions {
    bitmask: u64,
}

impl RetryOptions {
    pub fn close_only() -> Self {
        RetryOptions { bitmask: CLOSE_CHANNEL }
    }

    pub fn retry_only() -> Self {
        RetryOptions { bitmask: RETRY }
    }

    pub fn and_close(&self) -> Self {
        RetryOptions { bitmask: self.bitmask | CLOSE_CHANNEL }
    }

    pub fn and_retry(&self) -> Self {
        RetryOptions { bitmask: self.bitmask | RETRY }
    }
}
