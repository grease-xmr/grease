use crate::errors::PeerConnectionError;
use crate::ContactInfo;
use futures::channel::oneshot;
use libgrease::channel_id::ChannelId;
use libgrease::crypto::traits::PublicKey;
use libgrease::payment_channel::ChannelRole;
use libgrease::state_machine::error::InvalidProposal;
use libgrease::state_machine::{ChannelSeedInfo, ProposedChannelInfo};
use libp2p::request_response::ResponseChannel;
use libp2p::{Multiaddr, PeerId};
use monero::Address as MoneroAddress;
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};

/// Requests that one peer can make to another peer in the Grease p2p network to create, update or close a payment
/// channel.
#[derive(Debug, Serialize, Deserialize)]
#[serde(bound(deserialize = "P: PublicKey  + for<'d> Deserialize<'d>"))]
pub enum GreaseRequest<P: PublicKey> {
    ProposeNewChannel(NewChannelProposal<P>),
    /// A request from the merchant to begin initializing the commit transaction wallet (Prep phase).
    MsInit(MultisigSetupInfo),
    /// A request from the merchant to exchange multisig keys (Prep phase).
    MsKeyExchange(MultisigKeyInfo),
    /// A request from the merchant to confirm that the multisig address was set up correctly (Prep phase).
    ConfirmMsAddress(MoneroAddress),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MultisigSetupInfo {
    // Something like MultisigxV2R1C9Bd2LN...
    pub init: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MultisigKeyInfo {
    // Something like MultisigxV2Rn1LVYohry...
    pub key: String,
}

/// The response to a [`GreaseRequest`] that the peer can return to the requester.
#[derive(Debug, Serialize, Deserialize)]
#[serde(bound(deserialize = "P: PublicKey  + for<'d> Deserialize<'d>"))]
pub enum GreaseResponse<P: PublicKey> {
    ChannelProposalResult(ChannelProposalResult<P>),
    /// The customer's response to the MS init request. The customer's Init info is included in the response.
    MsInit(MultiSigInitResponse),
    /// The customer's response to the MS key exchange request. The customer's key info is included in the response.
    MsKeyExchange(MultisigKeyResponse),
    /// The customer's response to the MS address confirmation request. The response is a boolean indicating
    /// whether the address was confirmed or not. If false, the channel establishment will be aborted.
    ConfirmMsAddress(bool),
    ChannelClosed,
    ChannelNotFound,
    Error(String),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MultiSigInitResponse {
    // Something like MultisigxV2R1C9Bd2LN...
    pub init: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MultisigKeyResponse {
    // Something like MultisigxV2Rn1LVYohry...
    pub key: String,
}

impl<P: PublicKey> From<ChannelProposalResult<P>> for GreaseResponse<P> {
    fn from(res: ChannelProposalResult<P>) -> Self {
        GreaseResponse::ChannelProposalResult(res)
    }
}

impl<P> Display for GreaseResponse<P>
where
    P: PublicKey,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            GreaseResponse::ChannelProposalResult(ChannelProposalResult::Accepted(_)) => {
                write!(f, "Channel Proposal accepted")
            }
            GreaseResponse::ChannelProposalResult(ChannelProposalResult::Rejected(ref _rej)) => {
                write!(f, "Channel Proposal REJECTED.")
            }
            GreaseResponse::Error(err) => write!(f, "Error: {}", err),
            GreaseResponse::MsInit(info) => write!(f, "MultisigInit({})", info.init),
            GreaseResponse::MsKeyExchange(_) => write!(f, "MultisigKeyExchange(***)"),
            GreaseResponse::ConfirmMsAddress(ok) => {
                write!(f, "Multisig address confirmation: {}", if *ok { "OK" } else { "NOT OK" })
            }
            GreaseResponse::ChannelClosed => write!(f, "Channel Closed"),
            GreaseResponse::ChannelNotFound => write!(f, "Channel Not Found"),
        }
    }
}

impl<P> GreaseRequest<P>
where
    P: PublicKey,
{
    pub fn channel_name(&self) -> String {
        match self {
            GreaseRequest::ProposeNewChannel(ref proposal) => proposal.channel_name(),
            _ => todo!(),
        }
    }
}

/// The set of commands that can be initiated by the user (via the `Client`) to the network event loop.
///
/// There is typically one method in the `Client` for each of these commands.
#[derive(Debug)]
pub enum ClientCommand<P: PublicKey> {
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
    /// Generalised response message to peers for all requests.
    ResponseToRequest {
        res: GreaseResponse<P>,
        return_chute: ResponseChannel<GreaseResponse<P>>,
    },
    /// Request with a proposal to open a payment channel with a peer. Executed via [`crate::Client::new_channel_proposal`].
    ProposeChannelRequest {
        peer_id: PeerId,
        data: NewChannelProposal<P>,
        sender: oneshot::Sender<ChannelProposalResult<P>>,
    },
    MultiSigSetupRequest {
        peer_id: PeerId,
        multi_sig_setup: MultisigSetupInfo,
        sender: oneshot::Sender<MultiSigSetupResponse>,
    },
    KesReadyNotification {
        peer_id: PeerId,
        kes_ready: usize, // todo
        sender: oneshot::Sender<AckKesNotification>,
    },
    AckKesReadyNotification {
        res: AckKesNotification,
        channel: ResponseChannel<GreaseResponse<P>>,
    },
    FundingTxRequestStart {
        peer_id: PeerId,
        funding_tx: usize, // todo
        sender: oneshot::Sender<FundingTxStartResponse>,
    },
    FundingTxFinalizeRequest {
        peer_id: PeerId,
        funding_tx: usize, // todo
        sender: oneshot::Sender<FundingTxFinalizeResponse>,
    },
    FundingTxBroadcastNotification {
        peer_id: PeerId,
        funding_tx: usize, // todo
        sender: oneshot::Sender<AckFundingTxBroadcast>,
    },
    AckFundingTxBroadcastNotification {
        res: AckFundingTxBroadcast,
        channel: ResponseChannel<GreaseResponse<P>>,
    },
    /// Request the list of connected peers. Executed via [`crate::Client::connected_peers`].
    ConnectedPeers {
        sender: oneshot::Sender<Vec<PeerId>>,
    },
    /// Shutdown the network event loop. Executed via [`crate::Client::shutdown`].
    Shutdown(oneshot::Sender<bool>),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MultiSigSetupInfo {}

#[derive(Debug, Serialize, Deserialize)]
pub struct MultiSigSetupResponse;

#[derive(Debug, Serialize, Deserialize)]
pub struct FundingTxStartResponse;

#[derive(Debug, Serialize, Deserialize)]
pub struct FundingTxFinalizeResponse;

#[derive(Debug, Serialize, Deserialize)]
pub struct AckFundingTxBroadcast;

#[derive(Debug, Serialize, Deserialize)]
pub struct AckKesNotification;

#[derive(Debug)]
pub enum PeerConnectionEvent<P: PublicKey> {
    InboundRequest { request: GreaseRequest<P>, response: ResponseChannel<GreaseResponse<P>> },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(deserialize = "P: PublicKey  + for<'d> Deserialize<'d>"))]
pub struct NewChannelProposal<P: PublicKey> {
    /// The seed info that the (usually) merchant provided initially.
    pub seed: ChannelSeedInfo<P>,
    /// The contact info for the customer (usually).
    pub contact_info_proposer: ContactInfo,
    /// The contact info for the merchant (usually).
    pub contact_info_proposee: ContactInfo,
    /// Hexadecimal string representation of the public key of the peer that will be the customer (usually).
    pub proposer_pubkey: P,
    /// Salt used to derive the channel ID - customer (usually) portion
    pub proposer_label: String,
}

impl<P: PublicKey> NewChannelProposal<P> {
    pub fn new<S: Into<String>>(
        seed: ChannelSeedInfo<P>,
        my_pubkey: P,
        my_label: S,
        my_contact_info: ContactInfo,
        their_contact_info: ContactInfo,
    ) -> Self {
        Self {
            seed,
            contact_info_proposer: my_contact_info,
            contact_info_proposee: their_contact_info,
            proposer_pubkey: my_pubkey,
            proposer_label: my_label.into(),
        }
    }

    pub fn channel_name(&self) -> String {
        format!("{}-{}", self.proposer_label, self.seed.user_label)
    }

    /// Produce a struct that contains the information needed to create a new channel.
    /// The information is from the point of view of the *proposer* of the channel, usually the customer.
    pub fn proposed_channel_info(&self) -> ProposedChannelInfo<P> {
        let (merchant_pubkey, customer_pubkey) = match self.seed.role {
            ChannelRole::Merchant => (self.proposer_pubkey.clone(), self.seed.pubkey.clone()),
            ChannelRole::Customer => (self.seed.pubkey.clone(), self.proposer_pubkey.clone()),
        };
        let (merchant_label, customer_label) = match self.seed.role {
            ChannelRole::Merchant => (self.proposer_label.clone(), self.seed.user_label.clone()),
            ChannelRole::Customer => (self.seed.user_label.clone(), self.proposer_label.clone()),
        };
        let channel_id = ChannelId::new::<blake2::Blake2b512, _, _, _>(
            &merchant_label,
            &customer_label,
            "",
            self.seed.initial_balances,
        );
        ProposedChannelInfo {
            role: self.seed.role,
            merchant_pubkey,
            customer_pubkey,
            kes_public_key: self.seed.kes_public_key.clone(),
            initial_balances: self.seed.initial_balances,
            customer_label,
            merchant_label,
            channel_id,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(bound(deserialize = "P: PublicKey  + for<'d> Deserialize<'d>"))]
pub enum ChannelProposalResult<P: PublicKey> {
    Accepted(NewChannelProposal<P>),
    Rejected(RejectChannelProposal),
}

impl<P: PublicKey> ChannelProposalResult<P> {
    pub fn accept(proposal: NewChannelProposal<P>) -> Self {
        ChannelProposalResult::Accepted(proposal)
    }
    pub fn reject(reason: RejectReason, retry: RetryOptions) -> Self {
        ChannelProposalResult::Rejected(RejectChannelProposal::new(reason, retry))
    }
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
    /// The channel was not newly created, and so cannot accept a proposal.
    NotANewChannel,
    /// The proposal was rejected for an internal reason or bug.
    Internal(String),
}

impl Display for RejectReason {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            RejectReason::InvalidProposal(err) => write!(f, "Invalid proposal: {}", err),
            RejectReason::PeerUnavailable => write!(f, "Peer unavailable"),
            RejectReason::AtCapacity => write!(f, "At capacity"),
            RejectReason::NotSent(err) => write!(f, "Not sent: {}", err),
            RejectReason::NotANewChannel => {
                write!(f, "The channel was not newly created, and so cannot accept a proposal.")
            }
            RejectReason::Internal(msg) => write!(f, "Internal error: {msg}"),
        }
    }
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
