use crate::errors::{PeerConnectionError, RemoteServerError};
use crate::ContactInfo;
use futures::channel::oneshot;
use libgrease::channel_id::ChannelId;
use libgrease::crypto::zk_objects::PublicProof0;
use libgrease::monero::data_objects::{
    ChannelUpdate, ChannelUpdateFinalization, MessageEnvelope, MultisigKeyInfo, MultisigSplitSecrets,
    MultisigSplitSecretsResponse, StartChannelUpdateConfirmation, TransactionRecord,
};
use libgrease::payment_channel::ChannelRole;
use libgrease::state_machine::error::{InvalidProposal, LifeCycleError};
use libgrease::state_machine::{ChannelSeedInfo, ProposedChannelInfo};
use libp2p::request_response::ResponseChannel;
use libp2p::{Multiaddr, PeerId};
use log::*;
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};

/// Requests that one peer can make to another peer in the Grease p2p network to create, update or close a payment
/// channel.
#[derive(Debug, Serialize, Deserialize)]
pub enum GreaseRequest {
    /// The customer proposes a new channel to the merchant.
    ProposeChannelRequest(NewChannelProposal),
    /// The customer sends its multisig wallet key and expects the merchant keys as a response.
    MsKeyExchange(MessageEnvelope<MultisigKeyInfo>),
    /// The customer sends its split secrets to the merchant, and expects the merchant's split secrets and a
    /// signature from the KES in return.
    MsSplitSecretExchange(MessageEnvelope<MultisigSplitSecrets>),
    /// The customer wants to confirm that the wallet is created correctly.
    ConfirmMsAddress(MessageEnvelope<String>),
    /// The customer is requesting an exchange of witness0 proofs as one of the final steps for establishing a new
    /// channel
    ExchangeProof0(MessageEnvelope<PublicProof0>),
    /// The initiator of an update sends this request. The responder will validate the proofs, generate their own
    /// proofs and respond their own proofs. The responder responds with [`GreaseResponse::ConfirmUpdate`].
    StartChannelUpdate(MessageEnvelope<ChannelUpdate>),
    /// The final conformation of the channel update. The initiator will send this request after revalidating the
    /// proofs from the responder. The responder does not return a response to this request.
    FinalizeChannelUpdate(MessageEnvelope<ChannelUpdateFinalization>),
}

/// The response to a [`GreaseRequest`] that the peer can return to the requester.
#[derive(Debug, Serialize, Deserialize)]
pub enum GreaseResponse {
    ProposeChannelResponse(Result<ChannelProposalResult, RemoteServerError>),
    /// The merchant's response to the MS key exchange request. The customer's key info and split secrets are
    /// included in the response.
    MsKeyExchange(Result<MessageEnvelope<MultisigKeyInfo>, RemoteServerError>),
    MsSplitSecretExchange(Result<MessageEnvelope<MultisigSplitSecretsResponse>, RemoteServerError>),
    /// The customer's response to the MS address confirmation request. The response is a boolean indicating
    /// whether the address was confirmed or not. If false, the channel establishment will be aborted.
    ConfirmMsAddress(Result<MessageEnvelope<bool>, RemoteServerError>),
    ExchangeProof0(Result<MessageEnvelope<PublicProof0>, RemoteServerError>),
    ConfirmUpdate(Result<MessageEnvelope<StartChannelUpdateConfirmation>, RemoteServerError>),
    ChannelClosed,
    ChannelNotFound,
    Error(String),
    /// Do not return a response to the peer at all.
    NoResponse,
}

impl From<ChannelProposalResult> for GreaseResponse {
    fn from(res: ChannelProposalResult) -> Self {
        GreaseResponse::ProposeChannelResponse(Ok(res))
    }
}

impl Display for GreaseResponse {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            GreaseResponse::ProposeChannelResponse(Ok(ChannelProposalResult::Accepted(_))) => {
                write!(f, "Channel Proposal accepted")
            }
            GreaseResponse::ProposeChannelResponse(Ok(ChannelProposalResult::Rejected(ref _rej))) => {
                write!(f, "Channel Proposal REJECTED.")
            }
            GreaseResponse::ProposeChannelResponse(Err(err)) => {
                write!(f, "Remote server error: {err} while proposing a new channel")
            }
            GreaseResponse::Error(err) => write!(f, "Error: {}", err),
            GreaseResponse::MsKeyExchange(Ok(_)) => write!(f, "MultisigKeyExchange(***)"),
            GreaseResponse::MsKeyExchange(Err(e)) => write!(
                f,
                "Remote server error during MultisigKeyExchangeError\
            ({e})"
            ),
            GreaseResponse::ConfirmMsAddress(Ok(env)) => {
                let status = if env.payload { "OK" } else { "NOT OK" };
                write!(f, "Multisig address confirmation: {status}")
            }
            GreaseResponse::ConfirmMsAddress(Err(e)) => write!(
                f,
                "Remote server error ({e}) at MsConfirmMsAddress \
            stage"
            ),
            GreaseResponse::ChannelClosed => write!(f, "Channel Closed"),
            GreaseResponse::ChannelNotFound => write!(f, "Channel Not Found"),
            GreaseResponse::ConfirmUpdate(_) => write!(f, "Confirmation Update"),
            GreaseResponse::NoResponse => write!(f, "No response to send"),
            GreaseResponse::MsSplitSecretExchange(_) => write!(f, "MsSplitSecretExchange"),
            GreaseResponse::ExchangeProof0(_) => write!(f, "ExchangeProof0"),
        }
    }
}

impl GreaseRequest {
    pub fn channel_name(&self) -> String {
        match self {
            GreaseRequest::ProposeChannelRequest(ref proposal) => proposal.channel_name(),
            GreaseRequest::MsKeyExchange(env) => env.channel_name(),
            GreaseRequest::ConfirmMsAddress(env) => env.channel_name(),
            GreaseRequest::StartChannelUpdate(env) => env.channel_name(),
            GreaseRequest::FinalizeChannelUpdate(env) => env.channel_name(),
            GreaseRequest::MsSplitSecretExchange(env) => env.channel_name(),
            GreaseRequest::ExchangeProof0(env) => env.channel_name(),
        }
    }
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
    /// Generalised response message to peers for all requests.
    ResponseToRequest {
        res: GreaseResponse,
        return_chute: ResponseChannel<GreaseResponse>,
    },
    /// An internal message to confirm that the funding transaction has been confirmed.
    WaitForFundingTx {
        channel: String,
        sender: oneshot::Sender<Result<TransactionRecord, PeerConnectionError>>,
    },
    NotifyTxMined(TransactionRecord),
    /// Request with a proposal to open a payment channel with a peer. Executed via [`crate::Client::new_channel_proposal`].
    ProposeChannelRequest {
        peer_id: PeerId,
        data: NewChannelProposal,
        sender: oneshot::Sender<Result<ChannelProposalResult, RemoteServerError>>,
    },
    MultiSigKeyExchange {
        peer_id: PeerId,
        envelope: MessageEnvelope<MultisigKeyInfo>,
        sender: oneshot::Sender<Result<MessageEnvelope<MultisigKeyInfo>, RemoteServerError>>,
    },
    MultiSigSplitSecretsRequest {
        peer_id: PeerId,
        envelope: MessageEnvelope<MultisigSplitSecrets>,
        sender: oneshot::Sender<Result<MessageEnvelope<MultisigSplitSecretsResponse>, RemoteServerError>>,
    },
    ConfirmMultiSigAddressRequest {
        peer_id: PeerId,
        envelope: MessageEnvelope<String>,
        sender: oneshot::Sender<Result<MessageEnvelope<bool>, RemoteServerError>>,
    },
    ExchangeProof0 {
        peer_id: PeerId,
        envelope: MessageEnvelope<PublicProof0>,
        sender: oneshot::Sender<Result<MessageEnvelope<PublicProof0>, RemoteServerError>>,
    },
    InitiateNewUpdate {
        peer_id: PeerId,
        envelope: MessageEnvelope<ChannelUpdate>,
        sender: oneshot::Sender<Result<MessageEnvelope<StartChannelUpdateConfirmation>, RemoteServerError>>,
    },
    /// Verify the responder proofs provided in the `ChannelUpdate` given in the envelope; validate the update, and
    /// send final confirmation to the responder.
    FinalizeUpdate {
        peer_id: PeerId,
        envelope: MessageEnvelope<ChannelUpdateFinalization>,
        sender: oneshot::Sender<Result<(), RemoteServerError>>,
    },
    /// Request the list of connected peers. Executed via [`crate::Client::connected_peers`].
    ConnectedPeers {
        sender: oneshot::Sender<Vec<PeerId>>,
    },
    /// Shutdown the network event loop. Executed via [`crate::Client::shutdown`].
    Shutdown(oneshot::Sender<bool>),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FundingTxStartResponse;

#[derive(Debug, Serialize, Deserialize)]
pub struct FundingTxFinalizeResponse;

#[derive(Debug, Serialize, Deserialize)]
pub struct AckFundingTxBroadcast;

#[derive(Debug)]
pub enum PeerConnectionEvent {
    InboundRequest { request: GreaseRequest, response: ResponseChannel<GreaseResponse> },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NewChannelProposal {
    /// The seed info that the (usually) merchant provided initially.
    pub seed: ChannelSeedInfo,
    /// The contact info for the customer (usually).
    pub contact_info_proposer: ContactInfo,
    /// The contact info for the merchant (usually).
    pub contact_info_proposee: ContactInfo,
    /// Salt used to derive the channel ID - customer (usually) portion
    pub proposer_label: String,
}

impl NewChannelProposal {
    pub fn new(
        seed: ChannelSeedInfo,
        my_label: impl Into<String>,
        my_contact_info: ContactInfo,
        their_contact_info: ContactInfo,
    ) -> Self {
        Self {
            seed,
            contact_info_proposer: my_contact_info,
            contact_info_proposee: their_contact_info,
            proposer_label: my_label.into(),
        }
    }

    pub fn channel_name(&self) -> String {
        format!("{}-{}", self.proposer_label, self.seed.user_label)
    }

    /// Produce a struct that contains the information needed to create a new channel.
    /// The information is from the point of view of the *proposer* of the channel, usually the customer.
    pub fn proposed_channel_info(&self) -> ProposedChannelInfo {
        let (merchant_label, customer_label) = match self.seed.role {
            ChannelRole::Merchant => (self.proposer_label.clone(), self.seed.user_label.clone()),
            ChannelRole::Customer => (self.seed.user_label.clone(), self.proposer_label.clone()),
        };
        let channel_id =
            ChannelId::new::<blake2::Blake2b512>(&merchant_label, &customer_label, self.seed.initial_balances);
        ProposedChannelInfo {
            role: self.seed.role,
            kes_public_key: self.seed.kes_public_key.clone(),
            initial_balances: self.seed.initial_balances,
            customer_label,
            merchant_label,
            channel_name: channel_id.name(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
pub enum ChannelProposalResult {
    Accepted(NewChannelProposal),
    Rejected(RejectChannelProposal),
}

impl ChannelProposalResult {
    pub fn accept(proposal: NewChannelProposal) -> Self {
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

    pub fn internal(reason: impl Into<String>) -> Self {
        RejectChannelProposal { reason: RejectReason::Internal(reason.into()), retry: RetryOptions::close_only() }
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
            RejectReason::NotANewChannel => {
                write!(f, "The channel was not newly created, and so cannot accept a proposal.")
            }
            RejectReason::Internal(msg) => write!(f, "Internal error: {msg}"),
        }
    }
}

impl From<LifeCycleError> for RejectReason {
    fn from(err: LifeCycleError) -> Self {
        match err {
            LifeCycleError::InvalidStateTransition => RejectReason::NotANewChannel,
            LifeCycleError::Proposal(invalid) => RejectReason::InvalidProposal(invalid),
            LifeCycleError::WalletError(e) => {
                warn!("🖥️  Cannot send AckProposal to peer because of an internal error: {e}");
                RejectReason::Internal("Peer had an issue with the multisig wallet service".into())
            }
            LifeCycleError::InvalidState(s) => {
                warn!("🖥️  Cannot send AckProposal to peer because we are not in the expected state: {s}");
                RejectReason::NotANewChannel
            }
            LifeCycleError::NotEnoughFunds => RejectReason::NotANewChannel,
            LifeCycleError::InternalError(s) => RejectReason::Internal(s),
            LifeCycleError::MismatchedUpdateCount { .. } => unreachable!("Mismatched update count"),
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
