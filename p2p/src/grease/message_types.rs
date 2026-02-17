use crate::errors::RemoteServerError;
use crate::ContactInfo;
use libgrease::amount::MoneroDelta;
use libgrease::channel_id::{ChannelId, ChannelIdMetadata};
use libgrease::cryptography::zk_objects::{PublicProof0, PublicUpdateProof};
use libgrease::monero::data_objects::{
    FinalizedUpdate, MessageEnvelope, MultisigKeyInfo, MultisigSplitSecrets, MultisigSplitSecretsResponse,
    TransactionId,
};
use libgrease::state_machine::error::{InvalidProposal, LifeCycleError};
use libgrease::state_machine::{ChannelCloseRecord, MerchantSeedInfo, NewChannelProposal};
use libgrease::wallet::multisig_wallet::AdaptSig;
use log::*;
use monero::Network;
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Display, Formatter};

/// Requests that one peer can make to another peer in the Grease p2p network to create, update or close a payment
/// channel.
#[derive(Debug, Serialize, Deserialize)]
pub enum GreaseRequest {
    /// The customer proposes a new channel to the merchant.
    ProposeChannelRequest(NewChannelMessage),
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
    /// The initiator of an update sends this request as the first round of the update process
    PrepareUpdate(MessageEnvelope<PrepareUpdate>),
    CommitUpdate(MessageEnvelope<UpdateCommitted>),
    /// Either party can issue this request, asking for the channel to be closed co-operatively.
    ChannelClose(MessageEnvelope<ChannelCloseRecord>),
    /// Peer is informing that the closing transaction has been sent to the network.
    ChannelClosed(MessageEnvelope<TransactionId>),
}

/// The response to a [`GreaseRequest`] that the peer can return to the requester.
#[derive(Debug, Serialize, Deserialize)]
pub enum GreaseResponse {
    ProposeChannelResponse(ChannelProposalResult),
    /// The merchant's response to the MS key exchange request. The customer's key info and split secrets are
    /// included in the response.
    MsKeyExchange(MessageEnvelope<MultisigKeyInfo>),
    MsSplitSecretExchange(MessageEnvelope<MultisigSplitSecretsResponse>),
    /// The customer's response to the MS address confirmation request. The response is a boolean indicating
    /// whether the address was confirmed or not. If false, the channel establishment will be aborted.
    ConfirmMsAddress(MessageEnvelope<bool>),
    ExchangeProof0(MessageEnvelope<PublicProof0>),
    UpdatePrepared(MessageEnvelope<UpdatePrepared>),
    UpdateCommitted(MessageEnvelope<FinalizedUpdate>),
    ChannelClose(MessageEnvelope<ChannelCloseRecord>),
    ChannelClosed(MessageEnvelope<bool>),
    Error(RemoteServerError),
    /// Do not return a response to the peer at all.
    NoResponse,
}

impl From<ChannelProposalResult> for GreaseResponse {
    fn from(res: ChannelProposalResult) -> Self {
        GreaseResponse::ProposeChannelResponse(res)
    }
}

impl From<RemoteServerError> for GreaseResponse {
    fn from(err: RemoteServerError) -> Self {
        GreaseResponse::Error(err)
    }
}

impl Display for GreaseResponse {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            GreaseResponse::ProposeChannelResponse(ChannelProposalResult::Accepted(_)) => {
                write!(f, "Channel Proposal accepted")
            }
            GreaseResponse::ProposeChannelResponse(ChannelProposalResult::Rejected(ref _rej)) => {
                write!(f, "Channel Proposal REJECTED.")
            }
            GreaseResponse::Error(err) => write!(f, "Error: {}", err),
            GreaseResponse::MsKeyExchange(_) => write!(f, "MultisigKeyExchange(***)"),
            GreaseResponse::ConfirmMsAddress(env) => {
                let status = if env.payload { "OK" } else { "NOT OK" };
                write!(f, "Multisig address confirmation: {status}")
            }
            GreaseResponse::NoResponse => write!(f, "No response to send"),
            GreaseResponse::MsSplitSecretExchange(_) => write!(f, "MsSplitSecretExchange"),
            GreaseResponse::ExchangeProof0(_) => write!(f, "ExchangeProof0"),
            GreaseResponse::ChannelClose(_) => write!(f, "ChannelClose"),
            GreaseResponse::UpdatePrepared(_) => write!(f, "UpdatePrepared"),
            GreaseResponse::UpdateCommitted(_) => write!(f, "UpdateCommitted"),
            GreaseResponse::ChannelClosed(_) => write!(f, "ChannelClosed"),
        }
    }
}

impl GreaseRequest {
    pub fn channel_id(&self) -> ChannelId {
        match self {
            GreaseRequest::ProposeChannelRequest(ref proposal) => proposal.channel_id(),
            GreaseRequest::MsKeyExchange(env) => env.channel_id().clone(),
            GreaseRequest::ConfirmMsAddress(env) => env.channel_id().clone(),
            GreaseRequest::MsSplitSecretExchange(env) => env.channel_id().clone(),
            GreaseRequest::ExchangeProof0(env) => env.channel_id().clone(),
            GreaseRequest::ChannelClose(env) => env.channel_id().clone(),
            GreaseRequest::PrepareUpdate(env) => env.channel_id().clone(),
            GreaseRequest::CommitUpdate(env) => env.channel_id().clone(),
            GreaseRequest::ChannelClosed(env) => env.channel_id().clone(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FundingTxStartResponse;

#[derive(Debug, Serialize, Deserialize)]
pub struct FundingTxFinalizeResponse;

#[derive(Debug, Serialize, Deserialize)]
pub struct AckFundingTxBroadcast;

/// Message sent from customer to merchant to propose a new channel.
///
/// It is almost equivalent to `NewChannelProposal`, but also includes the contact info for both parties so that libp2p
/// connections can be established.
///
/// You can retrieve the equivalent `NewChannelProposal` via the `as_proposal` method.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NewChannelMessage {
    /// The Monero network this channel will operate on.
    #[serde(
        deserialize_with = "libgrease::monero::helpers::deserialize_network",
        serialize_with = "libgrease::monero::helpers::serialize_network"
    )]
    pub network: Network,
    /// Contains the information needed to uniquely identify the channel.
    pub id: ChannelIdMetadata,
    /// The seed info that the (usually) merchant provided initially.
    pub seed: MerchantSeedInfo,
    /// The libp2p contact info for the customer.
    pub contact_info_customer: ContactInfo,
    /// The libp2p contact info for the merchant.
    pub contact_info_merchant: ContactInfo,
}

impl NewChannelMessage {
    pub fn new(
        network: Network,
        id: ChannelIdMetadata,
        seed: MerchantSeedInfo,
        my_contact_info: ContactInfo,
        their_contact_info: ContactInfo,
    ) -> Self {
        Self { network, id, seed, contact_info_customer: my_contact_info, contact_info_merchant: their_contact_info }
    }

    pub fn channel_id(&self) -> ChannelId {
        self.id.name()
    }

    pub fn as_proposal(&self) -> NewChannelProposal {
        use ciphersuite::group::Group;
        use ciphersuite::Ed25519;
        NewChannelProposal {
            channel_id: self.id.clone(),
            // TODO: Store the customer's channel key in NewChannelMessage and use it here
            customer_channel_key: <Ed25519 as ciphersuite::Ciphersuite>::G::generator(),
            seed: self.seed.clone(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
pub enum ChannelProposalResult {
    Accepted(NewChannelMessage),
    Rejected(RejectChannelProposal),
}

impl ChannelProposalResult {
    pub fn accept(proposal: NewChannelMessage) -> Self {
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
            LifeCycleError::StateMismatch(_) => unreachable!("State mismatch"),
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

/// Data packet sent from customer to merchant in first phase of update.
#[derive(Clone, Serialize, Deserialize)]
pub struct PrepareUpdate {
    pub update_count: u64,
    pub delta: MoneroDelta,
    pub prepare_info_customer: Vec<u8>,
}

impl Debug for PrepareUpdate {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "PrepareUpdate(update_count: {}, delta: {})",
            self.update_count, self.delta.amount
        )
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct UpdatePrepared {
    pub update_count: u64,
    pub delta: MoneroDelta,
    pub prepare_info_merchant: Vec<u8>,
    pub update_proof: PublicUpdateProof,
    pub adapted_sig: AdaptSig,
}

impl Debug for UpdatePrepared {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "UpdatePrepared(update_count: {}, delta: {})",
            self.update_count, self.delta.amount
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UpdateCommitted {
    pub public_update_proof: PublicUpdateProof,
    pub adapted_signature: AdaptSig,
}
