use crate::errors::RemoteServerError;
use crate::ContactInfo;
use libgrease::amount::MoneroDelta;
use libgrease::channel_id::ChannelId;
use libgrease::cryptography::zk_objects::{PublicProof0, PublicUpdateProof};
use libgrease::monero::data_objects::{
    ClosingAddresses, FinalizedUpdate, MessageEnvelope, MultisigKeyInfo, MultisigSplitSecrets,
    MultisigSplitSecretsResponse, TransactionId,
};
use libgrease::payment_channel::ChannelRole;
use libgrease::state_machine::error::{InvalidProposal, LifeCycleError};
use libgrease::state_machine::{ChannelCloseRecord, ChannelSeedInfo, ProposedChannelInfo};
use log::*;
use monero::Address;
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Display, Formatter};
use wallet::multisig_wallet::AdaptSig;

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
    pub fn channel_name(&self) -> String {
        match self {
            GreaseRequest::ProposeChannelRequest(ref proposal) => proposal.channel_name(),
            GreaseRequest::MsKeyExchange(env) => env.channel_name(),
            GreaseRequest::ConfirmMsAddress(env) => env.channel_name(),
            GreaseRequest::MsSplitSecretExchange(env) => env.channel_name(),
            GreaseRequest::ExchangeProof0(env) => env.channel_name(),
            GreaseRequest::ChannelClose(env) => env.channel_name(),
            GreaseRequest::PrepareUpdate(env) => env.channel_name(),
            GreaseRequest::CommitUpdate(env) => env.channel_name(),
            GreaseRequest::ChannelClosed(env) => env.channel_name(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FundingTxStartResponse;

#[derive(Debug, Serialize, Deserialize)]
pub struct FundingTxFinalizeResponse;

#[derive(Debug, Serialize, Deserialize)]
pub struct AckFundingTxBroadcast;

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
    /// The address that the proposer will use to close the channel.
    pub closing_address: Address,
    /// The public key for channel ID derivation (from the proposer, usually customer)
    pub proposer_channel_key: libgrease::cryptography::keys::Curve25519PublicKey,
    /// The nonce for channel ID derivation (from the proposer, usually customer)
    pub proposer_channel_nonce: u64,
}

impl NewChannelProposal {
    pub fn new(
        seed: ChannelSeedInfo,
        my_label: impl Into<String>,
        my_contact_info: ContactInfo,
        my_closing_address: Address,
        their_contact_info: ContactInfo,
        my_channel_key: libgrease::cryptography::keys::Curve25519PublicKey,
        my_channel_nonce: u64,
    ) -> Self {
        Self {
            seed,
            contact_info_proposer: my_contact_info,
            contact_info_proposee: their_contact_info,
            proposer_label: my_label.into(),
            closing_address: my_closing_address,
            proposer_channel_key: my_channel_key,
            proposer_channel_nonce: my_channel_nonce,
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
        let (merchant_address, customer_address) = match self.seed.role {
            ChannelRole::Merchant => (self.closing_address, self.seed.closing_address),
            ChannelRole::Customer => (self.seed.closing_address, self.closing_address),
        };
        // Assign keys and nonces based on role
        let (merchant_key, customer_key, merchant_nonce, customer_nonce) = match self.seed.role {
            ChannelRole::Merchant => (
                self.proposer_channel_key,
                self.seed.channel_key,
                self.proposer_channel_nonce,
                self.seed.channel_nonce,
            ),
            ChannelRole::Customer => (
                self.seed.channel_key,
                self.proposer_channel_key,
                self.seed.channel_nonce,
                self.proposer_channel_nonce,
            ),
        };
        let closing_addresses = ClosingAddresses { merchant: merchant_address, customer: customer_address };
        let channel_id: ChannelId = ChannelId::new(
            merchant_key,
            customer_key,
            self.seed.initial_balances,
            closing_addresses,
            merchant_nonce,
            customer_nonce,
        );
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
