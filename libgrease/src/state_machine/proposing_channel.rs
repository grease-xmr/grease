use crate::channel_id::{ChannelId, ChannelIdMetadata};
use crate::channel_metadata::StaticChannelMetadata;
use crate::cryptography::dleq::Dleq;
use crate::cryptography::serializable_secret::SerializableSecret;
pub use crate::grease_protocol::MerchantSeedInfo;
use crate::monero::data_objects::ClosingAddresses;
use crate::payment_channel::{ChannelRole, HasRole};
use crate::state_machine::error::InvalidProposal;
use crate::state_machine::establishing_channel::EstablishingState;
use crate::state_machine::timeouts::TimeoutReason;
use crate::state_machine::{ChannelClosedReason, ClosedChannelState};
use ciphersuite::{Ciphersuite, Ed25519};
use grease_grumpkin::Grumpkin;
use log::*;
use modular_frost::curve::Curve as FrostCurve;
use monero::Address;
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;
use thiserror::Error;
use zeroize::Zeroizing;

// ====================== Message types ======================

/// The peer playing the role of Customer sends this proposal to the merchant to initiate a new channel.
///
/// The Customer must not modify the MerchantSeedInfo, or else the Merchant will reject the proposal.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct NewChannelProposal<KC: Ciphersuite = Ed25519> {
    /// The required metadata to calculate the channel id.
    pub channel_id: ChannelIdMetadata<KC>,
    /// The seed info that the merchant provided initially (echoed back for verification).
    pub seed: MerchantSeedInfo<KC>,
}

/// Merchant's response to a customer's channel proposal.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ProposalResponse {
    Accepted(ChannelId),
    Rejected(RejectProposalReason),
}

/// Customer's final confirmation after receiving acceptance from the merchant.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProposalConfirmed {
    pub channel_id: ChannelId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RejectProposalReason(String);

impl RejectProposalReason {
    pub fn new(reason: impl Into<String>) -> Self {
        RejectProposalReason(reason.into())
    }

    pub fn reason(&self) -> &str {
        &self.0
    }
}

// ====================== Customer-side states ======================

/// C1: Customer has received MerchantSeedInfo and prepares a proposal.
///
/// Created when the customer receives a MerchantSeedInfo, generates their own channel key,
/// and prepares a proposal to send to the merchant.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct ChannelProposer<SF = Grumpkin, KC = Ed25519>
where
    SF: FrostCurve,
    KC: Ciphersuite,
    Ed25519: Dleq<SF>,
{
    pub metadata: StaticChannelMetadata<KC>,
    pub seed_info: MerchantSeedInfo<KC>,
    /// The customer's secret nonce, $\hat{k}_a$, used to derive the shared channel secret $\kappa$.
    pub channel_secret: SerializableSecret<KC::F>,
    #[serde(skip)]
    _sf: PhantomData<SF>,
}

impl<SF, KC> HasRole for ChannelProposer<SF, KC>
where
    SF: FrostCurve,
    KC: Ciphersuite,
    Ed25519: Dleq<SF>,
{
    fn role(&self) -> ChannelRole {
        self.metadata.role()
    }
}

impl<SF, KC> ChannelProposer<SF, KC>
where
    SF: FrostCurve,
    KC: Ciphersuite,
    Ed25519: Dleq<SF>,
{
    /// Create a new `ChannelProposer` from the merchant's seed info and the customer's own parameters.
    ///
    /// The customer provides their channel secret, closing address, and nonce.
    /// The `ChannelIdMetadata` is constructed internally from the combined merchant + customer data.
    pub fn new(
        seed: MerchantSeedInfo<KC>,
        channel_secret: Zeroizing<KC::F>,
        customer_closing_address: Address,
        customer_nonce: u64,
    ) -> Self {
        let closing_addresses =
            ClosingAddresses { merchant: seed.merchant_closing_address, customer: customer_closing_address };
        let customer_channel_key = seed.merchant_channel_key * &*channel_secret;
        let channel_id = ChannelIdMetadata::new(
            seed.merchant_channel_key,
            customer_channel_key,
            seed.initial_balances,
            closing_addresses,
            seed.kes_config.clone(),
            seed.merchant_nonce,
            customer_nonce,
        );
        let metadata =
            StaticChannelMetadata::new(seed.network, ChannelRole::Customer, channel_id, seed.kes_type.clone());
        ChannelProposer { metadata, seed_info: seed, channel_secret: channel_secret.into(), _sf: PhantomData }
    }

    /// Generate a NewChannelProposal payload to send to the merchant.
    pub fn into_proposal(self) -> (AwaitingProposalResponse<SF, KC>, NewChannelProposal<KC>) {
        let proposal =
            NewChannelProposal { channel_id: self.metadata.channel_id().clone(), seed: self.seed_info.clone() };
        let awaiting_response = AwaitingProposalResponse {
            metadata: self.metadata,
            seed_info: self.seed_info,
            channel_secret: self.channel_secret,
            _sf: PhantomData,
        };
        (awaiting_response, proposal)
    }

    pub fn validate_seed_info(&self) -> Result<(), ProposeProtocolError> {
        // TODO - check that the KES and initial balances are acceptable
        // If this fails, we should abandon the channel creation
        Ok(())
    }
}

/// C2: Customer is waiting for the merchant's response to their proposal.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct AwaitingProposalResponse<SF = Grumpkin, KC = Ed25519>
where
    SF: FrostCurve,
    KC: Ciphersuite,
    Ed25519: Dleq<SF>,
{
    pub metadata: StaticChannelMetadata<KC>,
    pub seed_info: MerchantSeedInfo<KC>,
    /// The customer's secret nonce, $\hat{k}_a$, used to derive the shared channel secret $\kappa$.
    pub channel_secret: SerializableSecret<KC::F>,
    #[serde(skip)]
    _sf: PhantomData<SF>,
}

impl<SF, KC> AwaitingProposalResponse<SF, KC>
where
    SF: FrostCurve,
    KC: FrostCurve,
    Ed25519: Dleq<SF> + Dleq<KC>,
{
    /// Close the channel due to a lack of response from the peer.
    pub fn timeout(self, reason: TimeoutReason) -> ClosedChannelState<SF, KC> {
        let msg = format!("Awaiting proposal response has timed out: {}", reason.reason());
        info!("{msg}. The channel will be closed");
        let final_balances = self.metadata.initial_balance();
        ClosedChannelState::new(ChannelClosedReason::Timeout(reason), self.metadata, final_balances)
    }

    /// Handle the merchant's response to our proposal (C2).
    ///
    /// On `Accepted`: verify the echoed proposal matches what we sent, then transition to Establishing.
    /// On `Rejected`: transition to Closed.
    #[allow(clippy::result_large_err)]
    pub fn handle_response(
        self,
        response: ProposalResponse,
    ) -> Result<(EstablishingState<SF, KC>, ProposalConfirmed), ClosedChannelState<SF, KC>> {
        match response {
            ProposalResponse::Accepted(id) => {
                if self.metadata.channel_id().name() != id {
                    let final_balances = self.metadata.initial_balance();
                    return Err(ClosedChannelState::new(
                        ChannelClosedReason::Rejected(RejectProposalReason::new("Channel ID mismatch in acceptance")),
                        self.metadata,
                        final_balances,
                    ));
                }
                info!("Proposal accepted by merchant, transitioning to Establishing");
                let establishing: EstablishingState<SF, KC> = self.into();
                Ok((establishing, ProposalConfirmed { channel_id: id }))
            }
            ProposalResponse::Rejected(reason) => {
                info!("Proposal rejected by merchant: {}", reason.reason());
                // todo: depending on the reason, we might want to allow the customer to modify their proposal and try again instead of closing immediately
                let final_balances = self.metadata.initial_balance();
                Err(ClosedChannelState::new(
                    ChannelClosedReason::Rejected(reason),
                    self.metadata,
                    final_balances,
                ))
            }
        }
    }
}

// ====================== Merchant-side states ======================

/// M1: Merchant has shared seed info and is waiting for a customer to submit a proposal.
///
/// This state is standalone and NOT part of `ChannelState`, because no channel exists yet.
pub struct AwaitProposal<SF = Grumpkin, KC = Ed25519>
where
    SF: FrostCurve,
    KC: Ciphersuite,
    Ed25519: Dleq<SF>,
{
    initial_seed_info: MerchantSeedInfo<KC>,
    /// The merchant's secret nonce, $\hat{k}_a$, used to derive the shared channel secret $\kappa$.
    channel_secret: Zeroizing<KC::F>,
    _sf: PhantomData<SF>,
}

impl<SF, KC> AwaitProposal<SF, KC>
where
    SF: FrostCurve,
    KC: Ciphersuite,
    Ed25519: Dleq<SF>,
{
    pub fn new(initial_seed_info: MerchantSeedInfo<KC>, channel_secret: Zeroizing<KC::F>) -> Self {
        Self { initial_seed_info, channel_secret, _sf: PhantomData }
    }

    /// Verify and accept an incoming proposal from a customer (M2).
    ///
    /// Validates the proposal against the initial seed info and, if valid,
    /// transitions to `AwaitingConfirmation`. Consumes the `ReceiveProposal` state.
    pub fn receive_proposal(
        self,
        proposal: NewChannelProposal<KC>,
    ) -> Result<(AwaitingConfirmation<SF, KC>, ProposalResponse), InvalidProposal> {
        self.verify_seed_info(&proposal.seed)?;
        self.review_proposal(&proposal)?;
        let metadata = StaticChannelMetadata::new(
            self.initial_seed_info.network,
            ChannelRole::Merchant,
            proposal.channel_id,
            self.initial_seed_info.kes_type.clone(),
        );
        info!("Merchant Received Proposal: Proposal validated, transitioning to AwaitingConfirmation");
        let channel_id = metadata.channel_id().name();
        let response = ProposalResponse::Accepted(channel_id);
        let awaiting = AwaitingConfirmation {
            metadata,
            seed_info: self.initial_seed_info,
            channel_secret: self.channel_secret.into(),
            _sf: PhantomData,
        };
        Ok((awaiting, response))
    }

    fn verify_seed_info(&self, seed: &MerchantSeedInfo<KC>) -> Result<(), InvalidProposal> {
        if self.initial_seed_info != *seed {
            Err(InvalidProposal::SeedMismatch)
        } else {
            Ok(())
        }
    }

    /// A sanity check to make sure that information coming from the customer in the proposal
    /// matches what was shared initially.
    fn review_proposal(&self, proposal: &NewChannelProposal<KC>) -> Result<(), InvalidProposal> {
        debug!("Internal sanity check on proposal info");
        if self.initial_seed_info.initial_balances.total().is_zero() {
            return Err(InvalidProposal::ZeroTotalValue);
        }
        if self.initial_seed_info.initial_balances != proposal.channel_id.initial_balance() {
            return Err(InvalidProposal::MismatchedBalances);
        }
        if &self.initial_seed_info.merchant_channel_key != proposal.channel_id.merchant_key() {
            return Err(InvalidProposal::MismatchedMerchantPublicKey);
        }
        if &self.initial_seed_info.kes_config != proposal.channel_id.kes_config() {
            return Err(InvalidProposal::MismatchedKesConfig);
        }
        if &self.initial_seed_info.merchant_closing_address != proposal.channel_id.closing_addresses().merchant() {
            return Err(InvalidProposal::MismatchedAddress);
        }
        if self.initial_seed_info.merchant_nonce != proposal.channel_id.merchant_nonce() {
            return Err(InvalidProposal::MismatchedNonce);
        }
        Ok(())
    }
}

/// M2: Merchant has accepted the proposal and is waiting for the customer's confirmation.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct AwaitingConfirmation<SF = Grumpkin, KC = Ed25519>
where
    SF: FrostCurve,
    KC: Ciphersuite,
    Ed25519: Dleq<SF>,
{
    pub metadata: StaticChannelMetadata<KC>,
    pub seed_info: MerchantSeedInfo<KC>,
    /// The merchant's secret nonce, $\hat{k}_a$, used to derive the shared channel secret $\kappa$.
    pub channel_secret: SerializableSecret<KC::F>,
    #[serde(skip)]
    _sf: PhantomData<SF>,
}

impl<SF, KC> AwaitingConfirmation<SF, KC>
where
    SF: FrostCurve,
    KC: FrostCurve,
    Ed25519: Dleq<SF> + Dleq<KC>,
{
    /// Close the channel because the customer rejected the proposal or timed out.
    pub fn timeout(self, reason: TimeoutReason) -> ClosedChannelState<SF, KC> {
        let msg = format!("Awaiting confirmation has timed out: {}", reason.reason());
        info!("{msg}. The channel will be closed");
        let final_balances = self.metadata.initial_balance();
        ClosedChannelState::new(ChannelClosedReason::Timeout(reason), self.metadata, final_balances)
    }

    pub fn reject(self, reason: RejectProposalReason) -> ClosedChannelState<SF, KC> {
        let msg = format!("Channel proposal was rejected by customer: {}", reason.reason());
        info!("{msg}. The channel will be closed");
        let final_balances = self.metadata.initial_balance();
        ClosedChannelState::new(ChannelClosedReason::Rejected(reason), self.metadata, final_balances)
    }

    /// Handle the customer's final confirmation (M3).
    ///
    /// Verifies the channel ID matches and transitions to Establishing.
    /// If the channel ID doesn't match, transitions to Closed.
    #[allow(clippy::result_large_err)]
    pub fn handle_confirmation(
        self,
        confirmed: ProposalConfirmed,
    ) -> Result<EstablishingState<SF, KC>, ClosedChannelState<SF, KC>> {
        if self.metadata.channel_id().name() != confirmed.channel_id {
            let final_balances = self.metadata.initial_balance();
            return Err(ClosedChannelState::new(
                ChannelClosedReason::Rejected(RejectProposalReason::new("Channel ID mismatch in confirmation")),
                self.metadata,
                final_balances,
            ));
        }
        info!("Customer confirmed proposal, transitioning to Establishing");
        let establishing: EstablishingState<SF, KC> = self.into();
        Ok(establishing)
    }
}

// ====================== Error types ======================

/// Errors that can occur during the channel proposal protocol.
#[derive(Debug, Error)]
pub enum ProposeProtocolError {
    #[error("Missing required information: {0}")]
    MissingInformation(String),

    #[error("Invalid seed info: {0}")]
    InvalidSeedInfo(String),

    #[error("Invalid proposal: {0}")]
    InvalidProposal(String),

    #[error("Channel ID mismatch: expected {expected}, got {actual}")]
    ChannelIdMismatch { expected: String, actual: String },

    #[error("Proposal already received")]
    ProposalAlreadyReceived,

    #[error("No proposal received to accept or reject")]
    NoProposalReceived,

    #[error("Seed info not received")]
    SeedInfoNotReceived,

    #[error("Proposal was rejected: {0}")]
    ProposalRejected(String),

    #[error("Network mismatch: expected {expected}, got {actual}")]
    NetworkMismatch { expected: String, actual: String },

    #[error("Balance validation failed: {0}")]
    BalanceValidationFailed(String),
}
