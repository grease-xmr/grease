use crate::arbiter::ArbiterConfiguration;
use crate::channel_id::{ChannelId, ChannelIdMetadata};
use crate::channel_metadata::StaticChannelMetadata;
use crate::cryptography::keys::Curve25519Secret;
use crate::cryptography::serializable_secret::SerializableSecret;
pub use crate::grease_protocol::MerchantSeedInfo;
use crate::monero::data_objects::ClosingAddresses;
use crate::monero::error::ClosingAddressError;
use crate::payment_channel::{ChannelRole, HasRole};
use crate::state_machine::error::InvalidProposal;
use crate::state_machine::establishing_channel::EstablishingState;
use crate::state_machine::timeouts::TimeoutReason;
use crate::state_machine::{ChannelClosedReason, ClosedChannelState};
use crate::Ed25519;
use ciphersuite::Ciphersuite;
use log::*;
use monero::Address;
use serde::{Deserialize, Serialize};
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
pub struct ChannelProposer<KC = Ed25519>
where
    KC: Ciphersuite,
{
    pub metadata: StaticChannelMetadata<KC>,
    pub seed_info: MerchantSeedInfo<KC>,
    /// The customer's channel secret, $\hat{k}_a$. Its public key is #Pc in the channel-id transcript.
    channel_secret: SerializableSecret<KC::F>,
    /// The partial wallet spend key for this (to-be-created) channel
    pub(crate) partial_spend_key: Curve25519Secret,
}

impl<KC> HasRole for ChannelProposer<KC>
where
    KC: Ciphersuite,
{
    fn role(&self) -> ChannelRole {
        self.metadata.role()
    }
}

impl<KC> ChannelProposer<KC>
where
    KC: Ciphersuite,
{
    /// Create a new `ChannelProposer` from the merchant's seed info and the customer's own parameters.
    ///
    /// The customer provides their channel secret, closing address, nonce, and the arbiter they pick from the
    /// ones the seed offers. The `ChannelIdMetadata` is constructed internally from the combined merchant +
    /// customer data.
    ///
    /// # `partial_spend_key` must be fresh for every channel
    ///
    /// Channel-id separation no longer rests on this: each funding linking tag is `L_j = (d_j + x)·H_p(K_j)`
    /// over its own output's one-time key, and every funding transaction carries its own `R_j`, so two channels
    /// get different tags even when they share a spend key ([`crate::cryptography::linking_tag`]).
    ///
    /// The requirement stands on wallet grounds instead. Two channels built from the same pair of
    /// `partial_spend_key`s share one joint spend key `P`, hence one shared address: their deposits land in the
    /// same wallet, are scanned together, and cannot be told apart by their owners; and a spend key that leaks
    /// compromises every channel derived from it rather than one. Draw a fresh key per channel.
    ///
    /// # `customer_nonce` must be fresh for every channel
    ///
    /// The nonce is the customer's second, independent line of defence: drawn uniformly at random, it
    /// guarantees on its own that no two of the customer's channels share an id, even if a spend key were
    /// ever repeated. The merchant's nonce arrives with the seed and is shared by every proposal made from
    /// it, and every other customer-side field may legitimately repeat (a static closing address, a repeated
    /// channel key), so from one seed the customer's nonce is the only field *guaranteed* to separate two
    /// channels' provisional ids. A customer that reuses it bears the collision risk itself. See
    /// [`crate::channel_id::ChannelIdMetadata`], *Nonce freshness is mandatory*.
    pub fn new(
        seed: MerchantSeedInfo<KC>,
        arbiter: ArbiterConfiguration,
        channel_secret: Zeroizing<KC::F>,
        partial_spend_key: Curve25519Secret,
        customer_closing_address: Address,
        customer_nonce: u64,
    ) -> Result<Self, ProposeProtocolError> {
        if !seed.accepts_arbiter(&arbiter) {
            return Err(ProposeProtocolError::ArbiterNotAccepted(arbiter.canister_id().to_string()));
        }
        let closing_addresses =
            ClosingAddresses::new_from_addresses(customer_closing_address, seed.merchant_closing_address)?;
        let customer_public_key = KC::generator() * *channel_secret;
        let channel_id = ChannelIdMetadata::new(
            seed.merchant_public_key,
            customer_public_key,
            seed.initial_balances,
            closing_addresses,
            arbiter,
            seed.merchant_nonce,
            customer_nonce,
        );
        let metadata = StaticChannelMetadata::new(seed.network, ChannelRole::Customer, channel_id);
        Ok(ChannelProposer {
            metadata,
            seed_info: seed,
            partial_spend_key,
            channel_secret: channel_secret.into(),
        })
    }

    /// Generate a NewChannelProposal payload to send to the merchant.
    pub fn into_proposal(self) -> (AwaitingProposalResponse<KC>, NewChannelProposal<KC>) {
        let proposal =
            NewChannelProposal { channel_id: self.metadata.channel_id().clone(), seed: self.seed_info.clone() };
        let awaiting_response = AwaitingProposalResponse {
            metadata: self.metadata,
            seed_info: self.seed_info,
            channel_secret: self.channel_secret,
            partial_spend_key: self.partial_spend_key,
        };
        (awaiting_response, proposal)
    }
}

/// C2: Customer is waiting for the merchant's response to their proposal.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct AwaitingProposalResponse<KC = Ed25519>
where
    KC: Ciphersuite,
{
    pub metadata: StaticChannelMetadata<KC>,
    pub seed_info: MerchantSeedInfo<KC>,
    /// The customer's channel secret, $\hat{k}_a$. Its public key is #Pc in the channel-id transcript.
    pub(crate) channel_secret: SerializableSecret<KC::F>,
    /// The partial wallet spend key for this (to-be-created) channel
    pub(crate) partial_spend_key: Curve25519Secret,
}

impl<KC> AwaitingProposalResponse<KC>
where
    KC: Ciphersuite,
{
    /// Close the channel due to a lack of response from the peer.
    pub fn timeout(self, reason: TimeoutReason) -> ClosedChannelState<KC> {
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
    ) -> Result<(EstablishingState<KC>, ProposalConfirmed), ClosedChannelState<KC>> {
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
                let closing_balance = self.metadata.initial_balance();
                let metadata_backup = self.metadata.clone();
                let establishing: EstablishingState<KC> = EstablishingState::try_from(self).map_err(|e| {
                    ClosedChannelState::new(
                        ChannelClosedReason::Rejected(RejectProposalReason::new(e.to_string())),
                        metadata_backup,
                        closing_balance,
                    )
                })?;
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
pub struct AwaitProposal<KC = Ed25519>
where
    KC: Ciphersuite,
{
    initial_seed_info: MerchantSeedInfo<KC>,
    /// The merchant's channel secret, $\hat{k}_b$, whose public key #Pm the seed advertises.
    channel_secret: Zeroizing<KC::F>,
    /// The partial wallet spend key for this (to-be-created) channel. Must be fresh per channel — see
    /// [`AwaitProposal::new`].
    partial_spend_key: Curve25519Secret,
}

impl<KC> AwaitProposal<KC>
where
    KC: Ciphersuite,
{
    /// `partial_spend_key` must be freshly generated for every channel, and in particular must not be derived
    /// from the seed — the seed is reused across proposals by design. See
    /// [`ChannelProposer::new`](super::ChannelProposer::new) for what a repeated spend key costs.
    pub fn new(
        initial_seed_info: MerchantSeedInfo<KC>,
        channel_secret: Zeroizing<KC::F>,
        partial_spend_key: Curve25519Secret,
    ) -> Self {
        Self { initial_seed_info, channel_secret, partial_spend_key }
    }

    /// Verify and accept an incoming proposal from a customer (M2).
    ///
    /// Validates the proposal against the initial seed info and, if valid,
    /// transitions to `AwaitingConfirmation`. Consumes the `ReceiveProposal` state.
    pub fn receive_proposal(
        self,
        proposal: NewChannelProposal<KC>,
    ) -> Result<(AwaitingConfirmation<KC>, ProposalResponse), InvalidProposal> {
        self.verify_seed_info(&proposal.seed)?;
        self.review_proposal(&proposal)?;
        let metadata =
            StaticChannelMetadata::new(self.initial_seed_info.network, ChannelRole::Merchant, proposal.channel_id);
        info!("Merchant Received Proposal: Proposal validated, transitioning to AwaitingConfirmation");
        let channel_id = metadata.channel_id().name();
        let response = ProposalResponse::Accepted(channel_id);
        let awaiting = AwaitingConfirmation {
            metadata,
            seed_info: self.initial_seed_info,
            channel_secret: self.channel_secret.into(),
            partial_spend_key: self.partial_spend_key,
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
        if &self.initial_seed_info.merchant_public_key != proposal.channel_id.merchant_key() {
            return Err(InvalidProposal::MismatchedMerchantPublicKey);
        }
        if !self.initial_seed_info.accepts_arbiter(proposal.channel_id.arbiter_config()) {
            return Err(InvalidProposal::MismatchedArbiterConfig);
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
pub struct AwaitingConfirmation<KC = Ed25519>
where
    KC: Ciphersuite,
{
    pub metadata: StaticChannelMetadata<KC>,
    pub seed_info: MerchantSeedInfo<KC>,
    /// The merchant's channel secret, $\hat{k}_b$, whose public key #Pm the seed advertises.
    pub(crate) channel_secret: SerializableSecret<KC::F>,
    /// The partial wallet spend key for this (to-be-created) channel
    pub(crate) partial_spend_key: Curve25519Secret,
}

impl<KC> AwaitingConfirmation<KC>
where
    KC: Ciphersuite,
{
    /// Close the channel because the customer rejected the proposal or timed out.
    pub fn timeout(self, reason: TimeoutReason) -> ClosedChannelState<KC> {
        let msg = format!("Awaiting confirmation has timed out: {}", reason.reason());
        info!("{msg}. The channel will be closed");
        let final_balances = self.metadata.initial_balance();
        ClosedChannelState::new(ChannelClosedReason::Timeout(reason), self.metadata, final_balances)
    }

    pub fn reject(self, reason: RejectProposalReason) -> ClosedChannelState<KC> {
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
    ) -> Result<EstablishingState<KC>, ClosedChannelState<KC>> {
        if self.metadata.channel_id().name() != confirmed.channel_id {
            let final_balances = self.metadata.initial_balance();
            return Err(ClosedChannelState::new(
                ChannelClosedReason::Rejected(RejectProposalReason::new("Channel ID mismatch in confirmation")),
                self.metadata,
                final_balances,
            ));
        }
        info!("Customer confirmed proposal, transitioning to Establishing");
        let closing_balance = self.metadata.initial_balance();
        let metadata_backup = self.metadata.clone();
        let establishing: EstablishingState<KC> = EstablishingState::try_from(self).map_err(|e| {
            ClosedChannelState::new(
                ChannelClosedReason::Rejected(RejectProposalReason::new(e.to_string())),
                metadata_backup,
                closing_balance,
            )
        })?;
        Ok(establishing)
    }
}

// ====================== Error types ======================

/// Errors that can occur during the channel proposal protocol.
#[derive(Debug, Error)]
pub enum ProposeProtocolError {
    #[error("Missing required information: {0}")]
    MissingInformation(String),

    #[error("Invalid closing address in proposal: {0}")]
    ClosingAddressError(#[from] ClosingAddressError),

    #[error("The merchant's seed does not offer the arbiter {0}")]
    ArbiterNotAccepted(String),

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
