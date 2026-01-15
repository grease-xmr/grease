//! Channel Proposal Protocol Traits
//!
//! This module defines traits for the channel proposal phase, where a merchant (proposer)
//! creates channel seed information and a customer (proposee) submits a channel proposal.

use crate::channel_id::ChannelIdMetadata;
use crate::payment_channel::HasRole;
use crate::state_machine::{ChannelSeedInfo, NewChannelProposal, RejectNewChannelReason};
use monero::Address;
use rand_core::{CryptoRng, RngCore};
use thiserror::Error;

/// Configuration for creating channel seed information.
#[derive(Debug, Clone)]
pub struct ChannelSeedConfig {
    /// The KES public key identifier
    pub kes_public_key: String,
    /// The merchant's closing address
    pub closing_address: Address,
}

/// Common functionality shared by both proposer and proposee.
pub trait ProposeProtocolCommon: HasRole {
    /// Returns the channel ID if available.
    fn channel_id(&self) -> Option<&ChannelIdMetadata>;

    /// Returns the seed info if available.
    fn seed_info(&self) -> Option<&ChannelSeedInfo>;

    /// Validates the seed info against protocol requirements.
    fn validate_seed_info(&self) -> Result<(), ProposeProtocolError>;
}

/// Protocol trait for the proposer (typically the merchant).
///
/// The proposer - usually a merchant, creates the channel seed information, receives proposals from customers,
/// and can accept or reject them.
pub trait ProposeProtocolProposer: ProposeProtocolCommon {
    /// Create channel seed information for a new channel.
    ///
    /// The seed info contains the merchant's public key, KES info, proposed balances,
    /// and the merchant's nonce for channel ID derivation.
    fn create_channel_seed<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        config: ChannelSeedConfig,
    ) -> Result<ChannelSeedInfo, ProposeProtocolError>;

    /// Receive and validate a proposal from a customer.
    ///
    /// This validates that the proposal is consistent with the seed info
    /// and meets protocol requirements.
    fn receive_proposal(&mut self, proposal: &NewChannelProposal) -> Result<(), ProposeProtocolError>;

    /// Accept the received proposal and prepare for channel establishment.
    ///
    /// Returns the accepted proposal for transmission to the customer.
    fn accept_proposal(&self) -> Result<NewChannelProposal, ProposeProtocolError>;

    /// Reject the received proposal with a reason.
    fn reject_proposal(&self, reason: RejectNewChannelReason) -> Result<(), ProposeProtocolError>;
}

/// Protocol trait for the proposee (typically the customer).
///
/// The proposee receives seed information from a merchant, creates a proposal,
/// and handles the merchant's response.
pub trait ProposeProtocolProposee: ProposeProtocolCommon {
    /// Receive and store seed information from the merchant.
    ///
    /// This validates the seed info and extracts the channel parameters.
    fn receive_seed_info(&mut self, seed: ChannelSeedInfo) -> Result<(), ProposeProtocolError>;

    /// Create a channel proposal based on the received seed info.
    ///
    /// The proposal includes the customer's public key, closing address,
    /// and nonce for channel ID derivation.
    fn create_proposal<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        closing_address: &Address,
    ) -> Result<NewChannelProposal, ProposeProtocolError>;

    /// Handle acceptance of the proposal by the merchant.
    ///
    /// Validates that the accepted proposal matches what was sent.
    fn handle_acceptance(&mut self, accepted: &NewChannelProposal) -> Result<(), ProposeProtocolError>;

    /// Handle rejection of the proposal by the merchant.
    fn handle_rejection(&mut self, reason: RejectNewChannelReason) -> Result<(), ProposeProtocolError>;
}

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
