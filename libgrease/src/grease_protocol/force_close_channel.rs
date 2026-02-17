//! Channel Force Close Protocol Traits (Dispute Resolution)
//!
//! This module defines traits for unilateral channel closing via the KES,
//! including dispute mechanisms when parties disagree on the channel state.

use crate::channel_id::ChannelId;
use crate::cryptography::adapter_signature::SchnorrSignature;
use crate::cryptography::keys::Curve25519PublicKey;
use crate::cryptography::CrossCurveScalar;
use crate::helpers::Timestamp;
use crate::monero::data_objects::TransactionId;
use crate::payment_channel::HasRole;
use crate::XmrScalar;
use ciphersuite::Ciphersuite;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use thiserror::Error;

/// Request to initiate a force close via the KES.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForceCloseRequest<K: Ciphersuite> {
    /// The channel being force closed
    pub channel_id: ChannelId,
    /// Public key of the claimant
    pub claimant: Curve25519PublicKey,
    /// Public key of the defendant
    pub defendant: Curve25519PublicKey,
    /// The update count claimed by the claimant
    pub update_count_claimed: u64,
    /// Signature over the request
    pub signature: SchnorrSignature<K>,
}

/// Response to a force close request from the KES.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ForceCloseResponse {
    /// The force close request was accepted
    Accepted { dispute_window_end: Timestamp },
    /// The force close request was rejected
    Rejected { reason: String },
}

/// Request to claim channel funds after the dispute window closes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimChannelRequest<K: Ciphersuite> {
    /// The channel being claimed
    pub channel_id: ChannelId,
    /// Public key of the claimant
    pub claimant: Curve25519PublicKey,
    /// Signature over the request
    pub signature: SchnorrSignature<K>,
}

/// Request for consensus close (defendant agrees with claimed state).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusCloseRequest<SF: Ciphersuite, K: Ciphersuite> {
    /// The channel being closed
    pub channel_id: ChannelId,
    /// Public key of the claimant
    pub claimant: Curve25519PublicKey,
    /// Public key of the defendant
    pub defendant: Curve25519PublicKey,
    /// The update count (agreed upon)
    pub update_count_claimed: u64,
    /// Encrypted offset from the defendant (SNARK-friendly curve)
    pub encrypted_offset: CrossCurveScalar<SF>,
    /// Defendant's signature (signing curve)
    pub signature: SchnorrSignature<K>,
}

/// Dispute when the defendant has a more recent state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisputeChannelState {
    /// The channel being disputed
    pub channel_id: ChannelId,
    /// Public key of the claimant
    pub claimant: Curve25519PublicKey,
    /// Public key of the defendant
    pub defendant: Curve25519PublicKey,
    /// The defendant's update count (should be > claimant's)
    pub update_count: u64,
    /// Serialized update record proving the state
    #[serde(serialize_with = "crate::helpers::to_hex", deserialize_with = "crate::helpers::from_hex")]
    pub update_record: Vec<u8>,
    /// Defendant's signature
    #[serde(serialize_with = "crate::helpers::to_hex", deserialize_with = "crate::helpers::from_hex")]
    pub signature: Vec<u8>,
}

/// Resolution of a dispute.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DisputeResolution<SF: Ciphersuite> {
    /// The claimant won (defendant didn't respond or dispute failed)
    ClaimantWins { encrypted_offset: CrossCurveScalar<SF> },
    /// The defendant won (proved more recent state)
    DefendantWins { penalty_applied: bool },
}

/// Notification to the defendant of a pending close.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingChannelClose {
    /// The channel with a pending close
    pub channel_id: ChannelId,
    /// The claimant's public key
    pub claimant: Curve25519PublicKey,
    /// The update count claimed
    pub update_count_claimed: u64,
    /// When the dispute window ends (unix timestamp)
    pub dispute_window_end: Timestamp,
}

/// Status of a pending close operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PendingCloseStatus {
    /// Force close initiated, waiting for dispute window
    Pending,
    /// Dispute window passed, claimant can claim
    Claimable,
    /// Force close was abandoned
    Abandoned,
    /// Closed via consensus (defendant agreed)
    ConsensusClosed,
    /// Force closed after dispute window
    ForceClosed,
    /// Abandoned and claimed by defendant
    AbandonedClaimed,
    /// Dispute was successful (defendant proved newer state)
    DisputeSuccessful,
}

/// Common functionality shared by both claimant and defendant.
pub trait ForceCloseProtocolCommon<K: Ciphersuite>: HasRole {
    /// Returns the channel ID.
    fn channel_id(&self) -> ChannelId;

    /// Returns own public key.
    fn public_key(&self) -> &Curve25519PublicKey;

    /// Returns the peer's public key.
    fn peer_public_key(&self) -> &Curve25519PublicKey;

    /// Returns the dispute window duration.
    fn dispute_window(&self) -> Duration;

    /// Returns the current update count.
    fn update_count(&self) -> u64;

    /// Sign a message for KES interaction.
    fn sign_for_kes(&self, message: &[u8]) -> Result<SchnorrSignature<K>, ForceCloseProtocolError>;

    /// Verify a signature from the peer.
    fn verify_peer_signature(&self, message: &[u8], sig: &SchnorrSignature<K>) -> Result<(), ForceCloseProtocolError>;
}

/// Protocol trait for the force close claimant.
///
/// The claimant initiates a force close when they cannot get a cooperative
/// close from their peer.
pub trait ForceCloseProtocolClaimant<SF, K>: ForceCloseProtocolCommon<K>
where
    SF: Ciphersuite,
    K: Ciphersuite,
{
    /// Create a force close request to send to the KES.
    fn create_force_close_request(&self) -> Result<ForceCloseRequest<K>, ForceCloseProtocolError>;

    /// Handle the response from the KES to the force close request.
    fn handle_force_close_response(&mut self, response: ForceCloseResponse) -> Result<(), ForceCloseProtocolError>;

    /// Create a claim request after the dispute window has passed.
    fn create_claim_request(&self) -> Result<ClaimChannelRequest<K>, ForceCloseProtocolError>;

    /// Process the encrypted offset received from the KES.
    ///
    /// Returns the decrypted offset needed to complete the closing transaction.
    fn process_claimed_offset(&mut self, encrypted: &[u8]) -> Result<CrossCurveScalar<SF>, ForceCloseProtocolError>;

    /// Complete the closing transaction with the peer's offset.
    fn complete_closing_tx(&self, peer_offset: &XmrScalar) -> Result<Vec<u8>, ForceCloseProtocolError>;

    /// Broadcast the closing transaction.
    fn broadcast_closing_tx(&self, tx: &[u8]) -> Result<TransactionId, ForceCloseProtocolError>;
}

/// Protocol trait for the force close defendant.
///
/// The defendant receives notification of a force close and can either
/// agree (consensus close) or dispute with a more recent state.
pub trait ForceCloseProtocolDefendant<SF, K>: ForceCloseProtocolCommon<K>
where
    SF: Ciphersuite,
    K: Ciphersuite,
{
    /// Receive notification of a pending force close.
    fn receive_force_close_notification(&mut self, notif: PendingChannelClose) -> Result<(), ForceCloseProtocolError>;

    /// Check if we have a more recent state than claimed.
    fn has_more_recent_state(&self, claimed_count: u64) -> bool;

    /// Create a consensus close request (agree with the claimed state).
    fn create_consensus_close(&self) -> Result<ConsensusCloseRequest<SF, K>, ForceCloseProtocolError>;

    /// Create a dispute to prove a more recent state.
    fn create_dispute(&self) -> Result<DisputeChannelState, ForceCloseProtocolError>;

    /// Handle the resolution of a dispute.
    fn handle_dispute_resolution(&mut self, resolution: DisputeResolution<SF>) -> Result<(), ForceCloseProtocolError>;
}

/// Errors that can occur during the force close protocol.
#[derive(Debug, Error)]
pub enum ForceCloseProtocolError {
    #[error("Channel not found: {0}")]
    ChannelNotFound(String),

    #[error("Channel not in force-closeable state: {0}")]
    InvalidChannelState(String),

    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    #[error("Signature creation failed: {0}")]
    SignatureCreationFailed(String),

    #[error("Missing required information: {0}")]
    MissingInformation(String),

    #[error("Dispute window has not passed")]
    DisputeWindowActive,

    #[error("Dispute window has passed")]
    DisputeWindowExpired,

    #[error("No pending force close")]
    NoPendingForceClose,

    #[error("Force close already pending")]
    ForceCloseAlreadyPending,

    #[error("KES rejected request: {0}")]
    KesRejected(String),

    #[error("Failed to decrypt offset: {0}")]
    DecryptionFailed(String),

    #[error("Transaction creation failed: {0}")]
    TransactionCreationFailed(String),

    #[error("Transaction broadcast failed: {0}")]
    BroadcastFailed(String),

    #[error("Invalid update record: {0}")]
    InvalidUpdateRecord(String),

    #[error("Update count too low: claimed {claimed}, actual {actual}")]
    UpdateCountTooLow { claimed: u64, actual: u64 },

    #[error("Dispute failed: {0}")]
    DisputeFailed(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Network error: {0}")]
    NetworkError(String),
}
