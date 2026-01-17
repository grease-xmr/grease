//! Channel Close Protocol Traits (Cooperative Close)
//!
//! Curve-agnostic behavior for a cooperative channel close, where both parties
//! agree to close the channel and exchange partial signature offsets to enable the broadcast of the commitment
//! transaction.

use crate::channel_id::ChannelId;
use crate::cryptography::ChannelWitness;
use crate::monero::data_objects::TransactionId;
use crate::payment_channel::HasRole;
use ciphersuite::Ciphersuite;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Request to close a channel cooperatively.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct RequestChannelClose<SF: Ciphersuite> {
    /// The channel being closed
    pub channel_id: ChannelId,
    /// The initiator's partial offset (ω)
    pub offset: ChannelWitness<SF>,
    /// The update count at close time
    pub update_count: u64,
}

/// Successful channel close response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct ChannelCloseSuccess<SF: Ciphersuite> {
    /// The channel being closed
    pub channel_id: ChannelId,
    /// The responder's partial offset (ω)
    pub offset: ChannelWitness<SF>,
    /// Transaction ID if the responder broadcast the closing transaction
    pub txid: Option<TransactionId>,
}

/// Failed channel close response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestCloseFailed {
    /// The channel that failed to close
    pub channel_id: ChannelId,
    /// The reason for the failure
    pub reason: CloseFailureReason,
}

/// Reasons a cooperative close can fail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CloseFailureReason {
    /// The update counts don't match
    UpdateCountMismatch { expected: u64, received: u64 },
    /// The channel is not in a closeable state
    InvalidChannelState(String),
    /// The provided offset is invalid
    InvalidOffset(String),
    /// The peer is unresponsive
    PeerUnresponsive,
    /// General protocol error
    ProtocolError(String),
}

impl std::fmt::Display for CloseFailureReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CloseFailureReason::UpdateCountMismatch { expected, received } => {
                write!(f, "Update count mismatch: expected {expected}, received {received}")
            }
            CloseFailureReason::InvalidChannelState(s) => write!(f, "Invalid channel state: {s}"),
            CloseFailureReason::InvalidOffset(s) => write!(f, "Invalid offset: {s}"),
            CloseFailureReason::PeerUnresponsive => write!(f, "Peer unresponsive"),
            CloseFailureReason::ProtocolError(s) => write!(f, "Protocol error: {s}"),
        }
    }
}

/// Common functionality shared by both close initiator and responder.
pub trait CloseProtocolCommon<SF: Ciphersuite>: HasRole {
    /// Returns the channel ID.
    fn channel_id(&self) -> ChannelId;

    /// Returns the current update count.
    fn update_count(&self) -> u64;

    /// Returns the current channel witness (adapter signature offset).
    ///
    /// The witness is guaranteed to be valid in both Ed25519 and SF scalar fields.
    fn current_offset(&self) -> ChannelWitness<SF>;

    /// Verify that a peer's offset is valid for the given update count.
    ///
    /// This validates that the offset corresponds to the expected VCOF output
    /// for the specified update count.
    fn verify_offset(&self, offset: &ChannelWitness<SF>, update_count: u64) -> Result<(), CloseProtocolError>;
}

/// Protocol trait for the close initiator.
///
/// The initiator sends a close request with their offset and either receives
/// a success response (with the peer's offset) or a failure.
pub trait CloseProtocolInitiator<SF: Ciphersuite>: CloseProtocolCommon<SF> {
    /// Create a close request to send to the peer.
    fn create_close_request(&self) -> Result<RequestChannelClose<SF>, CloseProtocolError>;

    /// Handle a successful close response from the peer.
    ///
    /// Validates the peer's offset and prepares for transaction broadcast.
    fn handle_close_success(&mut self, response: ChannelCloseSuccess<SF>) -> Result<(), CloseProtocolError>;

    /// Handle a failed close response from the peer.
    fn handle_close_failed(&mut self, response: RequestCloseFailed) -> Result<(), CloseProtocolError>;

    /// Broadcast the closing transaction using the peer's offset.
    ///
    /// This should only be called after receiving a successful close response
    /// if the responder didn't broadcast.
    fn broadcast_closing_tx(&self, peer_offset: &ChannelWitness<SF>) -> Result<TransactionId, CloseProtocolError>;
}

/// Protocol trait for the close responder.
///
/// The responder receives a close request, validates it, and either
/// agrees (signing and optionally broadcasting) or rejects with a reason.
pub trait CloseProtocolResponder<SF: Ciphersuite>: CloseProtocolCommon<SF> {
    /// Receive and validate a close request from the initiator.
    fn receive_close_request(&mut self, request: RequestChannelClose<SF>) -> Result<(), CloseProtocolError>;

    /// Sign and optionally broadcast the closing transaction.
    ///
    /// Returns the transaction ID if broadcast, or None if the initiator should broadcast.
    fn sign_and_broadcast(
        &mut self,
        initiator_offset: &ChannelWitness<SF>,
    ) -> Result<Option<TransactionId>, CloseProtocolError>;

    /// Create a success response to send to the initiator.
    fn create_success_response(&self, txid: Option<TransactionId>) -> ChannelCloseSuccess<SF>;

    /// Create a failure response to send to the initiator.
    fn create_failure_response(&self, reason: CloseFailureReason) -> RequestCloseFailed;
}

/// Errors that can occur during the cooperative close protocol.
#[derive(Debug, Error)]
pub enum CloseProtocolError {
    #[error("Channel not found: {0}")]
    ChannelNotFound(String),

    #[error("Channel not in closeable state: {0}")]
    InvalidChannelState(String),

    #[error("Update count mismatch: expected {expected}, got {actual}")]
    UpdateCountMismatch { expected: u64, actual: u64 },

    #[error("Invalid offset: {0}")]
    InvalidOffset(String),

    #[error("Offset verification failed: {0}")]
    OffsetVerificationFailed(String),

    #[error("Missing required information: {0}")]
    MissingInformation(String),

    #[error("Transaction broadcast failed: {0}")]
    BroadcastFailed(String),

    #[error("Close request already received")]
    CloseRequestAlreadyReceived,

    #[error("No close request received")]
    NoCloseRequestReceived,

    #[error("Peer rejected close: {0}")]
    CloseRejected(CloseFailureReason),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Network error: {0}")]
    NetworkError(String),
}
