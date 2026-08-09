//! Channel Close Protocol Traits (Cooperative Close)
//!
//! A cooperative close is a two-message exchange between the parties alone: **the arbiter is not involved**, holds no
//! funds and is never contacted. Spec: `docs/src/16_cooperative_close.typ` §coopClose / §closeMessages, and
//! `docs/diagrams/close_channel_sequence.md`.
//!
//! The flow, from either side (the spec illustrates it with the customer initiating):
//!
//! 1. The initiator sends [`RequestChannelClose`] carrying its latest adaptor offset ω and the `update_count` of the
//!    latest cross-signed [`UpdateRecord`](crate::grease_protocol::update_record::UpdateRecord) — the record is the
//!    single source of truth for *which* state is being closed.
//! 2. The responder verifies the offset by attempting to complete the closing-transaction signature for that
//!    `update_count`: ω must be the discrete log of the adaptor point in the initiator's adapted signature over the
//!    closing transaction the record's `close_hash` commits to. On success it broadcasts the completed transaction,
//!    marks the channel `Closed`, and replies [`ChannelCloseSuccess`] with its own offset and the txid.
//! 3. On any error the responder replies [`RequestCloseFailed`] and the channel remains `Open`.
//! 4. `txid` is optional: if the responder did not broadcast, the initiator may use the returned offset to
//!    reconstruct and broadcast the closing transaction itself.
//!
//! If a party becomes unresponsive mid-close the other falls back to a unilateral close through the arbiter — that
//! path lives in [`force_close_channel`](crate::grease_protocol::force_close_channel), not here.
//!
//! Note that `update_count` is monotonic but not necessarily incremented by one: gaps are legal, so the only valid
//! check is equality against the latest cross-signed record's count.

use crate::channel_id::ChannelId;
use crate::monero::data_objects::TransactionId;
use crate::payment_channel::HasRole;
use crate::cryptography::keys::Curve25519Secret;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Request to close a channel cooperatively.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestChannelClose {
    /// The channel being closed
    pub channel_id: ChannelId,
    /// The initiator's latest adaptor offset (ω), which completes the initiator's adapted closing signature
    pub offset: Curve25519Secret,
    /// The update count of the latest cross-signed `UpdateRecord` — the state being closed
    pub update_count: u64,
}

/// Successful channel close response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelCloseSuccess {
    /// The channel being closed
    pub channel_id: ChannelId,
    /// The responder's latest adaptor offset (ω), which completes the responder's adapted closing signature
    pub offset: Curve25519Secret,
    /// The closing transaction's id if the responder broadcast it. `None` means the responder signed but did not
    /// broadcast, and the initiator may reconstruct and broadcast the transaction itself using `offset`.
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
pub trait CloseProtocolCommon: HasRole {
    /// Returns the channel ID.
    fn channel_id(&self) -> ChannelId;

    /// The `update_count` of the latest cross-signed
    /// [`UpdateRecord`](crate::grease_protocol::update_record::UpdateRecord) — the state this close settles.
    ///
    /// Counts are monotonic but may skip values, so this is only ever compared for equality, never for a `+1` step.
    fn update_count(&self) -> u64;

    /// Our own latest adaptor offset ω: the secret whose adaptor point `Q = ω·G` was adapted into the counterparty's
    /// closing signature for the state at [`update_count`](CloseProtocolCommon::update_count). Offsets are fresh and
    /// independent per state and per party — they are never derived from one another.
    ///
    fn current_offset(&self) -> Curve25519Secret;

    /// Verify that a peer's offset is valid for the given update count.
    ///
    /// Two checks: `update_count` must equal the count of our latest cross-signed `UpdateRecord`, and the offset must
    /// *complete the adaptor signature* for that state — that is, ω must be the discrete log of the adaptor point in
    /// the peer's adapted signature over the closing transaction, so that adding it yields a valid signature we can
    /// broadcast. An offset that does not complete the signature is rejected with
    /// [`CloseProtocolError::OffsetVerificationFailed`].
    fn verify_offset(&self, offset: &Curve25519Secret, update_count: u64) -> Result<(), CloseProtocolError>;
}

/// Protocol trait for the close initiator.
///
/// The initiator sends a close request with their offset and either receives
/// a success response (with the peer's offset) or a failure.
pub trait CloseProtocolInitiator: CloseProtocolCommon {
    /// Create a close request to send to the peer.
    fn create_close_request(&self) -> Result<RequestChannelClose, CloseProtocolError>;

    /// Handle a successful close response from the peer.
    ///
    /// Validates the peer's offset against our own latest update count and records the responder's txid if it
    /// broadcast; otherwise the caller finishes the close with
    /// [`broadcast_closing_tx`](CloseProtocolInitiator::broadcast_closing_tx).
    fn handle_close_success(&mut self, response: ChannelCloseSuccess) -> Result<(), CloseProtocolError>;

    /// Handle a failed close response from the peer. The channel remains `Open`.
    fn handle_close_failed(&mut self, response: RequestCloseFailed) -> Result<(), CloseProtocolError>;

    /// Complete the closing signature with the peer's offset and broadcast the closing transaction.
    ///
    /// Only called after a successful close response whose `txid` was `None` — the responder signed but left the
    /// broadcast to us.
    fn broadcast_closing_tx(&self, peer_offset: &Curve25519Secret) -> Result<TransactionId, CloseProtocolError>;
}

/// Protocol trait for the close responder.
///
/// The responder receives a close request, validates it, and either
/// agrees (signing and optionally broadcasting) or rejects with a reason.
pub trait CloseProtocolResponder: CloseProtocolCommon {
    /// Receive a close request from the initiator and verify it: the channel id must be ours, and the offset must
    /// complete the closing-transaction signature for the requested update count.
    fn receive_close_request(&mut self, request: RequestChannelClose) -> Result<(), CloseProtocolError>;

    /// Complete the closing-transaction signature with the initiator's offset and broadcast it.
    ///
    /// Returns the transaction id if we broadcast, or `None` to leave the broadcast to the initiator (who has our
    /// offset from [`create_success_response`](CloseProtocolResponder::create_success_response)).
    fn sign_and_broadcast(
        &mut self,
        initiator_offset: &Curve25519Secret,
    ) -> Result<Option<TransactionId>, CloseProtocolError>;

    /// Create a success response to send to the initiator.
    fn create_success_response(&self, txid: Option<TransactionId>) -> ChannelCloseSuccess;

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

impl CloseProtocolError {
    /// The [`CloseFailureReason`] a responder puts on the wire for this error. Local detail that is of no use to the
    /// peer collapses into [`CloseFailureReason::ProtocolError`].
    pub fn to_failure_reason(&self) -> CloseFailureReason {
        match self {
            CloseProtocolError::ChannelNotFound(id) => CloseFailureReason::InvalidChannelState(format!("unknown channel {id}")),
            CloseProtocolError::InvalidChannelState(s) => CloseFailureReason::InvalidChannelState(s.clone()),
            CloseProtocolError::UpdateCountMismatch { expected, actual } => {
                CloseFailureReason::UpdateCountMismatch { expected: *expected, received: *actual }
            }
            CloseProtocolError::InvalidOffset(s) => CloseFailureReason::InvalidOffset(s.clone()),
            CloseProtocolError::OffsetVerificationFailed(s) => CloseFailureReason::InvalidOffset(s.clone()),
            // A close cannot complete while the peer is unreachable, so the network paths report the peer, not us.
            CloseProtocolError::NetworkError(_) => CloseFailureReason::PeerUnresponsive,
            CloseProtocolError::CloseRejected(reason) => reason.clone(),
            other => CloseFailureReason::ProtocolError(other.to_string()),
        }
    }
}
