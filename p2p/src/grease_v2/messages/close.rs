//! Close protocol messages.
//!
//! The close phase handles cooperative channel closing. Either party can initiate.
//!
//! # Flow
//! 1. Initiator sends `RequestClose` with their closing record (partial secrets)
//! 2. Responder validates and returns `CloseAccepted` with their closing record
//! 3. Either party broadcasts the closing transaction
//! 4. Broadcaster notifies peer with `ClosingTxBroadcast`
//! 5. Peer acknowledges with `ClosingTxAcknowledged`

use libgrease::channel_id::ChannelId;
use libgrease::monero::data_objects::TransactionId;
use libgrease::state_machine::ChannelCloseRecord;
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};

/// Request messages for the close protocol.
///
/// Either customer or merchant can initiate a close.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CloseRequest {
    /// Initiate cooperative close with closing record.
    RequestClose(CloseRequestPayload),

    /// Notify peer that closing transaction has been broadcast.
    ClosingTxBroadcast(ClosingTxPayload),
}

impl CloseRequest {
    /// Returns the channel ID for this request.
    pub fn channel_id(&self) -> &ChannelId {
        match self {
            CloseRequest::RequestClose(p) => &p.channel_id,
            CloseRequest::ClosingTxBroadcast(p) => &p.channel_id,
        }
    }

    /// Creates a close request.
    pub fn request_close(channel_id: ChannelId, close_record: ChannelCloseRecord) -> Self {
        CloseRequest::RequestClose(CloseRequestPayload { channel_id, close_record })
    }

    /// Creates a closing tx broadcast notification.
    pub fn closing_tx_broadcast(channel_id: ChannelId, tx_id: TransactionId) -> Self {
        CloseRequest::ClosingTxBroadcast(ClosingTxPayload { channel_id, tx_id })
    }
}

/// Response messages for the close protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CloseResponse {
    /// Peer accepts the close and provides their closing record.
    CloseAccepted(CloseAcceptedPayload),

    /// Peer acknowledges the closing transaction broadcast.
    ClosingTxAcknowledged(ClosingTxAckPayload),

    /// Error during close.
    Error(CloseError),
}

impl Display for CloseResponse {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            CloseResponse::CloseAccepted(p) => write!(f, "CloseAccepted(channel={})", p.channel_id),
            CloseResponse::ClosingTxAcknowledged(p) => {
                write!(f, "ClosingTxAcknowledged(channel={}, success={})", p.channel_id, p.success)
            }
            CloseResponse::Error(e) => write!(f, "Error({e})"),
        }
    }
}

// ============================================================================
// Payload types
// ============================================================================

/// Payload for close request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloseRequestPayload {
    pub channel_id: ChannelId,
    /// The initiator's closing record with partial secrets.
    pub close_record: ChannelCloseRecord,
}

/// Payload for close accepted response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloseAcceptedPayload {
    pub channel_id: ChannelId,
    /// The responder's closing record with partial secrets.
    pub close_record: ChannelCloseRecord,
}

/// Payload for closing transaction broadcast notification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClosingTxPayload {
    pub channel_id: ChannelId,
    /// The transaction ID of the broadcast closing transaction.
    pub tx_id: TransactionId,
}

/// Payload for closing transaction acknowledgment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClosingTxAckPayload {
    pub channel_id: ChannelId,
    /// Whether the peer successfully received and validated the tx notification.
    pub success: bool,
}

impl ClosingTxAckPayload {
    pub fn success(channel_id: ChannelId) -> Self {
        Self { channel_id, success: true }
    }

    pub fn failure(channel_id: ChannelId) -> Self {
        Self { channel_id, success: false }
    }
}

// ============================================================================
// Error types
// ============================================================================

/// Errors that can occur during channel closing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CloseError {
    /// Channel not found.
    ChannelNotFound(ChannelId),

    /// Channel is not in a state that can be closed.
    CannotClose { channel_id: ChannelId, reason: String },

    /// Close record validation failed.
    InvalidCloseRecord { channel_id: ChannelId, reason: String },

    /// Balance mismatch in close record.
    BalanceMismatch { channel_id: ChannelId, our_balance: i64, their_balance: i64 },

    /// Witness verification failed.
    WitnessVerificationFailed { channel_id: ChannelId, reason: String },

    /// Channel is already closing.
    AlreadyClosing(ChannelId),

    /// Internal error.
    Internal { channel_id: ChannelId, reason: String },
}

impl Display for CloseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            CloseError::ChannelNotFound(id) => write!(f, "Channel not found: {id}"),
            CloseError::CannotClose { channel_id, reason } => {
                write!(f, "Channel {channel_id} cannot be closed: {reason}")
            }
            CloseError::InvalidCloseRecord { channel_id, reason } => {
                write!(f, "Channel {channel_id}: invalid close record: {reason}")
            }
            CloseError::BalanceMismatch { channel_id, our_balance, their_balance } => {
                write!(
                    f,
                    "Channel {channel_id}: balance mismatch (ours={our_balance}, theirs={their_balance})"
                )
            }
            CloseError::WitnessVerificationFailed { channel_id, reason } => {
                write!(f, "Channel {channel_id}: witness verification failed: {reason}")
            }
            CloseError::AlreadyClosing(id) => write!(f, "Channel {id} is already closing"),
            CloseError::Internal { channel_id, reason } => {
                write!(f, "Channel {channel_id}: internal error: {reason}")
            }
        }
    }
}

impl CloseError {
    pub fn channel_id(&self) -> &ChannelId {
        match self {
            CloseError::ChannelNotFound(id) => id,
            CloseError::CannotClose { channel_id, .. } => channel_id,
            CloseError::InvalidCloseRecord { channel_id, .. } => channel_id,
            CloseError::BalanceMismatch { channel_id, .. } => channel_id,
            CloseError::WitnessVerificationFailed { channel_id, .. } => channel_id,
            CloseError::AlreadyClosing(id) => id,
            CloseError::Internal { channel_id, .. } => channel_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn test_channel_id() -> ChannelId {
        ChannelId::from_str("XGC4a7024e7fd6f5c6a2d0131d12fd91ecd17f5da61c2970d603a05053b41a383").unwrap()
    }

    #[test]
    fn close_error_display() {
        let err = CloseError::AlreadyClosing(test_channel_id());
        assert!(err.to_string().contains("already closing"));
    }
}
