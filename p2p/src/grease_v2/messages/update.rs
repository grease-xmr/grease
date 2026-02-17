//! Update protocol messages.
//!
//! The update phase handles payment state updates. Either party can initiate an update.
//!
//! # Flow (2-round protocol)
//! 1. Initiator sends `PrepareUpdate` with delta and preprocessing info
//! 2. Responder validates and returns `UpdatePrepared` with their proof and signature
//! 3. Initiator sends `CommitUpdate` with their proof and signature
//! 4. Responder returns `UpdateCommitted` with finalized update record

use libgrease::amount::MoneroDelta;
use libgrease::channel_id::ChannelId;
use libgrease::cryptography::zk_objects::PublicUpdateProof;
use libgrease::monero::data_objects::FinalizedUpdate;
use libgrease::wallet::multisig_wallet::AdaptSig;
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Display, Formatter};

/// Request messages for the update protocol.
///
/// Either customer or merchant can initiate an update.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UpdateRequest {
    /// First round: Initiator prepares an update.
    PrepareUpdate(PrepareUpdatePayload),

    /// Second round: Initiator commits the update.
    CommitUpdate(CommitUpdatePayload),
}

impl UpdateRequest {
    /// Returns the channel ID for this request.
    pub fn channel_id(&self) -> &ChannelId {
        match self {
            UpdateRequest::PrepareUpdate(p) => &p.channel_id,
            UpdateRequest::CommitUpdate(p) => &p.channel_id,
        }
    }

    /// Creates a prepare update request.
    pub fn prepare(channel_id: ChannelId, update_count: u64, delta: MoneroDelta, prepare_info: Vec<u8>) -> Self {
        UpdateRequest::PrepareUpdate(PrepareUpdatePayload { channel_id, update_count, delta, prepare_info })
    }

    /// Creates a commit update request.
    pub fn commit(channel_id: ChannelId, update_count: u64, proof: PublicUpdateProof, adapted_sig: AdaptSig) -> Self {
        UpdateRequest::CommitUpdate(CommitUpdatePayload { channel_id, update_count, proof, adapted_sig })
    }
}

/// Response messages for the update protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UpdateResponse {
    /// Response to prepare: Responder's proof and signature.
    Prepared(UpdatePreparedPayload),

    /// Response to commit: Finalized update record.
    Committed(UpdateCommittedPayload),

    /// Error during update.
    Error(UpdateError),
}

impl Display for UpdateResponse {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            UpdateResponse::Prepared(p) => write!(f, "Prepared(channel={}, count={})", p.channel_id, p.update_count),
            UpdateResponse::Committed(p) => write!(f, "Committed(channel={})", p.channel_id),
            UpdateResponse::Error(e) => write!(f, "Error({e})"),
        }
    }
}

// ============================================================================
// Payload types
// ============================================================================

/// Payload for prepare update request.
#[derive(Clone, Serialize, Deserialize)]
pub struct PrepareUpdatePayload {
    pub channel_id: ChannelId,
    pub update_count: u64,
    pub delta: MoneroDelta,
    /// Opaque preprocessing data from the initiator.
    pub prepare_info: Vec<u8>,
}

impl Debug for PrepareUpdatePayload {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrepareUpdatePayload")
            .field("channel_id", &self.channel_id)
            .field("update_count", &self.update_count)
            .field("delta", &self.delta.amount)
            .field("prepare_info_len", &self.prepare_info.len())
            .finish()
    }
}

/// Payload for update prepared response.
#[derive(Clone, Serialize, Deserialize)]
pub struct UpdatePreparedPayload {
    pub channel_id: ChannelId,
    pub update_count: u64,
    pub delta: MoneroDelta,
    /// Opaque preprocessing data from the responder.
    pub prepare_info: Vec<u8>,
    /// Responder's update proof.
    pub proof: PublicUpdateProof,
    /// Responder's adapted signature.
    pub adapted_sig: AdaptSig,
}

impl Debug for UpdatePreparedPayload {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpdatePreparedPayload")
            .field("channel_id", &self.channel_id)
            .field("update_count", &self.update_count)
            .field("delta", &self.delta.amount)
            .finish()
    }
}

/// Payload for commit update request.
#[derive(Clone, Serialize, Deserialize)]
pub struct CommitUpdatePayload {
    pub channel_id: ChannelId,
    pub update_count: u64,
    /// Initiator's update proof.
    pub proof: PublicUpdateProof,
    /// Initiator's adapted signature.
    pub adapted_sig: AdaptSig,
}

impl Debug for CommitUpdatePayload {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CommitUpdatePayload")
            .field("channel_id", &self.channel_id)
            .field("update_count", &self.update_count)
            .finish()
    }
}

/// Payload for update committed response.
#[derive(Clone, Serialize, Deserialize)]
pub struct UpdateCommittedPayload {
    pub channel_id: ChannelId,
    /// The finalized update record containing both parties' data.
    pub finalized: FinalizedUpdate,
}

impl Debug for UpdateCommittedPayload {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpdateCommittedPayload").field("channel_id", &self.channel_id).finish()
    }
}

// ============================================================================
// Error types
// ============================================================================

/// Errors that can occur during channel updates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UpdateError {
    /// Channel not found.
    ChannelNotFound(ChannelId),

    /// Channel is not in Open state.
    ChannelNotOpen(ChannelId),

    /// Update count mismatch.
    UpdateCountMismatch { channel_id: ChannelId, expected: u64, received: u64 },

    /// Insufficient funds for this update.
    InsufficientFunds { channel_id: ChannelId, available: i64, requested: i64 },

    /// Proof verification failed.
    ProofVerificationFailed { channel_id: ChannelId, reason: String },

    /// Signature verification failed.
    SignatureVerificationFailed { channel_id: ChannelId, reason: String },

    /// Update already in progress.
    UpdateInProgress(ChannelId),

    /// Internal error.
    Internal { channel_id: ChannelId, reason: String },
}

impl Display for UpdateError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            UpdateError::ChannelNotFound(id) => write!(f, "Channel not found: {id}"),
            UpdateError::ChannelNotOpen(id) => write!(f, "Channel {id} is not open"),
            UpdateError::UpdateCountMismatch { channel_id, expected, received } => {
                write!(
                    f,
                    "Channel {channel_id}: update count mismatch (expected {expected}, got {received})"
                )
            }
            UpdateError::InsufficientFunds { channel_id, available, requested } => {
                write!(
                    f,
                    "Channel {channel_id}: insufficient funds (available {available}, requested {requested})"
                )
            }
            UpdateError::ProofVerificationFailed { channel_id, reason } => {
                write!(f, "Channel {channel_id}: proof verification failed: {reason}")
            }
            UpdateError::SignatureVerificationFailed { channel_id, reason } => {
                write!(f, "Channel {channel_id}: signature verification failed: {reason}")
            }
            UpdateError::UpdateInProgress(id) => write!(f, "Channel {id}: update already in progress"),
            UpdateError::Internal { channel_id, reason } => {
                write!(f, "Channel {channel_id}: internal error: {reason}")
            }
        }
    }
}

impl UpdateError {
    pub fn channel_id(&self) -> &ChannelId {
        match self {
            UpdateError::ChannelNotFound(id) => id,
            UpdateError::ChannelNotOpen(id) => id,
            UpdateError::UpdateCountMismatch { channel_id, .. } => channel_id,
            UpdateError::InsufficientFunds { channel_id, .. } => channel_id,
            UpdateError::ProofVerificationFailed { channel_id, .. } => channel_id,
            UpdateError::SignatureVerificationFailed { channel_id, .. } => channel_id,
            UpdateError::UpdateInProgress(id) => id,
            UpdateError::Internal { channel_id, .. } => channel_id,
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
    fn update_error_display() {
        let err = UpdateError::UpdateCountMismatch { channel_id: test_channel_id(), expected: 5, received: 3 };
        assert!(err.to_string().contains("update count mismatch"));
    }
}
