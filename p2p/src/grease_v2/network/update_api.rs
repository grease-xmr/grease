//! Update protocol network API.

use async_trait::async_trait;
use libgrease::amount::MoneroDelta;
use libgrease::channel_id::ChannelId;
use libgrease::cryptography::zk_objects::PublicUpdateProof;
use libgrease::monero::data_objects::FinalizedUpdate;
use libp2p::PeerId;
use wallet::multisig_wallet::AdaptSig;

use crate::grease_v2::messages::update::UpdatePreparedPayload;

/// Network error for update operations.
#[derive(Debug, Clone, thiserror::Error)]
pub enum UpdateNetworkError {
    #[error("Connection to peer failed: {0}")]
    ConnectionFailed(String),

    #[error("Request timed out")]
    Timeout,

    #[error("Channel not found: {0}")]
    ChannelNotFound(ChannelId),

    #[error("Update rejected: {0}")]
    Rejected(String),

    #[error("Protocol error: {0}")]
    ProtocolError(String),

    #[error("Unexpected response: {0}")]
    UnexpectedResponse(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

/// Network API for update protocol operations.
///
/// Implemented by network clients to send update requests to peers.
/// Used by `UpdateInitiator` for the 2-round update protocol.
#[async_trait]
pub trait UpdateNetworkAPI: Send + Sync {
    /// Send prepare update request (round 1).
    ///
    /// Initiator sends delta and preprocessing info, receives responder's
    /// preprocessing info, proof, and adapted signature.
    async fn send_prepare_update(
        &self,
        peer_id: PeerId,
        channel_id: &ChannelId,
        update_count: u64,
        delta: MoneroDelta,
        prepare_info: Vec<u8>,
    ) -> Result<UpdatePreparedPayload, UpdateNetworkError>;

    /// Send commit update request (round 2).
    ///
    /// Initiator sends their proof and adapted signature, receives
    /// the finalized update record.
    async fn send_commit_update(
        &self,
        peer_id: PeerId,
        channel_id: &ChannelId,
        update_count: u64,
        proof: PublicUpdateProof,
        adapted_sig: AdaptSig,
    ) -> Result<FinalizedUpdate, UpdateNetworkError>;
}
