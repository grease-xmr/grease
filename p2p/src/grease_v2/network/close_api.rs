//! Close protocol network API.

use async_trait::async_trait;
use libgrease::channel_id::ChannelId;
use libgrease::monero::data_objects::TransactionId;
use libgrease::state_machine::ChannelCloseRecord;
use libp2p::PeerId;

/// Network error for close operations.
#[derive(Debug, Clone, thiserror::Error)]
pub enum CloseNetworkError {
    #[error("Connection to peer failed: {0}")]
    ConnectionFailed(String),

    #[error("Request timed out")]
    Timeout,

    #[error("Channel not found: {0}")]
    ChannelNotFound(ChannelId),

    #[error("Close rejected: {0}")]
    Rejected(String),

    #[error("Protocol error: {0}")]
    ProtocolError(String),

    #[error("Unexpected response: {0}")]
    UnexpectedResponse(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

/// Network API for close protocol operations.
///
/// Implemented by network clients to send close requests to peers.
/// Used by `CloseInitiator` for cooperative channel closing.
#[async_trait]
pub trait CloseNetworkAPI: Send + Sync {
    /// Send close request to peer.
    ///
    /// Initiator sends their closing record (with partial secrets),
    /// receives peer's closing record in response.
    async fn send_close_request(
        &self,
        peer_id: PeerId,
        channel_id: &ChannelId,
        close_record: ChannelCloseRecord,
    ) -> Result<ChannelCloseRecord, CloseNetworkError>;

    /// Notify peer that closing transaction has been broadcast.
    ///
    /// Sends the transaction ID and receives acknowledgment.
    async fn send_closing_tx_broadcast(
        &self,
        peer_id: PeerId,
        channel_id: &ChannelId,
        tx_id: TransactionId,
    ) -> Result<bool, CloseNetworkError>;
}
