//! Proposal protocol network API.

use async_trait::async_trait;
use libp2p::PeerId;

use crate::grease::NewChannelMessage;
use crate::grease_v2::messages::proposal::{ChannelAccepted, ChannelRejected};

/// Network error for proposal operations.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ProposalNetworkError {
    #[error("Connection to peer failed: {0}")]
    ConnectionFailed(String),

    #[error("Request timed out")]
    Timeout,

    #[error("Peer rejected proposal: {0}")]
    Rejected(String),

    #[error("Unexpected response: {0}")]
    UnexpectedResponse(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

/// Network API for proposal protocol operations.
///
/// Implemented by network clients to send proposal requests to peers.
#[async_trait]
pub trait ProposalNetworkAPI: Send + Sync {
    /// Send a channel proposal to a merchant peer.
    ///
    /// Returns `Ok(ChannelAccepted)` if the merchant accepts, or `Err` with rejection details.
    async fn send_proposal(
        &self,
        peer_id: PeerId,
        proposal: NewChannelMessage,
    ) -> Result<ChannelAccepted, ProposalNetworkError>;
}

/// Result of a proposal, before converting to error.
#[derive(Debug, Clone)]
pub enum ProposalResult {
    Accepted(ChannelAccepted),
    Rejected(ChannelRejected),
}
