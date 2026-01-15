//! Establish protocol network API.

use async_trait::async_trait;
use libgrease::channel_id::ChannelId;
use libgrease::cryptography::zk_objects::PublicProof0;
use libgrease::monero::data_objects::{MultisigKeyInfo, MultisigSplitSecrets, MultisigSplitSecretsResponse};
use libp2p::PeerId;

/// Network error for establish operations.
#[derive(Debug, Clone, thiserror::Error)]
pub enum EstablishNetworkError {
    #[error("Connection to peer failed: {0}")]
    ConnectionFailed(String),

    #[error("Request timed out")]
    Timeout,

    #[error("Channel not found: {0}")]
    ChannelNotFound(ChannelId),

    #[error("Protocol error: {0}")]
    ProtocolError(String),

    #[error("Unexpected response: {0}")]
    UnexpectedResponse(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

/// Network API for establish protocol operations.
///
/// Implemented by network clients to send establish requests to peers.
/// Used by both `CustomerEstablish` (initiator) and for testing.
#[async_trait]
pub trait EstablishNetworkAPI: Send + Sync {
    /// Exchange multisig wallet keys with peer.
    ///
    /// Sends our key info and receives peer's key info in response.
    async fn send_key_exchange(
        &self,
        peer_id: PeerId,
        channel_id: &ChannelId,
        key_info: MultisigKeyInfo,
    ) -> Result<MultisigKeyInfo, EstablishNetworkError>;

    /// Confirm multisig wallet address matches.
    ///
    /// Sends the expected address and receives confirmation from peer.
    async fn send_address_confirmation(
        &self,
        peer_id: PeerId,
        channel_id: &ChannelId,
        address: String,
    ) -> Result<bool, EstablishNetworkError>;

    /// Exchange KES split secrets with peer.
    ///
    /// Sends our secrets (adapted signature, DLEQ proof, encrypted secret)
    /// and receives peer's secrets in response.
    async fn send_split_secrets(
        &self,
        peer_id: PeerId,
        channel_id: &ChannelId,
        secrets: MultisigSplitSecrets,
    ) -> Result<MultisigSplitSecretsResponse, EstablishNetworkError>;

    /// Exchange initial witness proofs (proof0) with peer.
    ///
    /// Sends our proof0 and receives peer's proof0 in response.
    async fn send_proof0(
        &self,
        peer_id: PeerId,
        channel_id: &ChannelId,
        proof: PublicProof0,
    ) -> Result<PublicProof0, EstablishNetworkError>;
}
