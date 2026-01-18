//! Network client implementation for Grease v2.

use async_trait::async_trait;
use futures::channel::{mpsc, oneshot};
use futures::SinkExt;
use libgrease::amount::MoneroDelta;
use libgrease::channel_id::ChannelId;
use libgrease::cryptography::zk_objects::PublicProof0;
use libgrease::cryptography::zk_objects::PublicUpdateProof;
use libgrease::monero::data_objects::{
    FinalizedUpdate, MultisigKeyInfo, MultisigSplitSecrets, MultisigSplitSecretsResponse, TransactionId,
};
use libgrease::state_machine::ChannelCloseRecord;
use libp2p::PeerId;
use log::*;
use wallet::multisig_wallet::AdaptSig;

use crate::behaviour_v2::ProtocolCommandV2;
use crate::grease::NewChannelMessage;
use crate::grease_v2::messages::proposal::{ChannelAccepted, ProposalError, ProposalRequest, ProposalResponse};
use crate::grease_v2::messages::update::UpdatePreparedPayload;
use crate::grease_v2::messages::{
    CloseRequest, CloseResponse, EstablishRequest, EstablishResponse, UpdateRequest, UpdateResponse,
};
use crate::p2p_networking::NetworkCommand;

use super::close_api::{CloseNetworkAPI, CloseNetworkError};
use super::establish_api::{EstablishNetworkAPI, EstablishNetworkError};
use super::proposal_api::{ProposalNetworkAPI, ProposalNetworkError};
use super::update_api::{UpdateNetworkAPI, UpdateNetworkError};

/// Network client for Grease v2 protocol operations.
///
/// Implements all protocol-specific network API traits, using the underlying
/// libp2p infrastructure via command channels to the event loop.
#[derive(Clone)]
pub struct NetworkClientV2 {
    sender: mpsc::Sender<NetworkCommand>,
}

impl NetworkClientV2 {
    /// Create a new network client with the given command sender.
    pub fn new(sender: mpsc::Sender<NetworkCommand>) -> Self {
        Self { sender }
    }

    /// Send a proposal protocol command and wait for response.
    async fn send_proposal_request(
        &self,
        peer_id: PeerId,
        request: ProposalRequest,
    ) -> Result<ProposalResponse, ProposalNetworkError> {
        let (sender, receiver) = oneshot::channel();
        let cmd = ProtocolCommandV2::SendProposalRequest { peer_id, request, sender };

        self.sender
            .clone()
            .send(NetworkCommand::ProtocolV2(cmd))
            .await
            .map_err(|e| ProposalNetworkError::Internal(format!("Failed to send command: {e}")))?;

        receiver
            .await
            .map_err(|_| ProposalNetworkError::Internal("Response channel closed".into()))?
            .map_err(|e| ProposalNetworkError::ConnectionFailed(e.to_string()))
    }

    /// Send an establish protocol command and wait for response.
    async fn send_establish_request(
        &self,
        peer_id: PeerId,
        request: EstablishRequest,
    ) -> Result<EstablishResponse, EstablishNetworkError> {
        let (sender, receiver) = oneshot::channel();
        let cmd = ProtocolCommandV2::SendEstablishRequest { peer_id, request, sender };

        self.sender
            .clone()
            .send(NetworkCommand::ProtocolV2(cmd))
            .await
            .map_err(|e| EstablishNetworkError::Internal(format!("Failed to send command: {e}")))?;

        receiver
            .await
            .map_err(|_| EstablishNetworkError::Internal("Response channel closed".into()))?
            .map_err(|e| EstablishNetworkError::ConnectionFailed(e.to_string()))
    }

    /// Send an update protocol command and wait for response.
    async fn send_update_request(
        &self,
        peer_id: PeerId,
        request: UpdateRequest,
    ) -> Result<UpdateResponse, UpdateNetworkError> {
        let (sender, receiver) = oneshot::channel();
        let cmd = ProtocolCommandV2::SendUpdateRequest { peer_id, request, sender };

        self.sender
            .clone()
            .send(NetworkCommand::ProtocolV2(cmd))
            .await
            .map_err(|e| UpdateNetworkError::Internal(format!("Failed to send command: {e}")))?;

        receiver
            .await
            .map_err(|_| UpdateNetworkError::Internal("Response channel closed".into()))?
            .map_err(|e| UpdateNetworkError::ConnectionFailed(e.to_string()))
    }

    /// Send a close protocol command and wait for response.
    async fn send_close_request(
        &self,
        peer_id: PeerId,
        request: CloseRequest,
    ) -> Result<CloseResponse, CloseNetworkError> {
        let (sender, receiver) = oneshot::channel();
        let cmd = ProtocolCommandV2::SendCloseRequest { peer_id, request, sender };

        self.sender
            .clone()
            .send(NetworkCommand::ProtocolV2(cmd))
            .await
            .map_err(|e| CloseNetworkError::Internal(format!("Failed to send command: {e}")))?;

        receiver
            .await
            .map_err(|_| CloseNetworkError::Internal("Response channel closed".into()))?
            .map_err(|e| CloseNetworkError::ConnectionFailed(e.to_string()))
    }
}

// ============================================================================
// ProposalNetworkAPI implementation
// ============================================================================

#[async_trait]
impl ProposalNetworkAPI for NetworkClientV2 {
    async fn send_proposal(
        &self,
        peer_id: PeerId,
        proposal: NewChannelMessage,
    ) -> Result<ChannelAccepted, ProposalNetworkError> {
        debug!("📤 Sending channel proposal to peer {peer_id}");

        let request = ProposalRequest::ProposeChannel(proposal);
        let response = self.send_proposal_request(peer_id, request).await?;

        match response {
            ProposalResponse::Accepted(accepted) => {
                info!("✅ Channel proposal accepted: {}", accepted.channel_id);
                Ok(accepted)
            }
            ProposalResponse::Rejected(rejected) => {
                warn!("❌ Channel proposal rejected: {}", rejected.reason);
                Err(ProposalNetworkError::Rejected(rejected.reason.to_string()))
            }
            ProposalResponse::Error(ProposalError::ChannelNotFound(id)) => {
                Err(ProposalNetworkError::UnexpectedResponse(format!("Channel not found: {id}")))
            }
            ProposalResponse::Error(ProposalError::Internal(msg)) => Err(ProposalNetworkError::Internal(msg)),
        }
    }
}

// ============================================================================
// EstablishNetworkAPI implementation
// ============================================================================

#[async_trait]
impl EstablishNetworkAPI for NetworkClientV2 {
    async fn send_key_exchange(
        &self,
        peer_id: PeerId,
        channel_id: &ChannelId,
        key_info: MultisigKeyInfo,
    ) -> Result<MultisigKeyInfo, EstablishNetworkError> {
        debug!("📤 Sending key exchange for channel {channel_id} to peer {peer_id}");

        let request = EstablishRequest::key_exchange(channel_id.clone(), key_info);
        let response = self.send_establish_request(peer_id, request).await?;

        match response {
            EstablishResponse::KeyExchange(payload) => {
                info!("🔑 Key exchange complete for channel {channel_id}");
                Ok(payload.key_info)
            }
            EstablishResponse::Error(e) => Err(EstablishNetworkError::ProtocolError(e.to_string())),
            other => Err(EstablishNetworkError::UnexpectedResponse(format!("{other}"))),
        }
    }

    async fn send_address_confirmation(
        &self,
        peer_id: PeerId,
        channel_id: &ChannelId,
        address: String,
    ) -> Result<bool, EstablishNetworkError> {
        debug!("📤 Sending address confirmation for channel {channel_id} to peer {peer_id}");

        let request = EstablishRequest::confirm_address(channel_id.clone(), address);
        let response = self.send_establish_request(peer_id, request).await?;

        match response {
            EstablishResponse::AddressConfirmed(payload) => {
                if payload.confirmed {
                    info!("📍 Address confirmed for channel {channel_id}");
                } else {
                    warn!("⚠️ Address mismatch for channel {channel_id}");
                }
                Ok(payload.confirmed)
            }
            EstablishResponse::Error(e) => Err(EstablishNetworkError::ProtocolError(e.to_string())),
            other => Err(EstablishNetworkError::UnexpectedResponse(format!("{other}"))),
        }
    }

    async fn send_split_secrets(
        &self,
        peer_id: PeerId,
        channel_id: &ChannelId,
        secrets: MultisigSplitSecrets,
    ) -> Result<MultisigSplitSecretsResponse, EstablishNetworkError> {
        debug!("📤 Sending split secrets for channel {channel_id} to peer {peer_id}");

        let request = EstablishRequest::split_secrets(channel_id.clone(), secrets);
        let response = self.send_establish_request(peer_id, request).await?;

        match response {
            EstablishResponse::SplitSecrets(payload) => {
                info!("🔒 Split secrets exchanged for channel {channel_id}");
                Ok(payload.secrets)
            }
            EstablishResponse::Error(e) => Err(EstablishNetworkError::ProtocolError(e.to_string())),
            other => Err(EstablishNetworkError::UnexpectedResponse(format!("{other}"))),
        }
    }

    async fn send_proof0(
        &self,
        peer_id: PeerId,
        channel_id: &ChannelId,
        proof: PublicProof0,
    ) -> Result<PublicProof0, EstablishNetworkError> {
        debug!("📤 Sending proof0 for channel {channel_id} to peer {peer_id}");

        let request = EstablishRequest::proof0(channel_id.clone(), proof);
        let response = self.send_establish_request(peer_id, request).await?;

        match response {
            EstablishResponse::Proof0(payload) => {
                info!("📜 Proof0 exchanged for channel {channel_id}");
                Ok(payload.proof)
            }
            EstablishResponse::Error(e) => Err(EstablishNetworkError::ProtocolError(e.to_string())),
            other => Err(EstablishNetworkError::UnexpectedResponse(format!("{other}"))),
        }
    }
}

// ============================================================================
// UpdateNetworkAPI implementation
// ============================================================================

#[async_trait]
impl UpdateNetworkAPI for NetworkClientV2 {
    async fn send_prepare_update(
        &self,
        peer_id: PeerId,
        channel_id: &ChannelId,
        update_count: u64,
        delta: MoneroDelta,
        prepare_info: Vec<u8>,
    ) -> Result<UpdatePreparedPayload, UpdateNetworkError> {
        debug!("📤 Sending prepare update #{update_count} for channel {channel_id} to peer {peer_id}");

        let request = UpdateRequest::prepare(channel_id.clone(), update_count, delta, prepare_info);
        let response = self.send_update_request(peer_id, request).await?;

        match response {
            UpdateResponse::Prepared(payload) => {
                info!("📝 Update #{update_count} prepared for channel {channel_id}");
                Ok(payload)
            }
            UpdateResponse::Error(e) => Err(UpdateNetworkError::ProtocolError(e.to_string())),
            other => Err(UpdateNetworkError::UnexpectedResponse(format!("{other}"))),
        }
    }

    async fn send_commit_update(
        &self,
        peer_id: PeerId,
        channel_id: &ChannelId,
        update_count: u64,
        proof: PublicUpdateProof,
        adapted_sig: AdaptSig,
    ) -> Result<FinalizedUpdate, UpdateNetworkError> {
        debug!("📤 Sending commit update #{update_count} for channel {channel_id} to peer {peer_id}");

        let request = UpdateRequest::commit(channel_id.clone(), update_count, proof, adapted_sig);
        let response = self.send_update_request(peer_id, request).await?;

        match response {
            UpdateResponse::Committed(payload) => {
                info!("✅ Update #{update_count} committed for channel {channel_id}");
                Ok(payload.finalized)
            }
            UpdateResponse::Error(e) => Err(UpdateNetworkError::ProtocolError(e.to_string())),
            other => Err(UpdateNetworkError::UnexpectedResponse(format!("{other}"))),
        }
    }
}

// ============================================================================
// CloseNetworkAPI implementation
// ============================================================================

#[async_trait]
impl CloseNetworkAPI for NetworkClientV2 {
    async fn send_close_request(
        &self,
        peer_id: PeerId,
        channel_id: &ChannelId,
        close_record: ChannelCloseRecord,
    ) -> Result<ChannelCloseRecord, CloseNetworkError> {
        debug!("📤 Sending close request for channel {channel_id} to peer {peer_id}");

        let request = CloseRequest::request_close(channel_id.clone(), close_record);
        let response = self.send_close_request_internal(peer_id, request).await?;

        match response {
            CloseResponse::CloseAccepted(payload) => {
                info!("🔐 Close accepted for channel {channel_id}");
                Ok(payload.close_record)
            }
            CloseResponse::Error(e) => Err(CloseNetworkError::ProtocolError(e.to_string())),
            other => Err(CloseNetworkError::UnexpectedResponse(format!("{other}"))),
        }
    }

    async fn send_closing_tx_broadcast(
        &self,
        peer_id: PeerId,
        channel_id: &ChannelId,
        tx_id: TransactionId,
    ) -> Result<bool, CloseNetworkError> {
        debug!("📤 Sending closing tx broadcast for channel {channel_id} to peer {peer_id}");

        let request = CloseRequest::closing_tx_broadcast(channel_id.clone(), tx_id);
        let response = self.send_close_request_internal(peer_id, request).await?;

        match response {
            CloseResponse::ClosingTxAcknowledged(payload) => {
                if payload.success {
                    info!("✅ Closing tx acknowledged for channel {channel_id}");
                } else {
                    warn!("⚠️ Closing tx acknowledgment failed for channel {channel_id}");
                }
                Ok(payload.success)
            }
            CloseResponse::Error(e) => Err(CloseNetworkError::ProtocolError(e.to_string())),
            other => Err(CloseNetworkError::UnexpectedResponse(format!("{other}"))),
        }
    }
}

impl NetworkClientV2 {
    /// Internal method to avoid name collision with trait method.
    async fn send_close_request_internal(
        &self,
        peer_id: PeerId,
        request: CloseRequest,
    ) -> Result<CloseResponse, CloseNetworkError> {
        let (sender, receiver) = oneshot::channel();
        let cmd = ProtocolCommandV2::SendCloseRequest { peer_id, request, sender };

        self.sender
            .clone()
            .send(NetworkCommand::ProtocolV2(cmd))
            .await
            .map_err(|e| CloseNetworkError::Internal(format!("Failed to send command: {e}")))?;

        receiver
            .await
            .map_err(|_| CloseNetworkError::Internal("Response channel closed".into()))?
            .map_err(|e| CloseNetworkError::ConnectionFailed(e.to_string()))
    }
}
