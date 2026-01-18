//! Protocol-specific network behavior for Grease v2.
//!
//! This module defines the v2 network behavior with separate `libp2p` request-response
//! behaviors for each protocol phase: proposal, establish, update, and close.
//!
//! # Benefits of Separate Behaviors
//!
//! - Type safety: Can't accidentally send EstablishRequest on Update channel
//! - Independent backpressure handling per protocol
//! - Cleaner coordinator implementations
//! - Easier to add new protocols
//!
//! # Architecture
//!
//! ```text
//! ConnectionBehaviorV2
//! ├── identify: identify::Behaviour
//! ├── proposal: json::Behaviour<ProposalRequest, ProposalResponse>
//! ├── establish: json::Behaviour<EstablishRequest, EstablishResponse>
//! ├── update: json::Behaviour<UpdateRequest, UpdateResponse>
//! └── close: json::Behaviour<CloseRequest, CloseResponse>
//! ```

use futures::channel::{mpsc, oneshot};
use libp2p::identify::Event as IdentifyEvent;
use libp2p::request_response::{json, ResponseChannel};
use libp2p::swarm::NetworkBehaviour;
use libp2p::{identify, PeerId};
use log::*;

use crate::errors::RemoteServerError;
use crate::grease_v2::messages::{
    CloseRequest, CloseResponse, EstablishRequest, EstablishResponse, ProposalRequest, ProposalResponse, UpdateRequest,
    UpdateResponse,
};
use crate::p2p_networking::{
    AsyncAPI, AsyncReqResponseHandler, InboundForwarder, PendingRequests, RemoteRequest, RequestResponseHandler,
};

// ============================================================================
// Network Behavior
// ============================================================================

/// Network behavior with separate request-response handlers per protocol phase.
///
/// The `#[derive(NetworkBehaviour)]` macro generates a `ConnectionBehaviorV2Event` enum
/// with variants for each behavior field.
#[derive(NetworkBehaviour)]
pub struct ConnectionBehaviorV2 {
    pub(crate) identify: identify::Behaviour,
    pub(crate) proposal: json::Behaviour<ProposalRequest, ProposalResponse>,
    pub(crate) establish: json::Behaviour<EstablishRequest, EstablishResponse>,
    pub(crate) update: json::Behaviour<UpdateRequest, UpdateResponse>,
    pub(crate) close: json::Behaviour<CloseRequest, CloseResponse>,
}

// ============================================================================
// Handler Type Aliases
// ============================================================================

/// Handler for proposal protocol messages.
pub type ProposalHandler =
    AsyncReqResponseHandler<InboundForwarder<ProposalRequest, ProposalResponse>, PendingRequests<ProposalResponse>>;

/// Handler for establish protocol messages.
pub type EstablishHandler =
    AsyncReqResponseHandler<InboundForwarder<EstablishRequest, EstablishResponse>, PendingRequests<EstablishResponse>>;

/// Handler for update protocol messages.
pub type UpdateHandler =
    AsyncReqResponseHandler<InboundForwarder<UpdateRequest, UpdateResponse>, PendingRequests<UpdateResponse>>;

/// Handler for close protocol messages.
pub type CloseHandler =
    AsyncReqResponseHandler<InboundForwarder<CloseRequest, CloseResponse>, PendingRequests<CloseResponse>>;

// ============================================================================
// Request-Response Handlers Container
// ============================================================================

/// Container for all v2 request-response handlers.
///
/// Centralizes request-response handling for all protocol phases, allowing the
/// `EventLoop` to remain protocol-agnostic.
pub struct RequestResponseHandlersV2 {
    proposal: ProposalHandler,
    establish: EstablishHandler,
    update: UpdateHandler,
    close: CloseHandler,
}

impl RequestResponseHandlersV2 {
    /// Create new handlers with the given inbound request forwarders.
    pub fn new(
        proposal_tx: mpsc::Sender<RemoteRequest<ProposalRequest, ProposalResponse>>,
        establish_tx: mpsc::Sender<RemoteRequest<EstablishRequest, EstablishResponse>>,
        update_tx: mpsc::Sender<RemoteRequest<UpdateRequest, UpdateResponse>>,
        close_tx: mpsc::Sender<RemoteRequest<CloseRequest, CloseResponse>>,
    ) -> Self {
        Self {
            proposal: AsyncReqResponseHandler::new(InboundForwarder::new(proposal_tx), PendingRequests::new()),
            establish: AsyncReqResponseHandler::new(InboundForwarder::new(establish_tx), PendingRequests::new()),
            update: AsyncReqResponseHandler::new(InboundForwarder::new(update_tx), PendingRequests::new()),
            close: AsyncReqResponseHandler::new(InboundForwarder::new(close_tx), PendingRequests::new()),
        }
    }

    /// Dispatch a behavior event to the appropriate handler.
    pub async fn dispatch_event(&mut self, event: ConnectionBehaviorV2Event) {
        match event {
            ConnectionBehaviorV2Event::Identify(ev) => self.handle_identify_event(ev),
            ConnectionBehaviorV2Event::Proposal(ev) => {
                self.proposal.handle_event(ev).await;
            }
            ConnectionBehaviorV2Event::Establish(ev) => {
                self.establish.handle_event(ev).await;
            }
            ConnectionBehaviorV2Event::Update(ev) => {
                self.update.handle_event(ev).await;
            }
            ConnectionBehaviorV2Event::Close(ev) => {
                self.close.handle_event(ev).await;
            }
        }
    }

    /// Handle identify protocol events.
    fn handle_identify_event(&self, event: IdentifyEvent) {
        match event {
            IdentifyEvent::Sent { peer_id, .. } => {
                info!("Sent identify info to {peer_id:?}");
            }
            IdentifyEvent::Received { peer_id, info, .. } => {
                info!("Received identify info from {peer_id:?}: {info:?}");
            }
            IdentifyEvent::Error { peer_id, error, connection_id } => {
                error!("Identify error with {peer_id:?} #{connection_id}: {error}");
            }
            IdentifyEvent::Pushed { connection_id, peer_id, info } => {
                info!("Identify info pushed to {peer_id:?} #{connection_id}");
                debug!("Identify info: {info:?}");
            }
        }
    }

    /// Handle a protocol-specific command.
    ///
    /// Routes commands to the appropriate behavior and tracks pending requests.
    pub fn handle_command(&mut self, command: ProtocolCommandV2, behavior: &mut ConnectionBehaviorV2) {
        match command {
            // Proposal
            ProtocolCommandV2::SendProposalRequest { peer_id, request, sender } => {
                let request_id = behavior.proposal.send_request(&peer_id, request);
                self.proposal.register_pending_request(request_id, sender);
            }
            ProtocolCommandV2::SendProposalResponse { response, channel } => {
                if let Err(resp) = behavior.proposal.send_response(channel, response) {
                    error!("Failed to send Proposal response: {resp:?}");
                }
            }
            // Establish
            ProtocolCommandV2::SendEstablishRequest { peer_id, request, sender } => {
                let request_id = behavior.establish.send_request(&peer_id, request);
                self.establish.register_pending_request(request_id, sender);
            }
            ProtocolCommandV2::SendEstablishResponse { response, channel } => {
                if let Err(resp) = behavior.establish.send_response(channel, response) {
                    error!("Failed to send Establish response: {resp:?}");
                }
            }
            // Update
            ProtocolCommandV2::SendUpdateRequest { peer_id, request, sender } => {
                let request_id = behavior.update.send_request(&peer_id, request);
                self.update.register_pending_request(request_id, sender);
            }
            ProtocolCommandV2::SendUpdateResponse { response, channel } => {
                if let Err(resp) = behavior.update.send_response(channel, response) {
                    error!("Failed to send Update response: {resp:?}");
                }
            }
            // Close
            ProtocolCommandV2::SendCloseRequest { peer_id, request, sender } => {
                let request_id = behavior.close.send_request(&peer_id, request);
                self.close.register_pending_request(request_id, sender);
            }
            ProtocolCommandV2::SendCloseResponse { response, channel } => {
                if let Err(resp) = behavior.close.send_response(channel, response) {
                    error!("Failed to send Close response: {resp:?}");
                }
            }
        }
    }
}

// ============================================================================
// Protocol Commands
// ============================================================================

/// Commands for sending requests and responses via the v2 protocols.
///
/// Each protocol phase has its own request/response command variants.
#[derive(Debug)]
pub enum ProtocolCommandV2 {
    // Proposal protocol
    /// Send a proposal request to a peer.
    SendProposalRequest {
        peer_id: PeerId,
        request: ProposalRequest,
        sender: oneshot::Sender<Result<ProposalResponse, RemoteServerError>>,
    },
    /// Send a proposal response to a peer.
    SendProposalResponse { response: ProposalResponse, channel: ResponseChannel<ProposalResponse> },

    // Establish protocol
    /// Send an establish request to a peer.
    SendEstablishRequest {
        peer_id: PeerId,
        request: EstablishRequest,
        sender: oneshot::Sender<Result<EstablishResponse, RemoteServerError>>,
    },
    /// Send an establish response to a peer.
    SendEstablishResponse { response: EstablishResponse, channel: ResponseChannel<EstablishResponse> },

    // Update protocol
    /// Send an update request to a peer.
    SendUpdateRequest {
        peer_id: PeerId,
        request: UpdateRequest,
        sender: oneshot::Sender<Result<UpdateResponse, RemoteServerError>>,
    },
    /// Send an update response to a peer.
    SendUpdateResponse { response: UpdateResponse, channel: ResponseChannel<UpdateResponse> },

    // Close protocol
    /// Send a close request to a peer.
    SendCloseRequest {
        peer_id: PeerId,
        request: CloseRequest,
        sender: oneshot::Sender<Result<CloseResponse, RemoteServerError>>,
    },
    /// Send a close response to a peer.
    SendCloseResponse { response: CloseResponse, channel: ResponseChannel<CloseResponse> },
}
