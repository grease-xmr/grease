//! Protocol-specific network behaviour and handler configuration.
//!
//! This module defines the application-level network behaviour for Grease, bridging the
//! low-level networking infrastructure in [`crate::p2p_networking`] with protocol-specific
//! message types and handlers.
//!
//! # Overview
//!
//! The module provides:
//!
//! - [`ConnectionBehavior`]: The libp2p `NetworkBehaviour` implementation that composes all
//!   supported protocols (identify, Grease request-response, etc.).
//!
//! - [`RequestResponseHandlers`]: A container managing handlers for each protocol, responsible for
//!   dispatching events and processing commands.
//!
//! - [`ProtocolCommand`]: An enum of protocol-specific commands that can be sent to the
//!   event loop for execution.
//!
//! # Adding New Protocols
//!
//! To add a new protocol (e.g., KES key exchange):
//!
//! 1. Add a `json::Behaviour<Req, Resp>` field to [`ConnectionBehavior`]
//! 2. Create a type alias for the handler (e.g., `KesHandler`)
//! 3. Add the handler field to [`RequestResponseHandlers`]
//! 4. Initialise the handler in [`RequestResponseHandlers::new()`]
//! 5. Add a dispatch arm in [`RequestResponseHandlers::dispatch_event()`]
//! 6. Add command variants to [`ProtocolCommand`]
//! 7. Handle the commands in [`RequestResponseHandlers::handle_command()`]
//!
//! # Separation of Concerns
//!
//! This module is the **extension point** for adding new protocols. Generic networking
//! infrastructure (event loop, async wrappers, etc.) lives in [`crate::p2p_networking`]
//! and should not be modified when adding protocols.

use futures::channel::{mpsc, oneshot};
use libp2p::identify::Event as IdentifyEvent;
use libp2p::request_response::{json, ResponseChannel};
use libp2p::swarm::NetworkBehaviour;
use libp2p::{identify, PeerId};
use log::*;

use crate::errors::RemoteServerError;
use crate::grease::{GreaseRequest, GreaseResponse};
use crate::p2p_networking::{
    AsyncAPI, AsyncReqResponseHandler, InboundForwarder, PendingRequests, RemoteRequest, RequestResponseHandler,
};

/// Network behavior with protocol-specific request-response handlers.
///
/// Each protocol (Grease, KES, etc.) has its own `json::Behaviour` field.
/// The `#[derive(NetworkBehaviour)]` macro generates a `ConnectionBehaviorEvent` enum
/// with variants for each behavior field.
#[derive(NetworkBehaviour)]
pub struct ConnectionBehavior {
    pub(crate) identify: identify::Behaviour,
    pub(crate) grease: json::Behaviour<GreaseRequest, GreaseResponse>,
    // Future protocols: add new json::Behaviour fields here
    // pub(crate) kes: json::Behaviour<KesRequest, KesResponse>,
}

// ============================================================================
// Request-Response Handlers - All protocol-specific code below this line
// ============================================================================
//
// To add a new request-response protocol:
// 1. Add a `json::Behaviour<Req, Resp>` field to `ConnectionBehavior` above
// 2. Add a type alias for the handler below
// 3. Add a field to `RequestResponseHandlers`
// 4. Add initialization in `RequestResponseHandlers::new()`
// 5. Add dispatch arm in `RequestResponseHandlers::dispatch_event()`
// 6. Add variants to `ProtocolCommand`
// 7. Add handling in `RequestResponseHandlers::handle_command()`

/// Type alias for the Grease protocol handler.
pub type GreaseHandler =
    AsyncReqResponseHandler<InboundForwarder<GreaseRequest, GreaseResponse>, PendingRequests<GreaseResponse>>;
// Future protocols: add type aliases here
// pub type KesHandler = AsyncReqResponseHandler<InboundForwarder<KesRequest, KesResponse>, PendingRequests<KesResponse>>;

/// Container for all request-response handlers.
///
/// This struct centralizes request-response handling for all message types (Grease, KES, etc.),
/// allowing `EventLoop` to remain protocol-agnostic. Adding a new request-response protocol
/// only requires changes to this file.
pub struct RequestResponseHandlers {
    grease: GreaseHandler,
    // Future protocols: add handler fields here
    // kes: KesHandler,
}

impl RequestResponseHandlers {
    /// Create new request-response handlers with the given inbound request forwarders.
    pub fn new(
        grease_inbound_tx: mpsc::Sender<RemoteRequest<GreaseRequest, GreaseResponse>>,
        // Future protocols: add parameters here
        // kes_inbound_tx: mpsc::Sender<RemoteRequest<KesRequest, KesResponse>>,
    ) -> Self {
        Self {
            grease: AsyncReqResponseHandler::new(InboundForwarder::new(grease_inbound_tx), PendingRequests::new()),
            // Future protocols: add initialization here
            // kes: AsyncReqResponseHandler::new(
            //     InboundForwarder::new(kes_inbound_tx),
            //     PendingRequests::new(),
            // ),
        }
    }

    /// Dispatch a behavior event to the appropriate handler.
    ///
    /// All protocol events (including identify) are handled here.
    pub async fn dispatch_event(&mut self, event: ConnectionBehaviorEvent) {
        match event {
            ConnectionBehaviorEvent::Identify(ev) => self.handle_identify_event(ev),
            ConnectionBehaviorEvent::Grease(ev) => {
                self.grease.handle_event(ev).await;
            } // Future protocols: add dispatch arms here
              // ConnectionBehaviorEvent::Kes(ev) => {
              //     self.kes.handle_event(ev).await;
              // }
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
    /// This method handles sending requests and responses for all protocols.
    /// It takes a mutable reference to the behavior to send messages via the swarm.
    pub fn handle_command(&mut self, command: ProtocolCommand, behavior: &mut ConnectionBehavior) {
        match command {
            ProtocolCommand::SendGreaseRequest { peer_id, request, sender } => {
                let request_id = behavior.grease.send_request(&peer_id, request);
                self.grease.register_pending_request(request_id, sender);
            }
            ProtocolCommand::SendGreaseResponse { response, channel } => {
                if let Err(resp) = behavior.grease.send_response(channel, response) {
                    error!("Failed to send Grease response: {resp}");
                }
            } // Future protocols: add command handling here
              // ProtocolCommand::SendKesRequest { peer_id, request, sender } => {
              //     let request_id = behavior.kes.send_request(&peer_id, request);
              //     self.kes.register_pending_request(request_id, sender);
              // }
              // ProtocolCommand::SendKesResponse { response, channel } => {
              //     if let Err(resp) = behavior.kes.send_response(channel, response) {
              //         error!("Failed to send Kes response: {resp}");
              //     }
              // }
        }
    }
}

/// Commands for sending requests and responses via the request-response protocols.
///
/// These commands are handled by [`RequestResponseHandlers::handle_command()`].
#[derive(Debug)]
pub enum ProtocolCommand {
    /// Send a Grease protocol request.
    SendGreaseRequest {
        peer_id: PeerId,
        request: GreaseRequest,
        sender: oneshot::Sender<Result<GreaseResponse, RemoteServerError>>,
    },
    /// Send a Grease protocol response.
    SendGreaseResponse { response: GreaseResponse, channel: ResponseChannel<GreaseResponse> },
    // Future protocols: add command variants here
    // SendKesRequest { peer_id: PeerId, request: KesRequest, sender: oneshot::Sender<Result<KesResponse, RemoteServerError>> },
    // SendKesResponse { response: KesResponse, channel: ResponseChannel<KesResponse> },
}
