use async_trait::async_trait;
use futures::channel::{mpsc, oneshot};
use libp2p::identify::Event as IdentifyEvent;
use libp2p::request_response::{
    json, InboundFailure, InboundRequestId, Message, OutboundFailure, OutboundRequestId, ResponseChannel,
};
use libp2p::swarm::{ConnectionId, NetworkBehaviour};
use libp2p::{identify, request_response, PeerId};
use log::*;
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::async_wrapper::{AsyncReqResponseHandler, InboundForwarder, PendingRequests};
use crate::errors::RemoteServerError;
use crate::event_loop::RemoteRequest;
use crate::grease::{GreaseRequest, GreaseResponse};

/// Network behavior with protocol-specific request-response handlers.
///
/// Each protocol (Grease, KES, etc.) has its own `json::Behaviour` field.
/// The `#[derive(NetworkBehaviour)]` macro generates a `ConnectionBehaviorEvent` enum
/// with variants for each behavior field.
///
/// To add a new protocol:
/// 1. Add a new `json::Behaviour<MyRequest, MyResponse>` field here
/// 2. Add a handler field in `EventLoop`
/// 3. Add a dispatch arm in `EventLoop::behaviour_event()`
#[derive(NetworkBehaviour)]
pub struct ConnectionBehavior {
    pub(crate) identify: identify::Behaviour,
    pub(crate) grease: json::Behaviour<GreaseRequest, GreaseResponse>,
    // Future protocols: add new json::Behaviour fields here
    // pub(crate) kes: json::Behaviour<KesRequest, KesResponse>,
}

/// Trait for handling JSON request-response messages in libp2p.
#[async_trait]
pub trait RequestResponseHandler {
    type Request: DeserializeOwned + Serialize + Send + 'static;
    type Response: DeserializeOwned + Serialize + Send + 'static;

    async fn handle_event(&mut self, event: request_response::Event<Self::Request, Self::Response>) {
        match event {
            request_response::Event::Message { peer, connection_id, message } => {
                self.on_message(peer, connection_id, message).await;
            }
            request_response::Event::InboundFailure { peer, connection_id, request_id, error } => {
                self.on_inbound_failure(peer, connection_id, request_id, error);
            }
            request_response::Event::ResponseSent { peer, connection_id, request_id } => {
                self.on_response_sent(peer, connection_id, request_id);
            }
            request_response::Event::OutboundFailure { peer, connection_id, request_id, error } => {
                self.on_outbound_failure(peer, connection_id, request_id, error);
            }
        }
    }

    /// Respond to a new request or response message from a network peer.
    async fn on_message(
        &mut self,
        peer: PeerId,
        connection_id: ConnectionId,
        message: Message<Self::Request, Self::Response>,
    );

    /// Handle a failed inbound request
    ///
    /// ## Parameters
    /// * `peer` - The peer from whom the request was received.
    /// * `connection_id` - Identifier of the connection that the request was received on.
    /// * `request_id` - The id of the failed request.
    /// * `error` - The error that happened.
    fn on_inbound_failure(
        &mut self,
        peer: PeerId,
        connection_id: ConnectionId,
        request_id: InboundRequestId,
        error: InboundFailure,
    ) {
        warn!("Inbound request failed. Peer: {peer}. Connection id: {connection_id}. Request id: {request_id}. Error: {error}");
    }

    /// This gets called when a response to an inbound request has been sent.
    /// When this event is received, the response has already been flushed on the underlying transport connection.
    ///
    /// ## Parameters
    /// * `peer` - The peer to whom the response was sent.
    /// * `connection_id` - Identifier of the connection that the response was sent on.
    /// * `request_id` - The id of the request for which the response was sent.
    fn on_response_sent(&mut self, peer: PeerId, connection_id: ConnectionId, request_id: InboundRequestId) {
        trace!("EVENT: Response sent. Peer: {peer}. Connection id: {connection_id}. Request id: {request_id}");
    }

    /// Handle a failed outbound request
    ///
    /// ## Parameters
    /// * `peer` - The peer to whom the request was sent.
    /// * `connection_id` - Identifier of the connection that the request was sent on.
    /// * `request_id` - The (local) ID of the failed request.
    /// * `error` - The error that happened.
    fn on_outbound_failure(
        &mut self,
        peer: PeerId,
        connection_id: ConnectionId,
        request_id: OutboundRequestId,
        error: OutboundFailure,
    ) {
        warn!("Outbound request failed. Peer: {peer}. Connection id: {connection_id}. Request id: {request_id}. Error: {error}");
    }
}

/// Trait for handlers that need async/await support with pending request tracking.
///
/// This allows EventLoop to register pending requests without knowing the internal
/// structure of the handler. Handlers that need to track pending outbound requests
/// should implement this trait.
pub trait AsyncAPI<Resp> {
    /// Register a pending outbound request.
    ///
    /// The sender will be used to complete the request when the response arrives
    /// (handled by the `RequestResponseHandler::on_message` implementation).
    fn register_pending_request(
        &mut self,
        request_id: OutboundRequestId,
        sender: oneshot::Sender<Result<Resp, RemoteServerError>>,
    );
    fn remove_pending_request(
        &mut self,
        request_id: OutboundRequestId,
    ) -> Option<oneshot::Sender<Result<Resp, RemoteServerError>>>;
}

// ============================================================================
// Protocol Handlers - All protocol-specific code below this line
// ============================================================================
//
// To add a new protocol:
// 1. Add a `json::Behaviour<Req, Resp>` field to `ConnectionBehavior` above
// 2. Add a type alias for the handler below
// 3. Add a field to `ProtocolHandlers`
// 4. Add initialization in `ProtocolHandlers::new()`
// 5. Add dispatch arm in `ProtocolHandlers::dispatch_event()`
// 6. Add variants to `ProtocolCommand`
// 7. Add handling in `ProtocolHandlers::handle_command()`

/// Type alias for the Grease protocol handler.
pub type GreaseHandler =
    AsyncReqResponseHandler<InboundForwarder<GreaseRequest, GreaseResponse>, PendingRequests<GreaseResponse>>;
// Future protocols: add type aliases here
// pub type KesHandler = AsyncReqResponseHandler<InboundForwarder<KesRequest, KesResponse>, PendingRequests<KesResponse>>;

/// Container for all protocol handlers.
///
/// This struct centralizes all protocol-specific handling, allowing `EventLoop`
/// to remain protocol-agnostic. Adding a new protocol only requires changes to
/// this file.
pub struct ProtocolHandlers {
    grease: GreaseHandler,
    // Future protocols: add handler fields here
    // kes: KesHandler,
}

impl ProtocolHandlers {
    /// Create new protocol handlers with the given inbound request forwarders.
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

/// Protocol-specific commands for sending requests and responses.
///
/// These commands are handled by `ProtocolHandlers::handle_command()`.
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
