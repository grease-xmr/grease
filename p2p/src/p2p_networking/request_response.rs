//! Request-response protocol handler trait.
//!
//! This module defines the [`RequestResponseHandler`] trait, which provides a consistent approach to handling libp2p's
//! request-response messages for _different_ classes of messages (Grease, KES, JSON-RPC etc.).
//!
//! # Usage
//!
//! Implement this trait to process incoming requests and responses for your message types.
//! Only [`on_message`](RequestResponseHandler::on_message) is required; default implementations
//! for error callbacks log warnings and can be overridden as needed.
//!
//! ```ignore
//! #[async_trait]
//! impl RequestResponseHandler for MyHandler {
//!     type Request = MyRequest;
//!     type Response = MyResponse;
//!
//!     async fn on_message(&mut self, peer: PeerId, conn_id: ConnectionId, message: Message<..>) {
//!         // Handle incoming requests and responses
//!     }
//! }
//! ```
//!
//! # Event Flow
//!
//! The [`handle_event`](RequestResponseHandler::handle_event) method dispatches libp2p events
//! to the appropriate callback:
//!
//! - `Message` → [`on_message`](RequestResponseHandler::on_message)
//! - `InboundFailure` → [`on_inbound_failure`](RequestResponseHandler::on_inbound_failure)
//! - `ResponseSent` → [`on_response_sent`](RequestResponseHandler::on_response_sent)
//! - `OutboundFailure` → [`on_outbound_failure`](RequestResponseHandler::on_outbound_failure)

use async_trait::async_trait;
use libp2p::request_response::{InboundFailure, InboundRequestId, Message, OutboundFailure, OutboundRequestId};
use libp2p::swarm::ConnectionId;
use libp2p::{request_response, PeerId};
use log::{trace, warn};
use serde::de::DeserializeOwned;
use serde::Serialize;

/// Trait for handling JSON request-response messages in libp2p.
#[async_trait]
pub trait RequestResponseHandler {
    type Request: DeserializeOwned + Serialize + Send + 'static;
    type Response: DeserializeOwned + Serialize + Send + 'static;

    /// Dispatch a request-response event to the appropriate handler method.
    ///
    /// This default implementation routes events to [`on_message`](Self::on_message),
    /// [`on_inbound_failure`](Self::on_inbound_failure), [`on_response_sent`](Self::on_response_sent),
    /// or [`on_outbound_failure`](Self::on_outbound_failure) based on event type.
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
