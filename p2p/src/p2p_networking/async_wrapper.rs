//! Async/await bridge for request-response protocols.
//!
//! This module provides types for bridging libp2p's event-driven request-response
//! patterns with async/await APIs:
//!
//! - [`PendingRequests`]: Tracks pending outbound requests with oneshot channels
//! - [`InboundForwarder`]: Forwards inbound requests to an mpsc channel
//! - [`AsyncReqResponseHandler`]: Wraps a handler with async pending request management

use async_trait::async_trait;

use crate::errors::RemoteServerError;
use crate::p2p_networking::event_loop::RemoteRequest;
use crate::p2p_networking::request_response::RequestResponseHandler;
use futures::channel::{mpsc, oneshot};
use futures::SinkExt;
use libp2p::request_response::{InboundFailure, InboundRequestId, Message, OutboundFailure, OutboundRequestId};
use libp2p::swarm::ConnectionId;
use libp2p::PeerId;
use log::*;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::collections::HashMap;
use std::fmt::Display;

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
    /// Remove and return a pending request's response sender.
    ///
    /// Returns `None` if no request with the given ID was registered.
    fn remove_pending_request(
        &mut self,
        request_id: OutboundRequestId,
    ) -> Option<oneshot::Sender<Result<Resp, RemoteServerError>>>;
}

/// Tracks pending outbound requests awaiting responses.
///
/// This is a simple implementation of [`AsyncAPI`] that stores pending requests
/// in a `HashMap` and provides methods to register and remove them.
pub struct PendingRequests<Resp> {
    pending: HashMap<OutboundRequestId, oneshot::Sender<Result<Resp, RemoteServerError>>>,
}

impl<Resp> Default for PendingRequests<Resp> {
    fn default() -> Self {
        Self::new()
    }
}

impl<Resp> PendingRequests<Resp> {
    /// Create a new empty `PendingRequests`.
    pub fn new() -> Self {
        Self { pending: HashMap::new() }
    }
}

impl<Resp> AsyncAPI<Resp> for PendingRequests<Resp> {
    fn register_pending_request(
        &mut self,
        request_id: OutboundRequestId,
        sender: oneshot::Sender<Result<Resp, RemoteServerError>>,
    ) {
        self.pending.insert(request_id, sender);
    }

    fn remove_pending_request(
        &mut self,
        request_id: OutboundRequestId,
    ) -> Option<oneshot::Sender<Result<Resp, RemoteServerError>>> {
        self.pending.remove(&request_id)
    }
}

/// A simple handler that forwards inbound requests to an mpsc channel.
///
/// This implements [`RequestResponseHandler`] and forwards all inbound requests
/// to the application layer via an mpsc channel. Responses are not handled here
/// (they should be handled by [`AsyncReqResponseHandler`] wrapping this handler).
pub struct InboundForwarder<Req, Resp>
where
    Req: DeserializeOwned + Serialize + Send + 'static,
    Resp: DeserializeOwned + Serialize + Send + 'static,
{
    /// Channel to forward inbound requests to application layer
    inbound_tx: mpsc::Sender<RemoteRequest<Req, Resp>>,
}

impl<Req, Resp> InboundForwarder<Req, Resp>
where
    Req: DeserializeOwned + Serialize + Send + 'static,
    Resp: DeserializeOwned + Serialize + Send + 'static,
{
    /// Create a new `InboundForwarder` with the given mpsc sender.
    pub fn new(inbound_tx: mpsc::Sender<RemoteRequest<Req, Resp>>) -> Self {
        Self { inbound_tx }
    }
}

#[async_trait]
impl<Req, Resp> RequestResponseHandler for InboundForwarder<Req, Resp>
where
    Req: DeserializeOwned + Serialize + Send + 'static,
    Resp: Display + DeserializeOwned + Serialize + Send + 'static,
{
    type Request = Req;
    type Response = Resp;

    async fn on_message(&mut self, peer: PeerId, _connection_id: ConnectionId, message: Message<Req, Resp>) {
        match message {
            Message::Request { request_id, request, channel } => {
                debug!("Inbound request received from {peer}. Request id: {request_id}");
                let remote_req = RemoteRequest::new(request, channel);
                if let Err(e) = self.inbound_tx.send(remote_req).await {
                    error!("Failed to forward inbound request from {peer}: {e}");
                }
            }
            Message::Response { request_id, .. } => {
                // Responses should be handled by AsyncReqResponseHandler, not here
                warn!("InboundForwarder received unexpected response. Peer: {peer}. Request id: {request_id}");
            }
        }
    }

    // Use default implementations for on_inbound_failure, on_response_sent, on_outbound_failure
}

/// Wraps a [`RequestResponseHandler`] with async pending request management.
///
/// This struct composes a handler with an [`AsyncAPI`] implementation to:
/// - Complete pending requests when responses arrive
/// - Notify pending requests of failures on outbound errors
///
/// The inner handler still receives all events for any additional processing.
pub struct AsyncReqResponseHandler<H, A>
where
    H: RequestResponseHandler,
    A: AsyncAPI<H::Response>,
{
    /// The async API for managing pending requests
    pub async_api: A,
    /// The inner handler that processes events
    pub handler: H,
}

impl<H, A> AsyncReqResponseHandler<H, A>
where
    H: RequestResponseHandler,
    A: AsyncAPI<H::Response>,
{
    /// Create a new `AsyncReqResponseHandler` wrapping the given handler and async API.
    pub fn new(handler: H, async_api: A) -> Self {
        Self { async_api, handler }
    }
}

#[async_trait]
impl<H, A> RequestResponseHandler for AsyncReqResponseHandler<H, A>
where
    H: RequestResponseHandler + Send,
    H::Request: DeserializeOwned + Serialize + Send + 'static,
    H::Response: Display + DeserializeOwned + Serialize + Send + 'static,
    A: AsyncAPI<H::Response> + Send,
{
    type Request = H::Request;
    type Response = H::Response;

    async fn on_message(
        &mut self,
        peer: PeerId,
        connection_id: ConnectionId,
        message: Message<Self::Request, Self::Response>,
    ) {
        // If this is a response, complete the pending request before delegating
        if let Message::Response { request_id, response } = message {
            match self.async_api.remove_pending_request(request_id) {
                Some(sender) => {
                    trace!("Completing pending request {request_id} from {peer}");
                    if sender.send(Ok(response)).is_err() {
                        warn!("Failed to send response to requester. Request id: {request_id}. Receiver dropped.");
                    }
                }
                None => {
                    warn!("We received response for an unregistered request. Peer: {peer}. Request id: {request_id}");
                }
            }
            // Don't delegate, as we've already handled the response
            return;
        }
        // For requests, delegate to the inner handler
        self.handler.on_message(peer, connection_id, message).await;
    }

    fn on_inbound_failure(
        &mut self,
        peer: PeerId,
        connection_id: ConnectionId,
        request_id: InboundRequestId,
        error: InboundFailure,
    ) {
        self.handler.on_inbound_failure(peer, connection_id, request_id, error);
    }

    fn on_response_sent(&mut self, peer: PeerId, connection_id: ConnectionId, request_id: InboundRequestId) {
        self.handler.on_response_sent(peer, connection_id, request_id);
    }

    fn on_outbound_failure(
        &mut self,
        peer: PeerId,
        conn_id: ConnectionId,
        request_id: OutboundRequestId,
        error: OutboundFailure,
    ) {
        // First notify the pending request of the failure
        if let Some(sender) = self.async_api.remove_pending_request(request_id) {
            if sender.send(Err(RemoteServerError::NetworkError)).is_err() {
                warn!("Failed to notify requester of outbound failure. Request id: {request_id}. Receiver dropped.");
            }
        }
        // Then delegate to the inner handler
        self.handler.on_outbound_failure(peer, conn_id, request_id, error);
    }
}

/// Implement `AsyncAPI` for `AsyncReqResponseHandler` by delegating to the inner async_api.
impl<H, A> AsyncAPI<H::Response> for AsyncReqResponseHandler<H, A>
where
    H: RequestResponseHandler,
    A: AsyncAPI<H::Response>,
{
    fn register_pending_request(
        &mut self,
        request_id: OutboundRequestId,
        sender: oneshot::Sender<Result<H::Response, RemoteServerError>>,
    ) {
        self.async_api.register_pending_request(request_id, sender);
    }

    fn remove_pending_request(
        &mut self,
        request_id: OutboundRequestId,
    ) -> Option<oneshot::Sender<Result<H::Response, RemoteServerError>>> {
        self.async_api.remove_pending_request(request_id)
    }
}
