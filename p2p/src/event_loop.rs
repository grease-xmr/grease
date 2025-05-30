//! The Grease P2P network event loop.
//!
//! See [`EventLoop`] for more information.

use crate::behaviour::ConnectionBehaviorEvent as Event;
use crate::errors::PeerConnectionError;
use crate::message_types::{ChannelProposalResult, RejectChannelProposal, RejectReason, RetryOptions};
use crate::{ClientCommand, GreaseRequest, GreaseResponse, PeerConnection, PeerConnectionEvent};
use futures::channel::{
    mpsc::{Receiver, Sender},
    oneshot,
};
use futures::{SinkExt, StreamExt};
use libgrease::crypto::traits::PublicKey;
use libgrease::monero::data_objects::{MessageEnvelope, MsKeyAndVssInfo, MultiSigInitInfo};
use libp2p::core::transport::ListenerId;
use libp2p::core::ConnectedPoint;
use libp2p::identify::Event as IdentifyEvent;
use libp2p::multiaddr::Protocol;
use libp2p::request_response::Event as BehaviourEvent;
use libp2p::request_response::{InboundFailure, InboundRequestId, Message, OutboundFailure, OutboundRequestId};
use libp2p::swarm::{ConnectionError, ConnectionId, DialError, ListenError, SwarmEvent};
use libp2p::{Multiaddr, PeerId, TransportError};
use log::*;
use std::any::Any;
use std::collections::{hash_map, HashMap, HashSet};
use std::io;
use std::num::NonZeroU32;
use std::sync::atomic::AtomicUsize;
use std::time::Duration;

pub type ReqResEvent<P> = BehaviourEvent<GreaseRequest<P>, GreaseResponse<P>>;
pub type EventMessage<P> = Message<GreaseRequest<P>, GreaseResponse<P>>;

const RUNNING: usize = 0;
const SHUTTING_DOWN: usize = 1;
const SHUTDOWN: usize = 2;

/// The main event loop handler for Grease p2p connections
///
/// The `EventLoop` handles network events and commands for the Grease p2p network communications. It responds to
/// events that are generated by the connection as well as commands that are received from remote peers.
///
/// The `EventLoop` ensures that network events are appropriately handled and commands are executed, maintaining the
/// state and connections of the p2p network.
///
/// **Important**: The `EventLoop` is only a data broker. It does not do any business or application logic itself.
///
/// ## Handling outbound requests to peers
///
/// If, in response to a command (e.g. via a call from [`crate::network_client::Client`], the event loop needs to
/// delegate a task to a peer on the network, the event loop:
///  * creates a new Request record via `self.swarm.behaviour_mut().json.send_request(&peer_id, cmd)`
///  * and stores the resulting request_id and one-shot sender channel in the appropriate data structure.
///    It can then return.
///
/// When the appropriate response is received from a peer, via a `Response` event, the event loop can then
/// * retrieve the stored return channel by using the request_id as a key,
/// * send the response via the one-shot sender channel
///
/// ## Handling inbound requests from peers
///
/// An inbound request will hit the event loop as a [`ReqResEvent::Message`] event. The event loop will then convert
/// this event into an [`PeerConnectionEvent::InboundRequest`] event, passing the request specifics _as well as_ the
/// network `ResponseChannel` instance to the application layer. `ResponseChannel` is a channel that libp2p uses to
/// track the response to a request.
///
/// The application layer carries out all the business logic and once it is done, it calls a suitable method on the
/// [`Client`] instance, which will handle the creation of the correct [`ClientCommand`], packaging the result
/// data and the `ResponseChannel` instance, and sending it to the event loop.
pub struct EventLoop<P: PublicKey + 'static> {
    swarm: PeerConnection<P>,
    command_receiver: Receiver<ClientCommand<P>>,
    event_sender: Sender<PeerConnectionEvent<P>>,
    pending_dial: HashMap<PeerId, oneshot::Sender<Result<(), PeerConnectionError>>>,
    pending_new_channel_proposals: HashMap<OutboundRequestId, oneshot::Sender<ChannelProposalResult<P>>>,
    pending_multisig_inits:
        HashMap<OutboundRequestId, oneshot::Sender<Result<MessageEnvelope<MultiSigInitInfo>, String>>>,
    pending_multisig_keys:
        HashMap<OutboundRequestId, oneshot::Sender<Result<MessageEnvelope<MsKeyAndVssInfo>, String>>>,
    pending_boolean_confirmations: HashMap<OutboundRequestId, oneshot::Sender<Result<MessageEnvelope<bool>, String>>>,
    pending_shutdown: Option<oneshot::Sender<bool>>,
    status: AtomicUsize,
    connections: HashSet<ConnectionId>,
}

impl<P: PublicKey + Send> EventLoop<P> {
    pub fn new(
        swarm: PeerConnection<P>,
        command_receiver: Receiver<ClientCommand<P>>,
        event_sender: Sender<PeerConnectionEvent<P>>,
    ) -> Self {
        Self {
            swarm,
            command_receiver,
            event_sender,
            pending_dial: Default::default(),
            pending_new_channel_proposals: Default::default(),
            pending_multisig_inits: Default::default(),
            pending_multisig_keys: Default::default(),
            pending_boolean_confirmations: Default::default(),
            pending_shutdown: None,
            status: AtomicUsize::new(RUNNING),
            connections: Default::default(),
        }
    }

    pub async fn run(mut self) {
        loop {
            tokio::select! {
                event = self.swarm.select_next_some() => self.handle_event(event).await,
                command = self.command_receiver.next() => match command {
                    Some(c) => self.handle_command(c).await,
                    // Command channel closed, thus shutting down the network event loop.
                    None=>  return,
                },
            }
            if self.status.load(std::sync::atomic::Ordering::SeqCst) == SHUTDOWN {
                info!("Event loop has shutdown gracefully.");
                if let Some(sender) = self.pending_shutdown.take() {
                    let _ = sender.send(true);
                }
                break;
            }
        }
    }

    pub fn is_running(&self) -> bool {
        self.status.load(std::sync::atomic::Ordering::SeqCst) == RUNNING
    }

    /// Main event handler.
    ///
    /// This function is called whenever a new event is received from the network.
    /// Both general network events ([SwarmEvent]) and specific events triggered by the payment channel state machine
    /// ([ReqResEvent]) are handled here.
    async fn handle_event(&mut self, event: SwarmEvent<Event<P>>) {
        match event {
            SwarmEvent::Behaviour(Event::Json(event)) => {
                self.handle_request_response_event(event).await;
            }
            SwarmEvent::Behaviour(Event::Identify(event)) => {
                self.handle_identify_event(event).await;
            }

            SwarmEvent::NewListenAddr { listener_id, address } => {
                self.on_new_listen_addr(listener_id, address);
            }
            SwarmEvent::IncomingConnection { connection_id, local_addr, send_back_addr } => {
                self.on_incoming_connection(connection_id, local_addr, send_back_addr);
            }
            SwarmEvent::ConnectionEstablished {
                peer_id,
                connection_id,
                endpoint,
                num_established,
                concurrent_dial_errors,
                established_in,
            } => {
                self.on_connection_established(
                    peer_id,
                    connection_id,
                    endpoint,
                    num_established,
                    concurrent_dial_errors,
                    established_in,
                );
            }
            SwarmEvent::ConnectionClosed { peer_id, connection_id, endpoint, num_established, cause } => {
                self.on_connection_closed(peer_id, connection_id, endpoint, num_established, cause);
            }
            SwarmEvent::OutgoingConnectionError { peer_id, connection_id, error } => {
                self.on_outgoing_connection_error(peer_id, connection_id, error);
            }
            SwarmEvent::IncomingConnectionError { connection_id, local_addr, send_back_addr, error } => {
                self.on_incoming_connection_error(connection_id, local_addr, send_back_addr, error);
            }
            SwarmEvent::Dialing { peer_id, connection_id } => {
                self.on_dialing_event(peer_id, connection_id);
            }
            SwarmEvent::ExpiredListenAddr { listener_id, address } => {
                self.on_expired_listen_addr(listener_id, address);
            }
            SwarmEvent::ListenerClosed { listener_id, addresses, reason } => {
                self.on_listener_closed(listener_id, addresses, reason);
            }
            SwarmEvent::ListenerError { listener_id, error } => {
                self.on_non_fatal_listener_error(listener_id, error);
            }
            SwarmEvent::NewExternalAddrCandidate { address } => {
                trace!("EVENT: New external address candidate: {address}");
            }
            SwarmEvent::ExternalAddrConfirmed { address } => {
                trace!("EVENT: External address confirmed: {address}");
            }
            SwarmEvent::ExternalAddrExpired { address } => {
                trace!("EVENT: External address expired: {address}");
            }
            SwarmEvent::NewExternalAddrOfPeer { peer_id, address } => {
                trace!("EVENT: New external address of peer: {peer_id} {address}");
            }
            ev => {
                trace!("Unknown and unhandled event: {:?}", ev.type_id());
            }
        }
    }

    async fn handle_request_response_event(&mut self, event: ReqResEvent<P>) {
        match event {
            ReqResEvent::Message { peer, connection_id, message } => {
                self.on_channel_message(peer, connection_id, message).await;
            }
            ReqResEvent::OutboundFailure { peer, connection_id, request_id, error } => {
                self.on_outbound_failure(peer, connection_id, request_id, error);
            }
            ReqResEvent::InboundFailure { peer, connection_id, request_id, error } => {
                self.on_inbound_failure(peer, connection_id, request_id, error);
            }
            ReqResEvent::ResponseSent { peer, connection_id, request_id } => {
                self.on_response_sent(peer, connection_id, request_id);
            }
        }
    }

    async fn handle_identify_event(&mut self, event: IdentifyEvent) {
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

    /// Respond to a new Request-Response Grease Channel message from the peer.
    async fn on_channel_message(&mut self, peer: PeerId, connection_id: ConnectionId, message: EventMessage<P>) {
        trace!("EVENT: Payment channel message received from {peer}. Connection id: {connection_id}.");
        match message {
            EventMessage::Request { request_id, request, channel } => {
                debug!("Request received. Peer: {peer}. Connection id: {connection_id}. Request id: {request_id}");
                self.event_sender
                    .send(PeerConnectionEvent::InboundRequest { request, response: channel })
                    .await
                    .expect("Event receiver not to be dropped.");
            }
            EventMessage::Response { request_id, response } => {
                trace!("EVENT: Response received. Peer: {peer}. Conn_id: {connection_id}. Req_id: {request_id}");
                match response {
                    GreaseResponse::ChannelProposalResult(result) => {
                        let pending = self.pending_new_channel_proposals.remove(&request_id);
                        let Some(sender) = pending else {
                            error!("Received response for unknown open channel request. Request id: {request_id}");
                            return;
                        };
                        let _ = sender.send(result);
                    }
                    GreaseResponse::MsInit(info) => {
                        let pending = self.pending_multisig_inits.remove(&request_id);
                        let Some(sender) = pending else {
                            error!("Received response for unknown multisig init request. Request id: {request_id}");
                            return;
                        };
                        let _ = sender.send(info);
                    }
                    GreaseResponse::MsKeyExchange(key) => {
                        let pending = self.pending_multisig_keys.remove(&request_id);
                        let Some(sender) = pending else {
                            error!(
                                "Received response for unknown multisig key exchange request. Request id: {request_id}"
                            );
                            return;
                        };
                        let _ = sender.send(key);
                    }
                    GreaseResponse::ConfirmMsAddress(confirmed) => {
                        let pending = self.pending_boolean_confirmations.remove(&request_id);
                        let Some(sender) = pending else {
                            error!("Received response for unknown multisig address confirmation request. Request id: {request_id}");
                            return;
                        };
                        let _ = sender.send(Ok(confirmed));
                    }
                    GreaseResponse::AcceptKes(accepted) => {
                        let pending = self.pending_boolean_confirmations.remove(&request_id);
                        let Some(sender) = pending else {
                            error!("Received response for unknown accept kes request. Request id: {request_id}");
                            return;
                        };
                        let _ = sender.send(Ok(accepted));
                    }
                    GreaseResponse::ChannelClosed => {}
                    GreaseResponse::ChannelNotFound => {}
                    GreaseResponse::Error(_) => {}
                }
            }
        }
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
        if let Some(sender) = self.pending_new_channel_proposals.remove(&request_id) {
            let reason = RejectReason::NotSent(format!("Outbound request failed. Error: {error}"));
            let response = RejectChannelProposal::new(reason, RetryOptions::close_only());
            if sender.send(ChannelProposalResult::Rejected(response)).is_err() {
                error!("Failed to send rejection response for request id: {request_id}.");
            }
        }
        if let Some(sender) = self.pending_multisig_inits.remove(&request_id) {
            let _ = sender.send(Err(format!("Outbound request failed: {error}")));
        }
        if let Some(sender) = self.pending_multisig_keys.remove(&request_id) {
            let _ = sender.send(Err(format!("Outbound request failed: {error}")));
        }
        if let Some(sender) = self.pending_boolean_confirmations.remove(&request_id) {
            let _ = sender.send(Err(format!("Outbound request failed: {error}")));
        }
    }

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

    /// Handle a failed connection attempt
    ///
    /// This gets called when an error happened on an outbound connection.
    ///
    /// ## Parameters
    /// * `peer_id` - Identity of the peer that we were trying to connect to, if it is known.
    /// * `connection_id` - Identifier of the connection that failed.
    /// * `error` - the dial error that happened.
    fn on_outgoing_connection_error(&mut self, peer_id: Option<PeerId>, connection_id: ConnectionId, error: DialError) {
        let peer_str = match peer_id {
            Some(peer_id) => peer_id.to_string(),
            None => "[unknown peer]".to_string(),
        };
        warn!("Connection to {peer_str} failed. Connection id: {connection_id}. Error: {error}");
        if let Some(peer_id) = peer_id {
            if let Some(sender) = self.pending_dial.remove(&peer_id) {
                let _ = sender.send(Err(PeerConnectionError::DialError(error)));
            }
        }
    }

    /// Handle a failed incoming connection
    ///
    /// This gets called when an error happened on an inbound connection during its initial handshake.
    /// This can include, for example, an error during the handshake of the encryption layer,
    /// or the connection unexpectedly closed.
    ///
    /// ## Parameters
    /// * `connection_id` - Identifier of the connection that failed.
    /// * `local_addr` - Local address that we were trying to listen on. This address has been earlier reported with
    ///         a [SwarmEvent::NewListenAddr] event.
    /// * `send_back_addr` - Address of the peer that we were trying to connect to.
    /// * `error` - the dial error that happened.
    fn on_incoming_connection_error(
        &mut self,
        connection_id: ConnectionId,
        local_addr: Multiaddr,
        send_back_addr: Multiaddr,
        error: ListenError,
    ) {
        warn!("Incoming connection failed. Connection id: {connection_id}. Local address: {local_addr}. Send back address: {send_back_addr}. Error: {error}");
    }

    /// Respond to a new connection
    ///
    /// This gets called when a connection to the given peer has been opened.
    ///
    /// ## Arguments
    /// * `peer_id` - Identity of the peer that we have connected to
    /// * `connection_id` - Identifier of the connection
    /// * `endpoint` - Endpoint of the connection that has been opened.
    /// * `num_established` - Number of established connections to this peer, including the one that has just been opened.
    /// * `concurrent_dial_errors` - [`Some`] when the new connection is an outgoing connection. Addresses are dialed
    ///         concurrently. Contains the addresses and errors of dial attempts that failed before
    ///         the one successful dial.
    fn on_connection_established(
        &mut self,
        peer_id: PeerId,
        connection_id: ConnectionId,
        endpoint: ConnectedPoint,
        num_established: NonZeroU32,
        concurrent_dial_errors: Option<Vec<(Multiaddr, TransportError<io::Error>)>>,
        established_in: Duration,
    ) {
        let ep_type = match endpoint {
            ConnectedPoint::Dialer { .. } => "dialer",
            ConnectedPoint::Listener { .. } => "listener",
        };
        info!("Connection to {peer_id} established as {ep_type} in {:0.3}s. Connection id: {connection_id}. {num_established} connections are active.", established_in.as_secs_f64());
        self.connections.insert(connection_id);
        if let Some(errs) = concurrent_dial_errors {
            if !errs.is_empty() {
                warn!("{} concurrent dial errors were reported for {peer_id}.", errs.len());
                errs.into_iter().for_each(|(addr, err)| {
                    debug!("Concurrent dial error for {peer_id}. Address: {addr}. Error: {err}");
                });
            }
        }
        if endpoint.is_dialer() {
            trace!("Letting client know dial was successful.");
            if let Some(sender) = self.pending_dial.remove(&peer_id) {
                let _ = sender.send(Ok(()));
            }
        }
    }

    /// Handle a new dial event
    ///
    /// A new dialing attempt has been initiated by the NetworkBehaviour implementation.
    /// A [SwarmEvent::ConnectionEstablished] event is reported if the dialing attempt succeeds,
    /// otherwise an [SwarmEvent::OutgoingConnectionError] event is reported.
    ///
    /// ## Parameters
    /// * `peer_id` - Identity of the peer that we are trying to connect to, if known.
    /// * `connection_id` - Identifier of the connection that is being dialed.
    fn on_dialing_event(&mut self, peer_id: Option<PeerId>, connection_id: ConnectionId) {
        let peer_str = match peer_id {
            Some(peer_id) => peer_id.to_string(),
            None => "[unknown peer]".to_string(),
        };
        info!("Dialing peer {peer_str}. Connection id: {connection_id}");
    }

    /// Respond to a connection being closed.
    ///
    /// This event fires when A connection with the given peer has been closed, possibly as a result of an error.
    ///
    /// ## Parameters
    /// * `peer_id` - Identity of the peer that we have connected to
    /// * `connection_id` - Identifier of the connection
    /// * `endpoint` - Endpoint of the connection that has been closed.
    /// * `num_established` - Number of other remaining connections to this same peer.
    /// * `cause` - [`Some`] if the connection was closed because of an error. Contains the error.
    fn on_connection_closed(
        &mut self,
        peer_id: PeerId,
        connection_id: ConnectionId,
        endpoint: ConnectedPoint,
        num_established: u32,
        cause: Option<ConnectionError>,
    ) {
        self.connections.remove(&connection_id);
        let endpoint_str = match endpoint {
            ConnectedPoint::Dialer { address, .. } => {
                let reason = match cause {
                    Some(e) => format!("Connection closed with error: {e}"),
                    None => "Connection closed gracefully".to_string(),
                };
                format!("We were dialer to {address}. Reason: {reason}")
            }
            ConnectedPoint::Listener { local_addr, send_back_addr } => {
                format!("We were listening on {local_addr}, and the remote peer connected from {send_back_addr}.")
            }
        };
        info!("Connection to {peer_id}/{connection_id} closed. {endpoint_str}. {num_established} connections remain.");
        if num_established == 0 && self.status.load(std::sync::atomic::Ordering::SeqCst) == SHUTTING_DOWN {
            self.status.store(SHUTDOWN, std::sync::atomic::Ordering::SeqCst);
        }
    }

    /// This gets called when one of our listeners has reported a new local listening address.
    ///
    /// ## Parameters
    /// * `listener_id` - Identifier of the listener that is now listening on the address.
    /// * `address` - Address that is now being listened on.
    fn on_new_listen_addr(&self, listener_id: ListenerId, address: Multiaddr) {
        let local_peer_id = *self.swarm.local_peer_id();
        info!(
            "Local node is listening on {:?} with id: {listener_id}",
            address.with(Protocol::P2p(local_peer_id))
        );
    }

    /// A new connection arrived on a listener and is in the process of protocol negotiation.
    ///
    /// A corresponding [`ConnectionEstablished`](SwarmEvent::ConnectionEstablished) or
    /// [`IncomingConnectionError`](SwarmEvent::IncomingConnectionError) event will later be generated for this
    /// connection.
    ///
    /// ## Parameters
    /// * `connection_id` - Identifier of the connection.
    /// * `local_addr` - Local address that received the connection.
    /// * `send_back_addr` - Address to which the connection is being sent back.
    fn on_incoming_connection(&self, connection_id: ConnectionId, local_addr: Multiaddr, send_back_addr: Multiaddr) {
        info!("Incoming connection. Connection id: {connection_id}. Local address: {local_addr}. Send back address: {send_back_addr}");
    }

    /// Responds when a listening address has expired.
    ///
    /// ## Parameters
    /// * `listener_id` - The listener that is no longer listening on the address.
    /// * `address` - Address that has expired.
    fn on_expired_listen_addr(&mut self, listener_id: ListenerId, address: Multiaddr) {
        trace!("EVENT: Expired listen address: {address} #{listener_id}");
    }

    /// Responds to a listener being closed.
    ///
    /// This gets called whn one of the listeners gracefully closed.
    ///
    /// ## Parameters
    /// * `listener_id` - Identifier of the listener that closed.
    /// * `addresses` - The addresses that the listener was listening on. These addresses are now considered
    ///                 expired, similar to if a [`ExpiredListenAddr`](SwarmEvent::ExpiredListenAddr) event
    ///                 has been generated for each of them.
    /// * `reason` - Reason for the listener being closed. Contains `Ok(())` if the stream produced `None`, or `Err`
    ///              if the stream produced an error.
    fn on_listener_closed(
        &mut self,
        listener_id: ListenerId,
        addresses: Vec<Multiaddr>,
        reason: Result<(), io::Error>,
    ) {
        let reason = match reason {
            Ok(()) => "gracefully",
            Err(e) => &format!("with error: {e}"),
        };
        trace!("EVENT: Listener {listener_id} closed {reason}.");
        let addresses = addresses.into_iter().map(|addr| format!("{addr}")).collect::<Vec<_>>();
        debug!("Connections closed: {}", addresses.join(","));
    }

    /// Responds to a non-fatal listener error.
    ///
    /// ## Parameters
    /// * `listener_id` - Identifier of the listener that produced the error.
    /// * `error` - The error that happened.
    fn on_non_fatal_listener_error(&mut self, listener_id: ListenerId, error: io::Error) {
        debug!("EVENT: Non-fatal listener error: {listener_id} Error: {error}");
    }

    async fn handle_command(&mut self, command: ClientCommand<P>) {
        if let Err(()) = self.command_handler(command).await {
            // Preserve the knowledge that the command was rejected.
            warn!("💡  A client command was not handled successfully – see logs above for details");
        }
    }
    async fn command_handler(&mut self, command: ClientCommand<P>) -> Result<(), ()> {
        match command {
            ClientCommand::StartListening { addr, sender } => {
                let sender = self.abort_if_shutting_down(sender, PeerConnectionError::EventLoopShuttingDown)?;
                let _ = match self.swarm.listen_on(addr) {
                    Ok(_) => sender.send(Ok(())),
                    Err(e) => sender.send(Err(PeerConnectionError::TransportError(e))),
                };
                Ok(())
            }
            ClientCommand::Dial { peer_id, peer_addr, sender } => {
                let sender = self.abort_if_shutting_down(sender, PeerConnectionError::EventLoopShuttingDown)?;
                if let hash_map::Entry::Vacant(e) = self.pending_dial.entry(peer_id) {
                    match self.swarm.dial(peer_addr.with(Protocol::P2p(peer_id))) {
                        Ok(()) => {
                            e.insert(sender);
                        }
                        Err(e) => {
                            let _ = sender.send(Err(PeerConnectionError::DialError(e)));
                        }
                    }
                } else {
                    debug!("Dialing already in progress for peer {peer_id}. Ignoring additional dial attempt.");
                }
                Ok(())
            }
            ClientCommand::ResponseToRequest { res, return_chute } => {
                if let Err(response) = self.swarm.behaviour_mut().json.send_response(return_chute, res) {
                    error!("Failed to send response to request. {response}");
                    // todo: retry logic
                }
                Ok(())
            }
            ClientCommand::ProposeChannelRequest { peer_id, data, sender } => {
                if !self.is_running() {
                    info!("Event loop is shutting down. I'm not going to start opening channels.");
                    let reason = RejectReason::NotSent("Event loop is shutting down.".to_string());
                    let rejection = RejectChannelProposal::new(reason, RetryOptions::close_only());
                    let _ = sender.send(ChannelProposalResult::Rejected(rejection));
                    return Err(());
                }
                let id = self.swarm.behaviour_mut().json.send_request(&peer_id, GreaseRequest::ProposeNewChannel(data));
                self.pending_new_channel_proposals.insert(id, sender);
                info!("New channel proposal sent to {peer_id}");
                Ok(())
            }
            ClientCommand::ConnectedPeers { sender } => {
                debug!("Connected peers requested.");
                let peers = self.swarm.connected_peers().cloned().collect();
                let _ = sender.send(peers);
                Ok(())
            }
            ClientCommand::Shutdown(sender) => {
                info!("Shutting down event loop.");
                self.status.store(SHUTTING_DOWN, std::sync::atomic::Ordering::SeqCst);
                self.pending_shutdown = Some(sender);
                let connections = self.connections.clone();
                for id in connections {
                    self.swarm.close_connection(id);
                }
                Ok(())
            }
            // MultiSig wallet prep commands
            ClientCommand::MultiSigInitRequest { peer_id, envelope, sender } => {
                let sender = self.abort_if_shutting_down(sender, "Event loop is shutting down.".to_string())?;
                let id = self.swarm.behaviour_mut().json.send_request(&peer_id, GreaseRequest::MsInit(envelope));
                self.pending_multisig_inits.insert(id, sender);
                Ok(())
            }
            ClientCommand::MultiSigKeyRequest { peer_id, envelope, sender } => {
                let sender = self.abort_if_shutting_down(sender, "Event loop is shutting down.".to_string())?;
                let id = self.swarm.behaviour_mut().json.send_request(&peer_id, GreaseRequest::MsKeyExchange(envelope));
                self.pending_multisig_keys.insert(id, sender);
                Ok(())
            }
            ClientCommand::ConfirmMultiSigAddressRequest { peer_id, envelope, sender } => {
                let sender = self.abort_if_shutting_down(sender, "Event loop is shutting down.".to_string())?;
                let id =
                    self.swarm.behaviour_mut().json.send_request(&peer_id, GreaseRequest::ConfirmMsAddress(envelope));
                self.pending_boolean_confirmations.insert(id, sender);
                Ok(())
            }
            ClientCommand::KesReadyNotification { peer_id, envelope, sender } => {
                let sender = self.abort_if_shutting_down(sender, "Event loop is shutting down.".to_string())?;
                let id = self.swarm.behaviour_mut().json.send_request(&peer_id, GreaseRequest::VerifyKes(envelope));
                self.pending_boolean_confirmations.insert(id, sender);
                Ok(())
            }
        }
    }

    fn abort_if_shutting_down<T, E>(
        &self,
        sender: oneshot::Sender<Result<T, E>>,
        err: E,
    ) -> Result<oneshot::Sender<Result<T, E>>, ()> {
        if !self.is_running() {
            info!("Event loop is shutting down. I'm not accepting any more instructions right now.");
            let _ = sender.send(Err(err));
            Err(())
        } else {
            Ok(sender)
        }
    }
}
