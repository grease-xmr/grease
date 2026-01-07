use super::message_types::{ChannelProposalResult, NewChannelMessage, PrepareUpdate, UpdateCommitted, UpdatePrepared};
use crate::behaviour::ConnectionBehavior;
use crate::errors::RemoteServerError;
use crate::event_loop::{ClientCommand, PeerConnectionError, RemoteRequest};
use crate::grease::{GreaseChannelEvents, GreaseRequest, GreaseResponse};
use futures::channel::{mpsc, oneshot};
use futures::SinkExt;
use futures::Stream;
use libgrease::cryptography::zk_objects::PublicProof0;
use libgrease::monero::data_objects::{
    FinalizedUpdate, MessageEnvelope, MultisigKeyInfo, MultisigSplitSecrets, MultisigSplitSecretsResponse,
    TransactionId,
};
use libgrease::state_machine::ChannelCloseRecord;
use libp2p::identity::Keypair;
use libp2p::multiaddr::Protocol;
use libp2p::request_response::ResponseChannel;
use libp2p::{
    identify, noise,
    request_response::{json, Config as RequestResponseConfig, ProtocolSupport},
    tcp, yamux, Multiaddr, PeerId, StreamProtocol,
};
use log::*;
use std::time::Duration;

pub type GreaseRemoteEvent = RemoteRequest<GreaseRequest, GreaseResponse>;

/// Creates the network components, namely:
///
/// - The network interface [`GreaseAPI`] to interact with the event loop from anywhere within your application.
/// - The network event stream, e.g. for incoming requests.
/// - The main business logic sits in the [`GreaseClient`], which responds to commands and messages delivered via the API and event stream.
pub fn new_network(
    key: Keypair,
) -> Result<(GreaseAPI, impl Stream<Item = GreaseRemoteEvent>, GreaseChannelEvents), PeerConnectionError> {
    let swarm = libp2p::SwarmBuilder::with_existing_identity(key)
        .with_tokio()
        .with_tcp(tcp::Config::default(), noise::Config::new, yamux::Config::default)?
        .with_behaviour(|key| {
            let config = identify::Config::new("/grease-channel/id/1".to_string(), key.public())
                .with_interval(Duration::from_secs(5 * 60));
            let identify = identify::Behaviour::new(config);
            let config = RequestResponseConfig::default()
                .with_request_timeout(Duration::from_secs(60))
                .with_max_concurrent_streams(2);
            let protocols = [(StreamProtocol::new("/grease-channel/comms/1"), ProtocolSupport::Full)];
            let json = json::Behaviour::new(protocols, config);
            ConnectionBehavior { identify, json }
        })?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();

    let (command_sender, command_receiver) = mpsc::channel(0);
    let (event_sender, event_receiver) = mpsc::channel(0);

    Ok((
        GreaseAPI { sender: command_sender },
        event_receiver,
        GreaseChannelEvents::new(swarm, command_receiver, event_sender),
    ))
}

/// A sender interface to the network event loop. It can be cheaply cloned and shared among threads and multiple sets
/// of peer-to-peer connections.
#[derive(Clone)]
pub struct GreaseAPI {
    sender: mpsc::Sender<ClientCommand<GreaseRequest, GreaseResponse>>,
}

/// Generates a method for taking a command-type interface, converting it to the appropriate GreaseRequest variant,
/// dispatching it, and then unwrapping the GreaseResponse variant into the appropriate response type.
macro_rules! enveloped_command {
    ($method_name:ident, $req_variant:path, $resp_variant:path, $request_payload: ty, $response_type:ty) => {
        pub async fn $method_name(
            &mut self,
            peer_id: PeerId,
            channel: &str,
            req: $request_payload,
        ) -> Result<$response_type, PeerConnectionError> {
            let envelope = MessageEnvelope::new(channel.into(), req);
            let request = $req_variant(envelope);
            let response = self.send_request(peer_id, request).await??;
            let envelope = match response {
                $resp_variant(envelope) => envelope,
                t => {
                    return Err(PeerConnectionError::unexpected_response(stringify!($resp_variant), t));
                }
            };
            let (return_channel, result) = envelope.open();
            if return_channel != channel {
                return Err(PeerConnectionError::unexpected_channel(channel, return_channel));
            }
            Ok(result)
        }
    };
}

/// An abstraction layer that sits between the main business logic of the application and the network ([`EventLoop`]).
///
/// The majority of the (async) methods in this struct follow the following pattern:
/// - A one-shot channel is created.
/// - An [`GreaseChannelCommand`] is sent to the [`EventLoop`] via the `sender` channel, containing the one-shot sender half.
/// - The method waits for the receiver half to receive its value, before returning it.
///
/// **Importantly**, this struct does not do any work.
/// It simply forwards the [`GreaseChannelCommand`]s to the [`EventLoop`] and waits for the results.
impl GreaseAPI {
    /// Listen for incoming connections on the given address.
    pub async fn start_listening(&mut self, addr: Multiaddr) -> Result<(), PeerConnectionError> {
        let (sender, receiver) = oneshot::channel();
        self.sender.send(ClientCommand::StartListening { addr, sender }).await?;
        receiver.await?
    }

    /// Dial the given peer at the given address.
    /// The peer id is extracted from the address, and therefore must be present.
    ///
    /// Valid examples:
    /// - /ip4/192.168.1.100/tcp/7740/p2p/QmZzv3sdlfkdlsdfd...
    /// - /dns4/example.com/tcp/443/p2p/QmZzv3sdlfkdlsdfd...
    pub async fn dial(&mut self, peer_addr: Multiaddr) -> Result<(), PeerConnectionError> {
        let peer_id = match peer_addr.iter().last() {
            Some(Protocol::P2p(p)) => p,
            _ => return Err(PeerConnectionError::MissingPeerId),
        };
        let (sender, receiver) = oneshot::channel();
        self.sender.send(ClientCommand::Dial { peer_id, peer_addr, sender }).await?;
        receiver.await?
    }

    pub async fn connected_peers(&mut self) -> Result<Vec<PeerId>, PeerConnectionError> {
        let (sender, receiver) = oneshot::channel();
        self.sender.send(ClientCommand::ConnectedPeers { sender }).await?;
        let peers = receiver.await?;
        Ok(peers)
    }

    pub async fn new_channel_proposal(
        &mut self,
        data: NewChannelMessage,
    ) -> Result<ChannelProposalResult, PeerConnectionError> {
        let peer_id = data.contact_info_merchant.peer_id;
        trace!("NetworkClient: Sending new channel proposal to peer {peer_id}");
        let req = GreaseRequest::ProposeChannelRequest(data);
        let open_result = self.send_request(peer_id, req).await??;
        match open_result {
            GreaseResponse::ProposeChannelResponse(result) => Ok(result),
            t => Err(PeerConnectionError::unexpected_response("ProposeChannelResponse", t)),
        }
    }

    async fn send_request(
        &mut self,
        peer_id: PeerId,
        req: GreaseRequest,
    ) -> Result<Result<GreaseResponse, RemoteServerError>, PeerConnectionError> {
        let (sender, receiver) = oneshot::channel();
        let request = Box::new(req);
        self.sender.send(ClientCommand::NewRequest { peer_id, request, sender }).await?;
        let response = receiver.await?;
        Ok(response)
    }

    enveloped_command!(
        send_multisig_key,
        GreaseRequest::MsKeyExchange,
        GreaseResponse::MsKeyExchange,
        MultisigKeyInfo,
        MultisigKeyInfo
    );
    enveloped_command!(
        send_split_secrets,
        GreaseRequest::MsSplitSecretExchange,
        GreaseResponse::MsSplitSecretExchange,
        MultisigSplitSecrets,
        MultisigSplitSecretsResponse
    );
    enveloped_command!(
        send_wallet_confirmation,
        GreaseRequest::ConfirmMsAddress,
        GreaseResponse::ConfirmMsAddress,
        String,
        bool
    );
    enveloped_command!(
        send_proof0,
        GreaseRequest::ExchangeProof0,
        GreaseResponse::ExchangeProof0,
        PublicProof0,
        PublicProof0
    );
    enveloped_command!(
        send_update_preparation,
        GreaseRequest::PrepareUpdate,
        GreaseResponse::UpdatePrepared,
        PrepareUpdate,
        UpdatePrepared
    );
    enveloped_command!(
        send_update_commitment,
        GreaseRequest::CommitUpdate,
        GreaseResponse::UpdateCommitted,
        UpdateCommitted,
        FinalizedUpdate
    );
    enveloped_command!(
        send_close_request,
        GreaseRequest::ChannelClose,
        GreaseResponse::ChannelClose,
        ChannelCloseRecord,
        ChannelCloseRecord
    );
    enveloped_command!(
        notify_closing_tx,
        GreaseRequest::ChannelClosed,
        GreaseResponse::ChannelClosed,
        TransactionId,
        bool
    );

    pub async fn send_response_to_peer(
        &mut self,
        res: GreaseResponse,
        return_channel: ResponseChannel<GreaseResponse>,
    ) -> Result<(), PeerConnectionError> {
        let res = Box::new(res);
        self.sender.send(ClientCommand::ResponseToRequest { res, return_channel }).await?;
        Ok(())
    }

    pub async fn shutdown(mut self) -> Result<bool, PeerConnectionError> {
        let (sender, receiver) = oneshot::channel();
        self.sender.send(ClientCommand::Shutdown(sender)).await?;
        let result = receiver.await?;
        Ok(result)
    }
}
