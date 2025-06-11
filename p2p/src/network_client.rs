use crate::behaviour::ConnectionBehavior;
use crate::data_objects::TransactionRecord;
use crate::errors::{PeerConnectionError, RemoteServerError};
use crate::message_types::{ChannelProposalResult, NewChannelProposal};
use crate::{ClientCommand, EventLoop, GreaseResponse, PeerConnectionEvent};
use futures::channel::{mpsc, oneshot};
use futures::SinkExt;
use futures::Stream;
use libgrease::monero::data_objects::{
    ChannelUpdate, MessageEnvelope, MultisigKeyInfo, MultisigSplitSecrets, MultisigSplitSecretsResponse,
    StartChannelUpdateConfirmation,
};
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

pub type PeerConnection = libp2p::Swarm<ConnectionBehavior>;
/// Creates the network components, namely:
///
/// - The network [`Client`] to interact with the event loop from anywhere within your application.
/// - The network event stream, e.g. for incoming requests.
/// - The main [`EventLoop`] driving the network itself.
pub fn new_network(
    key: Keypair,
) -> Result<(Client, impl Stream<Item = PeerConnectionEvent>, EventLoop), PeerConnectionError> {
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
        Client { sender: command_sender },
        event_receiver,
        EventLoop::new(swarm, command_receiver, event_sender),
    ))
}

/// A sender interface to the network event loop. It can be cheaply cloned and shared among threads and multiple sets
/// of peer-to-peer connections.
#[derive(Clone)]
pub struct Client {
    sender: mpsc::Sender<ClientCommand>,
}

macro_rules! grease_request {
    ($name:ident, $command:ident, $request: ty, $response:ty) => {
        pub async fn $name(
            &mut self,
            peer_id: PeerId,
            channel: &str,
            req: $request,
        ) -> Result<Result<MessageEnvelope<$response>, RemoteServerError>, PeerConnectionError> {
            let (sender, receiver) = oneshot::channel();
            let envelope = MessageEnvelope::new(channel.into(), req);
            self.sender.send(ClientCommand::$command { peer_id, envelope, sender }).await?;
            let res = receiver.await?;
            Ok(res)
        }
    };
}

/// An abstraction layer that sits between the main business logic of the application and the network ([`EventLoop`]).
///
/// The majority of the (async) methods in this struct follow the following pattern:
/// - A one-shot channel is created.
/// - An [`ClientCommand`] is sent to the [`EventLoop`] via the `sender` channel, containing the one-shot sender half.
/// - The method waits for the receiver half to receive its value, before returning it.
///
/// **Importantly**, this struct does not do any work.
/// It simply forwards the [`ClientCommand`]s to the [`EventLoop`] and waits for the results.
impl Client {
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
        data: NewChannelProposal,
    ) -> Result<ChannelProposalResult, PeerConnectionError> {
        let (sender, receiver) = oneshot::channel();
        let peer_id = data.contact_info_proposee.peer_id;
        trace!("NetworkClient: Sending new channel proposal to peer {peer_id}");
        self.sender.send(ClientCommand::ProposeChannelRequest { peer_id, data, sender }).await?;
        let open_result = receiver.await??;
        Ok(open_result)
    }

    grease_request!(send_multisig_key, MultiSigKeyExchange, MultisigKeyInfo, MultisigKeyInfo);
    grease_request!(
        send_split_secrets,
        MultiSigSplitSecretsRequest,
        MultisigSplitSecrets,
        MultisigSplitSecretsResponse
    );
    grease_request!(send_wallet_confirmation, ConfirmMultiSigAddressRequest, String, bool);

    pub async fn wait_for_funding_tx(&mut self, name: &str) -> Result<TransactionRecord, PeerConnectionError> {
        trace!("⚡️ Waiting for funding transaction for channel {name}");
        let (sender, receiver) = oneshot::channel();
        self.sender.send(ClientCommand::WaitForFundingTx { channel: name.to_string(), sender }).await?;
        let record = receiver.await?;
        record
    }

    pub async fn notify_tx_mined(&mut self, tx: TransactionRecord) -> Result<(), PeerConnectionError> {
        self.sender.send(ClientCommand::NotifyTxMined(tx)).await?;
        Ok(())
    }

    /// This starts a new update balance request with the peer.
    /// The necessary proofs for the update must already have been generated and be available in the `update` parameter.
    /// We then send the update request to the remote peer.
    /// and wait for the remote peer to confirm the update (or reject it).
    pub async fn update_balance(
        &mut self,
        peer_id: PeerId,
        channel: &str,
        update: ChannelUpdate,
    ) -> Result<StartChannelUpdateConfirmation, PeerConnectionError> {
        let (sender, receiver) = oneshot::channel();
        let envelope = MessageEnvelope::new(channel.into(), update);

        trace!("⚡️ Sending channel update request for peer {} on channel {}", peer_id, channel);
        self.sender.send(ClientCommand::InitiateNewUpdate { peer_id, envelope, sender }).await?;
        let return_envelope = receiver.await??;
        trace!("⚡️ Received channel update confirmation for peer {peer_id} on channel {channel}");
        let (return_channel, result) = return_envelope.open();
        if return_channel != channel {
            return Err(PeerConnectionError::ChannelMismatch { expected: channel.into(), actual: return_channel });
        }
        Ok(result)
    }

    pub async fn send_response_to_peer(
        &mut self,
        res: GreaseResponse,
        return_chute: ResponseChannel<GreaseResponse>,
    ) -> Result<(), PeerConnectionError> {
        self.sender.send(ClientCommand::ResponseToRequest { res, return_chute }).await?;
        Ok(())
    }

    pub async fn shutdown(mut self) -> Result<bool, PeerConnectionError> {
        let (sender, receiver) = oneshot::channel();
        self.sender.send(ClientCommand::Shutdown(sender)).await?;
        let result = receiver.await?;
        Ok(result)
    }
}
