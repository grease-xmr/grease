use crate::behaviour::ConnectionBehavior;
use crate::errors::PeerConnectionError;
use crate::messages::{EventLoop, PeerConnectionCommand, PeerConnectionEvent};
use futures::channel::{mpsc, oneshot};
use futures::SinkExt;
use futures::Stream;
use libp2p::identity::Keypair;
use libp2p::multiaddr::Protocol;
use libp2p::{
    identify, noise,
    request_response::{json, Config as RequestResponseConfig, ProtocolSupport},
    tcp, yamux, Multiaddr, StreamProtocol,
};
use std::time::Duration;

pub type PeerConnection = libp2p::Swarm<ConnectionBehavior>;

/// Creates the network components, namely:
///
/// - The network [`Client`] to interact with the event loop from anywhere within your application.
/// - The network event stream, e.g. for incoming requests.
/// - The main [`EventLoop`] driving the network itself.
pub async fn new_connection(
    key: Keypair,
) -> Result<(Client, impl Stream<Item = PeerConnectionEvent>, EventLoop), PeerConnectionError> {
    let swarm = libp2p::SwarmBuilder::with_existing_identity(key)
        .with_tokio()
        .with_tcp(tcp::Config::default(), noise::Config::new, yamux::Config::default)?
        .with_behaviour(|key| {
            // todo - take this from config
            let config = identify::Config::new("/grease-channel/id/1".to_string(), key.public())
                .with_interval(Duration::from_secs(5 * 60));
            let identify = identify::Behaviour::new(config);
            // todo - take this from config
            let config = RequestResponseConfig::default()
                .with_request_timeout(Duration::from_secs(20))
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

#[derive(Clone)]
pub struct Client {
    sender: mpsc::Sender<PeerConnectionCommand>,
}

/// An abstraction layer that sits between the main business logic of the application and the network ([`EventLoop`]).
///
/// The majority of the (async) methods in this struct follow the following pattern:
/// - A one-shot channel is created.
/// - An [`PeerConnectionCommand`] is sent to the [`EventLoop`] via the `sender` channel, containing the one-shot sender half.
/// - The method waits for the receiver half to receive its value, before returning it.
///
/// **Importantly**, this struct does not do any work.
/// It simply forwards the [`PeerConnectionCommand`]s to the [`EventLoop`] and waits for the results.
impl Client {
    /// Listen for incoming connections on the given address.
    pub async fn start_listening(&mut self, addr: Multiaddr) -> Result<(), PeerConnectionError> {
        let (sender, receiver) = oneshot::channel();
        self.sender.send(PeerConnectionCommand::StartListening { addr, sender }).await?;
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
        self.sender.send(PeerConnectionCommand::Dial { peer_id, peer_addr, sender }).await?;
        let dial_result = receiver.await?;
        dial_result
    }
}
