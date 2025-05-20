use futures::channel::{mpsc, oneshot};
use libgrease::kes::error::KesError;
use libgrease::monero::error::MoneroWalletError;
use libgrease::state_machine::error::LifeCycleError;
use libp2p::{noise, TransportError};
use std::convert::Infallible;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PeerConnectionError {
    #[error("Failed to create P2P connection, due to an error in the Noise handshake. {0}")]
    NoiseError(#[from] noise::Error),
    #[error("Failed to dial peer: {0}")]
    DialError(#[from] libp2p::swarm::DialError),
    #[error("Failed to create P2P connection, due to an error in the transport layer. {0}")]
    TransportError(#[from] TransportError<std::io::Error>),
    #[error("Cannot dial server peer, because the peer id is missing in the multiaddr")]
    MissingPeerId,
    #[error("Error in an internal mpsc channel. {0}")]
    SendError(#[from] mpsc::SendError),
    #[error("Could not give network client the result of a command because the return channel is canceled. {0}")]
    OneshotError(#[from] oneshot::Canceled),
    #[error("The event loop is shutting down, so the command cannot be executed.")]
    EventLoopShuttingDown,
    #[error("Will never happen, but required for the error trait")]
    Infallible(#[from] Infallible),
    #[error("The channel {0} does not exist.")]
    ChannelNotFound(String),
}

#[derive(Error, Debug)]
pub enum PaymentChannelError {
    #[error("Error loading channel. {0}")]
    LoadingError(String),
    #[error("I/O error. {0}")]
    IOError(#[from] std::io::Error),
    #[error("Error serializing channel. {0}")]
    SerializationError(#[from] ron::Error),
}

#[derive(Error, Debug)]
pub enum ChannelServerError {
    #[error("Channel is not in the Merchant role.")]
    NotMerchantRole,
    #[error("Channel is not in the Customer role.")]
    NotCustomerRole,
    #[error("Channel is in an invalid state. {0}")]
    InvalidState(String),
    #[error("Channel not found.")]
    ChannelNotFound,
    #[error("Error Setting up wallet. {0}")]
    WalletSetup(#[from] MoneroWalletError),
    #[error("Secret sharing failure. {0}")]
    VssFailure(String),
    #[error("Error communicating with peer. {0}")]
    PeerConnectionError(#[from] PeerConnectionError),
    #[error("The peer rejected the protocol. {0}")]
    PeerCommsError(String),
    #[error("Lifecycle state machine error. {0}")]
    LifeCycleError(#[from] LifeCycleError),
    #[error("An error Occurred with the KES. {0}")]
    KesError(#[from] KesError),
}

#[derive(Error, Debug)]
#[error("Verifiable Secret Sharing failure due to {reason}")]
pub struct VssError {
    pub reason: String,
}
