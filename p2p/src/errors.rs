use futures::channel::{mpsc, oneshot};
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
    #[error("Could not dial server due to an error in the internal mpsc channel. {0}")]
    SendError(#[from] mpsc::SendError),
    #[error("Could not dial server due to an error in the internal mpsc channel. {0}")]
    OneshotError(#[from] oneshot::Canceled),
    #[error("Will never happen, but required for the error trait")]
    Infallible(#[from] Infallible),
}
