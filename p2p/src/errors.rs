use crate::delegates::error::DelegateError;
use crate::message_types::RejectChannelProposal;
use futures::channel::{mpsc, oneshot};
use libgrease::payment_channel::UpdateError;
use libgrease::state_machine::error::LifeCycleError;
use libgrease::state_machine::lifecycle::StateStorageError;
use libp2p::request_response::OutboundFailure;
use libp2p::{noise, TransportError};
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use thiserror::Error;
use wallet::errors::WalletError;
use wallet::RpcError;

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
    #[error("The channel {0} does not exist.")]
    ChannelNotFound(String),
    #[error("The remote peer server returned an operational error. {0}")]
    RemoteServerError(#[from] RemoteServerError),
    #[error("We expected a response from Channel {expected} but got one from {actual} instead.")]
    ChannelMismatch { expected: String, actual: String },
    #[error("Will never happen, but required for the error trait")]
    Infallible(#[from] Infallible),
    #[error("An error occurred while processing an outbound request. {0}")]
    OutboundFailure(#[from] OutboundFailure),
}

#[derive(Error, Debug)]
pub enum PaymentChannelError {
    #[error("Error loading channel. {0}")]
    LoadingError(String),
    #[error("I/O error. {0}")]
    IOError(#[from] std::io::Error),
    #[error("Error serializing channel. {0}")]
    SerializationError(#[from] ron::Error),
    #[error("Error saving/loading channel. {0}")]
    PersistenceError(#[from] StateStorageError),
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
    WalletSetup(#[from] WalletError),
    #[error("Error communicating with peer. {0}")]
    PeerConnectionError(#[from] PeerConnectionError),
    #[error("Lifecycle state machine error. {0}")]
    LifeCycleError(#[from] LifeCycleError),
    #[error("An error occurred while generated payment channel update proofs. {0}")]
    UpdateError(#[from] UpdateError),
    #[error("An error occurred during a peer-to-peer exchange. {0}")]
    ProtocolError(String),
    #[error("A Monero RPC call failed. {0}")]
    RpcError(#[from] RpcError),
    #[error("The proposal was rejected.")]
    ProposalRejected(RejectChannelProposal),
    #[error("An error occurred while delegating work. {0}")]
    DelegateError(#[from] DelegateError),
}

#[derive(Error, Debug)]
#[error("Verifiable Secret Sharing failure due to {reason}")]
pub struct VssError {
    pub reason: String,
}

/// An error code from the peer server, akin to an HTTP error code.
#[derive(Error, Debug, Serialize, Deserialize)]
pub enum RemoteServerError {
    #[error("The remote server is shutting down and cannot handle any new requests. Try again later.")]
    ServerShuttingDown,
    #[error("The request did not reach the peer due to a network issue.")]
    NetworkError,
    #[error("An internal error occurred on the remote server. {0}")]
    InternalError(String),
    #[error("Peer was not expecting to be in the role asked of it.")]
    UnexpectedRole,
    #[error("The channel does not exist on this peer.")]
    ChannelDoesNotExist,
    #[error("A proof verification failed. {0}")]
    InvalidProof(String),
}

impl RemoteServerError {
    pub fn internal(msg: impl Into<String>) -> Self {
        RemoteServerError::InternalError(msg.into())
    }
}

impl From<RemoteServerError> for ChannelServerError {
    fn from(error: RemoteServerError) -> Self {
        PeerConnectionError::from(error).into()
    }
}

/// Generally, we don´t want to reveal too much info about the remote server error to the client, but some errors do
/// map cleanly that we can pass back to the peer.
impl From<ChannelServerError> for RemoteServerError {
    fn from(error: ChannelServerError) -> Self {
        match error {
            ChannelServerError::NotMerchantRole | ChannelServerError::NotCustomerRole => {
                RemoteServerError::UnexpectedRole
            }
            ChannelServerError::InvalidState(_) => RemoteServerError::internal("Invalid channel state"),
            ChannelServerError::ChannelNotFound => RemoteServerError::ChannelDoesNotExist,
            ChannelServerError::WalletSetup(_) => RemoteServerError::internal("Wallet setup error"),
            ChannelServerError::PeerConnectionError(_) => RemoteServerError::NetworkError,
            ChannelServerError::LifeCycleError(_) => RemoteServerError::internal("State machine error"),
            ChannelServerError::UpdateError(_) => RemoteServerError::internal("Update error"),
            ChannelServerError::ProtocolError(_) => RemoteServerError::internal("Protocol error"),
            ChannelServerError::RpcError(_) => RemoteServerError::internal("Error with Monero RPC"),
            ChannelServerError::ProposalRejected(_) => RemoteServerError::internal("Proposal was rejected"),
            ChannelServerError::DelegateError(_) => RemoteServerError::internal("Delegate work error"),
        }
    }
}
