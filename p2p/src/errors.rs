use libgrease::state_machine::lifecycle::StateStorageError;
use serde::{Deserialize, Serialize};
use thiserror::Error;

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
