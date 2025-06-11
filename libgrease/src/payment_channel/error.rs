use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Error, Serialize, Deserialize)]
pub enum UpdateError {
    #[error("The provided DLEQ proof is invalid")]
    InvalidDleqProof,
    #[error("The provided modulo proof is invalid")]
    InvalidModProof,
    #[error("The provided VCOF proof is invalid")]
    InvalidVcofProof,
    #[error("The new balance does not match the expected value on the peer side")]
    InvalidBalance,
    #[error("The amount being spent would cause one party to have a negative balance")]
    InsufficientFunds,
    #[error("A network error occurred: {0}")]
    NetworkError(String),
}
