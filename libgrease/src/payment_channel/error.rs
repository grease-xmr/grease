use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Error, Serialize, Deserialize)]
pub enum UpdateError {
    #[error("The new balance does not match the expected value on the peer side")]
    InvalidBalance,
    #[error("The amount being spent would cause one party to have a negative balance")]
    InsufficientFunds,
    #[error("A network error occurred: {0}")]
    NetworkError(String),
    #[error("An error occurred while preparing the update transaction: {0}")]
    WalletError(String),
}
