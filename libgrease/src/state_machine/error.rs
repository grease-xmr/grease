use crate::monero::error::MoneroWalletError;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Debug, Error)]
pub enum LifeCycleError {
    #[error("The channel is in a state that does not allow the requested operation")]
    InvalidStateTransition,
    #[error("Invalid channel proposal: {0}")]
    Proposal(#[from] InvalidProposal),
    #[error("Wallet error: {0}")]
    WalletError(#[from] MoneroWalletError),
    #[error("The channel is not in the correct lifecycle state to call {0}")]
    InvalidState(String),
    #[error("There are not enough funds in the channel to effect the payment.")]
    NotEnoughFunds,
    #[error("The update count in the channel is incorrect. Expected {exp}, got {actual}")]
    MismatchedUpdateCount { exp: u64, actual: u64 },
    #[error("Our {0} does not match what was received from the peer")]
    StateMismatch(String),
    #[error("This is a bug. {0}")]
    InternalError(String),
}

#[derive(Clone, Debug, Error, Serialize, Deserialize)]
pub enum InvalidProposal {
    #[error("A channel requires one merchant role and one customer role")]
    IncompatibleRoles,
    #[error("Mismatched initial balances proposed")]
    MismatchedBalances,
    #[error("The total value of the channel cannot be zero")]
    ZeroTotalValue,
    #[error("The merchant's public key in the proposal does not match the one that was expected")]
    MismatchedMerchantPublicKey,
    #[error("The customer's public key in the proposal does not match the one that was expected")]
    MismatchedCustomerPublicKey,
    #[error("The KES configuration in the proposal does not match the one that was expected")]
    MismatchedKesConfig,
    #[error("The channel ID in the proposal does not match the one that was expected")]
    MismatchedChannelId,
    #[error("The network in the proposal does not match the one that was expected")]
    MismatchedNetwork,
    #[error("The seed information in the proposal does not match what was expected")]
    SeedMismatch,
    #[error("The closing address in the proposal does not match the one that was expected")]
    MismatchedAddress,
    #[error("The channel nonce in the proposal does not match the one that was expected")]
    MismatchedNonce,
}

impl LifeCycleError {
    pub fn invalid_state_for(func: &str) -> Self {
        LifeCycleError::InvalidState(func.into())
    }

    pub fn mismatch(what: impl Into<String>) -> Self {
        LifeCycleError::StateMismatch(what.into())
    }
}
