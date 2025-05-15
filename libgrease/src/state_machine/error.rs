use crate::monero::error::MoneroWalletServiceError;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Debug, Error)]
pub enum LifeCycleError {
    #[error("The channel is in a state that does not allow the requested operation")]
    InvalidStateTransition,
    #[error("Invalid channel proposal: {0}")]
    Proposal(#[from] InvalidProposal),
    #[error("Wallet service error: {0}")]
    WalletServiceError(#[from] MoneroWalletServiceError),
}

#[derive(Clone, Debug, Error, Serialize, Deserialize)]
pub enum InvalidProposal {
    #[error("A channel requires one merchant role and one customer role")]
    IncompatibleRoles,
    #[error("Mismatched initial balances proposed")]
    MismatchedBalances,
    #[error("The merchant's public key in the proposal does not match the one that was expected")]
    MismatchedMerchantPublicKey,
    #[error("The customer's public key in the proposal does not match the one that was expected")]
    MismatchedCustomerPublicKey,
    #[error("The KES's public key in the proposal does not match the one that was expected")]
    MismatchedKesPublicKey,
    #[error("The channel ID in the proposal does not match the one that was expected")]
    MismatchedChannelId,
}
