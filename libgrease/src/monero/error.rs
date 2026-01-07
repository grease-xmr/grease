use monero::Network;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum ClosingAddressError {
    #[error("Invalid address: {0}")]
    InvalidAddress(String),
    #[error("Customer and merchant addresses must be different")]
    IdenticalAddresses,
    #[error("Network mismatch: customer address is on {customer:?}, merchant address is on {merchant:?}")]
    NetworkMismatch { customer: Network, merchant: Network },
}

#[derive(Debug, Clone, Error, PartialEq, Eq, Serialize, Deserialize)]
pub enum MoneroWalletError {
    #[error("Wallet creation failed")]
    Creation,
    #[error("Wallet multisig preparation failed")]
    MultisigPrepare,
    #[error("The key received from the peer is not a valid public key")]
    InvalidPeerPubkey,
    #[error("Wallet multisig key image import failed")]
    ImportMultisigKeyImage,
    #[error("Exporting partial spend key failed")]
    ExportSpendKey,
    #[error("Importing partial spend key failed")]
    ImportSpendKey,
    #[error("Multisig wallet error: {0}")]
    Other(String),
}
