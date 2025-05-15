use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Error, PartialEq, Eq, Serialize, Deserialize)]
pub enum MoneroWalletError {
    #[error("Wallet multisig preparation failed")]
    MultisigPrepare,
    #[error("Wallet multisig key image export failed")]
    MakeMultisig,
    #[error("Wallet multisig key image import failed")]
    ImportMultisigKeyImage,
    #[error("Exporting multisig key image export failed")]
    ExportSpendKey,
    #[error("Importing multisig key image import failed")]
    ImportSpendKey,
    #[error("Multisig wallet error: {0}")]
    Other(String),
}

#[derive(Debug, Clone, Error)]
pub enum MoneroWalletServiceError {
    #[error("Could not create a new wallet")]
    WalletCreation,
    #[error("Could not assign peer")]
    PeerAssignment,
}
