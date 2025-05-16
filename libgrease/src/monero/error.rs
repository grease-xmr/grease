use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Error, PartialEq, Eq, Serialize, Deserialize)]
pub enum MoneroWalletError {
    #[error("Wallet creation failed")]
    Creation,
    #[error("Wallet multisig preparation failed")]
    MultisigPrepare,
    #[error("Wallet multisig key image export failed")]
    MakeMultisig,
    #[error("Wallet multisig key image import failed")]
    ImportMultisigKeyImage,
    #[error("Exporting partial spend key failed")]
    ExportSpendKey,
    #[error("Importing partial spend key failed")]
    ImportSpendKey,
    #[error("Multisig wallet error: {0}")]
    Other(String),
}
