use thiserror::Error;

#[derive(Debug, Error)]
pub enum MoneroWalletError {
    #[error("Wallet multisig preparation failed")]
    MultisigPrepare,
}

#[derive(Debug, Error)]
pub enum MoneroWalletServiceError {
    #[error("Could not create a new wallet")]
    WalletCreation,
    #[error("Could not assign peer")]
    PeerAssignment,
}
