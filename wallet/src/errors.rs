use modular_frost::FrostError;
use monero_rpc::RpcError;
use monero_wallet::send::SendError;
use thiserror::Error;

#[derive(Debug, Clone, Error)]
pub enum WalletError {
    #[error("RPC Error: {0}")]
    RpcError(#[from] RpcError),
    #[error("Key Error: {0}")]
    KeyError(String),
    #[error("Not enough funds in wallet, or blockchain needs to be scanned")]
    InsufficientFunds,
    #[error("Transaction creation error: {0}")]
    SendError(#[from] SendError),
    #[error("Multisig protocol error: {0}")]
    FrostError(#[from] FrostError),
    #[error("Error deserializing: {0}")]
    DeserializeError(String),
    #[error("Error signing transaction: {0}")]
    SigningError(String),
    #[error("An internal error occurred: {0}")]
    InternalError(String),
}
