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
    #[error("Transaction was invalid due to Double Spend")]
    DoubleSpend,
    #[error("Transaction was invalid due to Fee Too Low")]
    FeeTooLow,
    #[error("Transaction was invalid due to Invalid Input")]
    InvalidInput,
    #[error("Transaction was invalid due to Invalid Output")]
    InvalidOutput,
    #[error("Transaction was invalid due to Low Mixin")]
    LowMixin,
    #[error("Transaction was invalid due to Not Relayed")]
    NotRelayed,
    #[error("Transaction was invalid due to overspend")]
    Overspend,
    #[error("Transaction was invalid due to Too Big")]
    TooBig,
    #[error("Transaction was invalid due to Too Few Outputs")]
    TooFewOutputs,
}
