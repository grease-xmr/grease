mod common;
pub mod errors;
pub mod multisig_wallet;
pub mod utils;
pub mod wallet;
pub mod watch_only;

use monero_simple_request_rpc::SimpleRequestRpc;
pub async fn connect_to_rpc(rpc_server: impl Into<String>) -> Result<SimpleRequestRpc, RpcError> {
    let rpc = SimpleRequestRpc::new(rpc_server.into()).await?;
    Ok(rpc)
}

pub use multisig_wallet::MultisigWallet;

// Re-exports
pub use dalek_ff_group::{dalek::Scalar as DScalar, EdwardsPoint, Scalar};
pub use monero_rpc::{Rpc, RpcError};
pub use monero_wallet::address::{AddressType, MoneroAddress, Network, SubaddressIndex};
pub use zeroize::Zeroizing;

pub use common::publish_transaction;
