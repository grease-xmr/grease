pub mod common;
pub mod errors;
pub mod helpers;
pub mod multisig_wallet;
pub mod transaction_monitor;
pub mod utils;
pub mod wallet;
pub mod watch_only;

use monero_simple_request_rpc::SimpleRequestRpc;
use monero_wallet::rpc::RpcError;
pub async fn connect_to_rpc(rpc_server: impl Into<String>) -> Result<SimpleRequestRpc, RpcError> {
    let rpc = SimpleRequestRpc::new(rpc_server.into()).await?;
    Ok(rpc)
}
