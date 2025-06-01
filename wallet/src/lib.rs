pub mod utils;
pub mod virtual_wallet;

use monero_simple_request_rpc::SimpleRequestRpc;

pub async fn connect_to_rpc(rpc_server: impl Into<String>) -> Result<SimpleRequestRpc, monero_rpc::RpcError> {
    let rpc = SimpleRequestRpc::new(rpc_server.into()).await?;
    Ok(rpc)
}
