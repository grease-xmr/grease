use crate::wallet::WalletWorld;
use cucumber::{given, when};
use log::*;
use monero_rpc::Rpc;
use monero_simple_request_rpc::SimpleRequestRpc;

#[given("a Monero regtest network")]
async fn new_node(world: &mut WalletWorld) {
    world.start_node().await;
}

#[when(expr = "{word} mines {int} block(s)")]
async fn mine_blocks(world: &mut WalletWorld, who: String, count: usize) {
    let address = world.address_for(&who).expect("Unknown user");
    let rpc = get_rpc_client(world).await;
    let (blocks, last_block) = rpc.generate_blocks(&address, count).await.expect("Failed to mine blocks");
    info!("Mined {} blocks. Last block: {}", blocks.len(), last_block);
}

async fn get_rpc_client(world: &mut WalletWorld) -> SimpleRequestRpc {
    if let Some(node) = &world.monero_node {
        node.rpc_client().await.expect("Failed to get RPC client")
    } else {
        panic!("Monero node is not running");
    }
}
