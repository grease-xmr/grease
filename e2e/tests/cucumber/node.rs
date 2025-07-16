use crate::cucumber::GreaseWorld;
use cucumber::{given, then, when};
use e2e::NodeStatus;
use monero_rpc::Rpc;
use monero_simple_request_rpc::SimpleRequestRpc;
use std::time::Duration;

#[given("a Monero regtest network")]
async fn new_node(world: &mut GreaseWorld) {
    world.start_node().await;
}

#[when(expr = "I stop the node")]
async fn stop_node(world: &mut GreaseWorld) {
    let rpc = get_rpc_client(world).await;
    let result = rpc.post("stop_daemon", vec![]).await.expect("Failed to stop the Monero node");
    let msg = String::from_utf8(result).unwrap_or_else(|_| "unknown response".to_string());
    println!("Stop daemon response: {msg}");
    tokio::time::sleep(Duration::from_millis(1000)).await;
    match world.node_status().await {
        NodeStatus::Exited(s) => assert!(s.success()),
        _ => panic!("Node is still running after stop command"),
    }
}

#[when(expr = "I kill the node")]
async fn kill_node(world: &mut GreaseWorld) {
    if let Some(node) = &mut world.monero_node {
        node.kill().await.expect("Failed to kill the Monero node");
    } else {
        panic!("Monero node is not running");
    }
}

#[when(expr = "{word} mines {int} blocks")]
async fn mine_blocks(world: &mut GreaseWorld, who: String, count: usize) {
    let address = world.address_for(&who).expect("Unknown user");
    let rpc = get_rpc_client(world).await;
    let (blocks, last_block) = rpc.generate_blocks(&address, count).await.expect("Failed to mine blocks");
    println!("Mined {} blocks. Last block: {}", blocks.len(), last_block);
}

#[then(expr = "the node status is {string}")]
async fn node_status(world: &mut GreaseWorld, status_str: String) {
    let status = world.node_status().await.to_string();
    assert_eq!(
        status, status_str,
        "Expected node status to be '{status_str}', but got '{status}'"
    );
}

#[then(expr = "the current block height is {int}")]
async fn get_height(world: &mut GreaseWorld, expected_height: usize) {
    let rpc = get_rpc_client(world).await;
    let height = rpc.get_height().await.expect("Failed to get block height");
    assert_eq!(
        height, expected_height,
        "Expected block height to be {expected_height}, but got {height}"
    );
}

async fn get_rpc_client(world: &mut GreaseWorld) -> SimpleRequestRpc {
    if let Some(node) = &world.monero_node {
        node.rpc_client().await.expect("Failed to get RPC client")
    } else {
        panic!("Monero node is not running");
    }
}
