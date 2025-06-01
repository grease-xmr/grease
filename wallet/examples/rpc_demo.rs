use chrono::DateTime;
use monero_rpc::Rpc;
use monero_serai::block::Block;
use monero_simple_request_rpc::SimpleRequestRpc;
use monero_wallet::address::{MoneroAddress, Network};
use tokio;
use wallet::connect_to_rpc;

/// Create a new RPC connection, print the block height, and exit.
#[tokio::main]
async fn main() {
    match connect_to_rpc("http://localhost:25070").await {
        Ok(rpc) => {
            // Successfully connected to the RPC, now we can use it
            println!("Connected to RPC successfully.");
            let height = rpc.get_height().await.unwrap_or_else(|e| {
                eprintln!("Failed to get block height: {}", e);
                0
            });
            for i in 1..height {
                rpc.get_block_by_number(i)
                    .await
                    .map(|block| {
                        if block.transactions.len() > 0 || i % 100 == 0 {
                            println!("{}", print_block(&block));
                        }
                    })
                    .unwrap_or_else(|e| {
                        eprintln!("Failed to get block {}: {}", i, e);
                    });
            }
            println!("Current height: {height}");
            mine_blocks(&rpc, 100).await;
        }
        Err(e) => {
            eprintln!("Failed to connect to RPC: {}", e);
        }
    }
}

const ALICE: &str = "43i4pVer2tNFELvfFEEXxmbxpwEAAFkmgN2wdBiaRNcvYcgrzJzVyJmHtnh2PWR42JPeDVjE8SnyK3kPBEjSixMsRz8TncK";

async fn mine_blocks(rpc: &SimpleRequestRpc, count: usize) {
    let address = MoneroAddress::from_str(Network::Mainnet, ALICE).unwrap();
    match rpc.generate_blocks(&address, count).await {
        Ok((blocks, last_block)) => {
            println!("Mined {} blocks. Last block {last_block}", blocks.len());
        }
        Err(e) => {
            eprintln!("Failed to mine blocks: {}", e);
        }
    }
}

fn print_block(block: &Block) -> String {
    format!(
        "Block #{} {} {}\n{} transactions",
        block.number().unwrap(),
        DateTime::from_timestamp(block.header.timestamp as i64, 0).unwrap().to_rfc2822(),
        hex::encode(block.hash()),
        block.transactions.len()
    )
}
