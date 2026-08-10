use chrono::DateTime;
use libgrease::wallet::connect_to_rpc;
use libgrease::wallet::MoneroRpc;
use monero_interface::prelude::*;
use monero_oxide::block::Block;
use monero_wallet::address::{MoneroAddress, Network};
use tokio;

/// Create a new RPC connection, print the block height, and exit.
#[tokio::main]
async fn main() {
    match connect_to_rpc("http://localhost:25070").await {
        Ok(rpc) => {
            // Successfully connected to the RPC, now we can use it
            println!("Connected to RPC successfully.");
            // `latest_block_number` is the tip's number, so the loop is inclusive of it.
            let tip = rpc.latest_block_number().await.unwrap_or_else(|e| {
                eprintln!("Failed to get block height: {e}");
                0
            });
            for i in 1..=tip {
                rpc.block_by_number(i)
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
            println!("Current tip: {tip}");
            mine_blocks(&rpc, 100).await;
        }
        Err(e) => {
            eprintln!("Failed to connect to RPC: {}", e);
        }
    }
}

const ALICE: &str = "43i4pVer2tNFELvfFEEXxmbxpwEAAFkmgN2wdBiaRNcvYcgrzJzVyJmHtnh2PWR42JPeDVjE8SnyK3kPBEjSixMsRz8TncK";

async fn mine_blocks(rpc: &MoneroRpc, count: usize) {
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
        block.number(),
        DateTime::from_timestamp(block.header.timestamp as i64, 0).unwrap().to_rfc2822(),
        hex::encode(block.hash()),
        block.transactions.len()
    )
}
