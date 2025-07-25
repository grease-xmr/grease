use crate::cucumber::GreaseWorld;
use cucumber::then;
use libgrease::amount::{MoneroAmount, MoneroDelta};
use log::info;
use monero_rpc::Rpc;

/// Checks the LAST 10 blocks for a user receiving a specific amount of XMR.
/// You can prefix the amount with a character to indicate a fuzzy match:
/// - `~` for a range (e.g., `~0.1` means within 0.1 XMR of the specified amount)
/// - `>` for greater than (e.g., `>0.1` means more than 0.1 XMR)
/// - `<` for less than (e.g., `<0.1` means less than 0.1 XMR)
/// If no prefix is given, it checks for an exact match.
#[then(regex = r"^(\w+) receives ([~><])?(\d+\.?\d*) XMR$")]
async fn user_receives_xmr(world: &mut GreaseWorld, who: String, fuzzy: String, amount: String) {
    let user = world.users.get(&who).expect("User not found in the world");
    let amount = MoneroAmount::from_xmr(&amount).expect("Failed to parse amount");
    let delta = MoneroDelta::from(100_000_000_000);
    let (min, max) = match fuzzy.as_str() {
        "~" => (
            amount.checked_apply_delta(-delta).unwrap(),
            amount.checked_apply_delta(delta).unwrap(),
        ), // Allow a small range for fuzzy matching
        ">" => (amount, MoneroAmount::from_piconero(u64::MAX)), // Greater than
        "<" => (MoneroAmount::from_piconero(0), amount),        // Less than
        _ => (amount, amount),                                  // Exact match
    };
    let rpc = world.monero_node.as_ref().unwrap().rpc_client().await.expect("Could not get RPC client");
    let height = rpc.get_height().await.expect("Could not get RPC height") as u64;
    let mut wallet = user.wallet().await;
    let output_count = wallet.scan(Some(height - 10), Some(height)).await.unwrap();
    let result = wallet.outputs().iter().rev().take(output_count as usize).any(|output| {
        let output_amount = MoneroAmount::from(output.commitment().amount);
        if output_amount >= min && output_amount <= max {
            info!("{} received {} XMR", who, output_amount);
            true
        } else {
            false
        }
    });
    if !result {
        panic!("{} did not receive a payment", who);
    }
}
