use crate::cucumber::GreaseWorld;
use cucumber::gherkin::Table;
use cucumber::{gherkin::Step, given, then, when};
use e2e::create_channel_proposal;
use libgrease::amount::MoneroAmount;
use libgrease::balance::Balances;
use log::*;
use monero_address::{MoneroAddress, Network};

#[given(expr = "{word} runs the grease server")]
async fn start_server(world: &mut GreaseWorld, client_name: String) {
    world.start_server(&client_name).await;
}

#[when(expr = "{word} initiates a new channel with {word}")]
async fn new_channel(world: &mut GreaseWorld, step: &Step, customer: String, merchant: String) {
    info!("Starting new channel: {customer}");
    let customer = world.users.get(&customer).expect("Initiator user not found in the world");
    let merchant = world.users.get(&merchant).expect("Recipient user not found in the world");
    let initial_balances = step
        .table
        .as_ref()
        .map(|t| initial_balances_from_table(t))
        .unwrap_or(Balances::new(MoneroAmount::from(0), MoneroAmount::from_xmr("1.0").unwrap()));
    let proposal =
        create_channel_proposal(customer, merchant, initial_balances).expect("Failed to create channel proposal");
    let customer_server = world.servers.get(&customer.name).expect("Customer server not found in the world");
    let channel_name = customer_server.server.establish_new_channel(proposal.clone()).await.unwrap();
    info!("Channel established: {channel_name}");
    world.current_channel = Some(channel_name.clone());
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let mut wallet = customer.wallet().await;
    let channel_address = customer_server
        .server
        .wallet_address(&channel_name, "mainnet")
        .await
        .expect("Failed to get wallet address for channel");
    let channel_address =
        MoneroAddress::from_str(Network::Mainnet, &channel_address).expect("Failed to parse channel address");
    let amt = initial_balances.customer;
    wallet.send(channel_address, amt).await.expect("Failed to send funds");
    info!("Funds sent from {} to {}: {}", customer.name, merchant.name, amt);
}

fn initial_balances_from_table(table: &Table) -> Balances {
    let mut balances = Balances::new(MoneroAmount::from(0), MoneroAmount::from(0));
    for row in table.rows.iter() {
        match (row.get(0).map(|s| s.as_str()), row.get(1)) {
            (Some("customer_balance"), Some(val)) => {
                balances.customer = MoneroAmount::from_xmr(val).expect("Failed to parse customer balance");
            }
            (Some("merchant_balance"), Some(val)) => {
                balances.merchant = MoneroAmount::from_xmr(val).expect("Failed to parse merchant balance");
            }
            _ => {}
        }
    }
    balances
}

#[then(expr = "{word} sees the channel status as {word}")]
async fn channel_status(world: &mut GreaseWorld, user: String, status: String) {
    let server = world.servers.get(&user).expect("Server not found in the world");
    let channel = world.current_channel.clone().expect("There is no current channel");
    let channel_status = server.server.channel_status(&channel).await.expect(&format!("Channel {channel} not found"));
    assert_eq!(
        channel_status.to_string().to_lowercase(),
        status.to_lowercase(),
        "Expected channel status for {channel} to be {status}, but got {channel_status}",
    );
}
