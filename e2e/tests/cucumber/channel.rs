use crate::cucumber::GreaseWorld;
use cucumber::gherkin::Table;
use cucumber::{gherkin::Step, given, then, when};
use e2e::create_channel_proposal;
use libgrease::amount::MoneroAmount;
use libgrease::balance::Balances;
use log::*;
use monero::Denomination::Monero;
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
        .map(|t| balances_from_table(t))
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

fn balances_from_table(table: &Table) -> Balances {
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

#[when(regex = r"^(\w+) (pays|refunds) (\d+\.?\d*) XMR to (\w+)(?: (\d+) times)?$")]
async fn send_on_channel(
    world: &mut GreaseWorld,
    sender: String,
    dir: String,
    amount: String,
    recipient: String,
    count: String,
) {
    let amount = MoneroAmount::from_xmr(&amount).expect("Failed to parse amount");
    let sender = world.users.get(&sender).expect(&format!("Sender {sender} not found in the world"));
    let recipient = world.users.get(&recipient).expect(&format!("Sender {recipient} not found in the world"));
    let channel = world.current_channel.clone().expect("There is no current channel");
    let sender_server = world.servers.get(&sender.name).expect("Sender server not found in the world");
    let count = count.parse::<usize>().unwrap_or(1);
    for i in 0..count {
        let result = match dir.as_str() {
            "pays" => sender_server.server.pay(&channel, amount).await,
            "refunds" => sender_server.server.refund(&channel, amount).await,
            _ => unreachable!(),
        };
        match result {
            Ok(r) => {
                info!("Payment {i} successful: {r:?}");
            }
            Err(e) => {
                error!("Failed to send payment from {} to {}: {}", sender.name, recipient.name, e);
                panic!("Payment failed on attempt {i}");
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

#[then("the channel balance is")]
async fn channel_balance(world: &mut GreaseWorld, step: &Step) {
    let channel = world.current_channel.clone().expect("There is no current channel");
    let server = &world.servers.values().next().expect("No server found in the world").server;
    let metadata = server.channel_metadata(&channel).await.expect("Failed to get channel balances");
    let balances = metadata.balances();
    let expected_balances = balances_from_table(step.table.as_ref().expect("Table is required"));
    assert_eq!(
        balances.customer, expected_balances.customer,
        "Expected customer balance to be {}, but got {}",
        expected_balances.customer, balances.customer
    );
    assert_eq!(
        balances.merchant, expected_balances.merchant,
        "Expected merchant balance to be {}, but got {}",
        expected_balances.merchant, balances.merchant
    );
}

#[then(expr = "the transaction count is {int}")]
async fn transaction_count(world: &mut GreaseWorld, count: u64) {
    let channel = world.current_channel.clone().expect("There is no current channel");
    let server = &world.servers.values().next().expect("No server found in the world").server;
    let update_count = server.transaction_count(&channel).await.expect("Failed to get transaction count");
    assert_eq!(
        update_count, count,
        "Expected transaction count to be {count}, but got {update_count}"
    );
}
