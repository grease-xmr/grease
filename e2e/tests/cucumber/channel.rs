use crate::cucumber::GreaseWorld;
use cucumber::gherkin::Table;
use cucumber::{gherkin::Step, given, when};
use e2e::create_channel_proposal;
use libgrease::amount::MoneroAmount;
use libgrease::balance::Balances;
use log::*;

#[given(expr = "{word} runs the grease client")]
async fn start_client(world: &mut GreaseWorld, client_name: String) {
    world.start_client(&client_name).await;
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
