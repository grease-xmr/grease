use crate::user::User;
use grease_cli::config::GlobalOptions;
use grease_p2p::delegates::DummyDelegate;
use grease_p2p::grease::{GreaseClient, GreaseClientOptions, NewChannelMessage, PaymentChannels};
use grease_p2p::ConversationIdentity;
use libgrease::balance::Balances;
use libgrease::channel_id::ChannelId;
use libgrease::monero::data_objects::ClosingAddresses;
use libgrease::payment_channel::ChannelRole;
use libgrease::state_machine::ChannelSeedBuilder;
use monero::Network;
use std::fmt::Debug;
use std::time::Duration;

pub struct GreaseInfra {
    pub server: GreaseClient<DummyDelegate>,
}

impl Debug for GreaseInfra {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GreaseInfra").finish()
    }
}

impl GreaseInfra {
    pub fn new(id: ConversationIdentity, config: GlobalOptions, monerod_rpc: &str) -> Result<Self, anyhow::Error> {
        let delegate = DummyDelegate::new(monerod_rpc.to_string());
        let channels = PaymentChannels::load(config.channel_directory())?;
        let options = GreaseClientOptions { tx_poll_interval: Duration::from_millis(10) };
        let server = GreaseClient::new(id, channels, monerod_rpc, delegate, options)?;
        Ok(Self { server })
    }
}

pub fn create_channel_proposal(
    customer: &User,
    merchant: &User,
    initial_balances: Balances,
) -> anyhow::Result<NewChannelMessage, anyhow::Error> {
    let customer_label = customer.config.user_label.clone().expect("User label is not set");
    let customer_contact_info = customer.identity.contact_info();
    let customer_closing_address = customer.config.refund_address.expect("Customer refund address is not set");
    use libgrease::cryptography::keys::{Curve25519PublicKey, PublicKey};
    use rand_core::{OsRng, RngCore};

    let merchant_contact_info = merchant.identity.contact_info();
    // Generate merchant's channel key and nonce
    let (_, merchant_channel_key) = Curve25519PublicKey::keypair(&mut OsRng);
    let merchant_channel_nonce = OsRng.next_u64();
    let seed_info = ChannelSeedBuilder::new(ChannelRole::Customer, Network::Mainnet)
        .with_closing_address(merchant.config.refund_address.expect("Merchant refund address is not set"))
        .with_kes_public_key(merchant.config.kes_public_key.as_ref().expect("No public key for KES specified").clone())
        .with_initial_balances(initial_balances)
        .with_channel_key(merchant_channel_key)
        .with_channel_nonce(merchant_channel_nonce)
        .build()
        .expect("Missing data in channel seed builder");
    // Generate customer's channel key and nonce
    let (_, customer_channel_key) = Curve25519PublicKey::keypair(&mut OsRng);
    let customer_channel_nonce = OsRng.next_u64();
    let closing = ClosingAddresses {
        customer: customer.config.refund_address().expect("Customer refund address is not set"),
        merchant: merchant.config.refund_address().expect("Merchant refund address is not set"),
    };
    let channel_id = ChannelId::new(
        seed_info.merchant_channel_key.clone(),
        customer_channel_key,
        initial_balances,
        closing,
        seed_info.merchant_nonce,
        customer_channel_nonce,
    );
    let proposal = NewChannelMessage::new(
        Network::Mainnet,
        channel_id,
        seed_info,
        customer_contact_info,
        merchant_contact_info,
    );
    Ok(proposal)
}
