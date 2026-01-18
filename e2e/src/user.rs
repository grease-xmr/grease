use crate::MONEROD_RPC;
use ciphersuite::{Ciphersuite, Ed25519};
use grease_cli::config::GlobalOptions;
use grease_cli::id_management::LocalIdentitySet;
use grease_p2p::ConversationIdentity;
use libgrease::cryptography::keys::{Curve25519PublicKey, Curve25519Secret, PublicKey};
use log::*;
use monero::util::address::Address as MoneroAddressUtil;
use monero_address::{AddressType, MoneroAddress, Network};
use std::collections::HashMap;
use std::path::PathBuf;
use std::str::FromStr;
use wallet::connect_to_rpc;
use wallet::wallet::MoneroWallet;

pub const KES_PUBKEY: &str = "da591aec8b4f4509103d2098125128d1ce89df51d04de4ed8b5f757550f9db46";

#[derive(Debug, Clone)]
pub struct User {
    pub name: String,
    pub secret_key: Curve25519Secret,
    pub public_key: Curve25519PublicKey,
    pub config: GlobalOptions,
    pub identity: ConversationIdentity,
}

impl User {
    pub fn address(&self) -> MoneroAddress {
        let view_key = self.private_view_key();
        let view = Curve25519PublicKey::from_secret(&view_key).as_point().0;
        let spend = self.public_key.as_point().0;
        MoneroAddress::new(Network::Mainnet, AddressType::Legacy, spend, view)
    }

    pub fn private_view_key(&self) -> Curve25519Secret {
        const DST: &str = "E2ETestUserPrivateViewKey";
        let scalar = self.secret_key.as_scalar();
        let k = Ed25519::hash_to_F(DST.as_bytes(), scalar.as_bytes());
        Curve25519Secret::from(k)
    }

    pub async fn wallet(&self) -> MoneroWallet {
        let rpc = connect_to_rpc(MONEROD_RPC).await.expect("could not create RPC client");
        MoneroWallet::new(rpc, self.secret_key.clone(), self.private_view_key(), None)
            .expect("could not create Monero wallet")
    }
}

pub fn create_user(name: &str, spend_key: &str, port: u16) -> User {
    let (secret_key, public_key) = Curve25519PublicKey::keypair_from_hex(spend_key).unwrap();
    let mut config = GlobalOptions::default();
    let lower_name = name.to_lowercase();
    // The path to the configuration file.
    config.base_path = Some(PathBuf::from(format!("data/{lower_name}")));
    // The path to the identity database.
    config.identities_file = Some(PathBuf::from("fixtures/identities.yml"));
    let mut identities = LocalIdentitySet::try_load(config.identities_file.as_ref().unwrap())
        .expect("could not load local identity set");
    let identity = identities.remove(name).expect("could not find identity in local identity set");
    // The default identity to use when creating new channels.
    config.preferred_identity = Some(name.to_string());
    // The public key of the Key Escrow Service (KES).
    config.kes_public_key = Some(KES_PUBKEY.to_string());
    // A name, or label that will be inserted into every channel you are part of.
    config.user_label = Some(format!("{lower_name}-channel"));
    // The folder where channels are stored.
    config.channel_storage_directory = Some(PathBuf::from("channels"));
    // The address of the wallet that will receive funds on channel closures.
    config.refund_address = None;
    // The address other parties can use to contact this identity on the internet.
    let addr = format!("/ip4/127.0.0.1/tcp/{port}").parse().unwrap();
    config.server_address = Some(addr);
    let mut user = User { name: name.to_string(), secret_key, public_key, config, identity };
    let addr = MoneroAddressUtil::from_str(&user.address().to_string()).expect("could not parse address");
    info!("Created user {name} with address {addr}");
    user.config.refund_address = Some(addr);
    user
}

pub fn create_users() -> HashMap<String, User> {
    let alice = create_user(
        "Alice",
        "8eb8a1fd0f2c42fa7508a8883addb0860a0c5e44c1c14605abb385375c533609",
        24010,
    );
    let bob = create_user("Bob", "73ee459dd8a774afdbffafe6879ebc3b925fb23ceec9ac631f4ae02acff05f07", 25010);
    HashMap::from_iter([("Alice".to_string(), alice), ("Bob".to_string(), bob)])
}
