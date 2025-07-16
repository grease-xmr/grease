use grease_cli::config::GlobalOptions;
use grease_cli::id_management::LocalIdentitySet;
use grease_p2p::ConversationIdentity;
use libgrease::crypto::keys::{Curve25519PublicKey, Curve25519Secret};
use monero::util::address::Address as MoneroAddressUtil;
use monero_address::{MoneroAddress, Network};
use std::collections::HashMap;
use std::path::PathBuf;
use std::str::FromStr;

pub const KES_PUBKEY: &str = "da591aec8b4f4509103d2098125128d1ce89df51d04de4ed8b5f757550f9db46";

#[derive(Debug, Clone)]
pub struct User {
    pub name: String,
    pub address: MoneroAddress,
    pub secret_key: Curve25519Secret,
    pub public_key: Curve25519PublicKey,
    pub config: GlobalOptions,
    pub identity: ConversationIdentity,
}

impl User {
    pub fn address(&self) -> &MoneroAddress {
        &self.address
    }
}

pub fn create_user(name: &str, address: &str, secret: &str, port: u16) -> User {
    let (secret_key, public_key) = Curve25519PublicKey::keypair_from_hex(secret).unwrap();
    let monero_address = MoneroAddress::from_str(Network::Mainnet, address).unwrap();
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
    config.refund_address = Some(MoneroAddressUtil::from_str(address).unwrap());
    // The address other parties can use to contact this identity on the internet.
    let addr = format!("/ip4/127.0.0.1/tcp/{port}").parse().unwrap();
    config.server_address = Some(addr);
    User { name: name.to_string(), address: monero_address, secret_key, public_key, config, identity }
}

pub fn create_users() -> HashMap<String, User> {
    let alice = create_user(
        "Alice",
        "43i4pVer2tNFELvfFEEXxmbxpwEAAFkmgN2wdBiaRNcvYcgrzJzVyJmHtnh2PWR42JPeDVjE8SnyK3kPBEjSixMsRz8TncK",
        "8eb8a1fd0f2c42fa7508a8883addb0860a0c5e44c1c14605abb385375c533609",
        24010,
    );
    let bob = create_user(
        "Bob",
        "4BH2vFAir1iQCwi2RxgQmsL1qXmnTR9athNhpK31DoMwJgkpFUp2NykFCo4dXJnMhU7w9UZx7uC6qbNGuePkRLYcFo4N7p3",
        "73ee459dd8a774afdbffafe6879ebc3b925fb23ceec9ac631f4ae02acff05f07",
        25010,
    );
    HashMap::from_iter([("Alice".to_string(), alice), ("Bob".to_string(), bob)])
}
