use libgrease::crypto::keys::{Curve25519PublicKey, Curve25519Secret};
use monero_address::{MoneroAddress, Network};

const ALICE: &str = "43i4pVer2tNFELvfFEEXxmbxpwEAAFkmgN2wdBiaRNcvYcgrzJzVyJmHtnh2PWR42JPeDVjE8SnyK3kPBEjSixMsRz8TncK";

pub fn get_address_for(who: &str) -> MoneroAddress {
    match who {
        "Alice" | "alice" => MoneroAddress::from_str(Network::Mainnet, ALICE).unwrap(),
        _ => panic!("Unknown address for {}", who),
    }
}

pub fn alice() -> MoneroWallet {
    // Alice generates a keypair
    let (k_a, p_a) =
        Curve25519PublicKey::keypair_from_hex("8eb8a1fd0f2c42fa7508a8883addb0860a0c5e44c1c14605abb385375c533609")
            .unwrap();

    MoneroWallet { address: ALICE, secret: k_a, pubkey: p_a }
}

pub struct MoneroWallet {
    address: &'static str,
    secret: Curve25519Secret,
    pubkey: Curve25519PublicKey,
}
