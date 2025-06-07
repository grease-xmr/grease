use ciphersuite::group::ff::PrimeField;
use dalek_ff_group::{EdwardsPoint, Scalar, ED25519_BASEPOINT_TABLE};
use log::info;
use monero_rpc::{Rpc, RpcError};
use monero_serai::transaction::Transaction;
use monero_simple_request_rpc::SimpleRequestRpc;
use monero_wallet::address::{MoneroAddress, Network};
use serde::Deserialize;
use serde_json::json;
use wallet::virtual_wallet::{MultisigWallet, WalletError};
use zeroize::Zeroizing;
use modular_frost::sign::{Preprocess, SignatureShare, Writable};
use modular_frost::curve::{Ed25519};
use std::mem;

#[tokio::main]
async fn main() -> Result<(), WalletError> {
    env_logger::try_init().unwrap_or_else(|_| {
        eprintln!("Failed to initialize logger, using default settings");
    });

    //Top:
    //9wviCeWe2D8XS82k2ovp5EUYLzBt9pYNW2LXUFsZiv8S3Mt21FZ5qQaAroko1enzw3eGr9qC7X1D7Geoo2RrAotYPwq9Gm8
    const ALICE_ADDRESS: &str =
        "9wviCeWe2D8XS82k2ovp5EUYLzBt9pYNW2LXUFsZiv8S3Mt21FZ5qQaAroko1enzw3eGr9qC7X1D7Geoo2RrAotYPwq9Gm8";

    //Bottom:
    //9wq792k9sxVZiLn66S3Qzv8QfmtcwkdXgM5cWGsXAPxoQeMQ79md51PLPCijvzk1iHbuHi91pws5B7iajTX9KTtJ4bh2tCh
    const BOB_ADDRESS: &str =
        "9wq792k9sxVZiLn66S3Qzv8QfmtcwkdXgM5cWGsXAPxoQeMQ79md51PLPCijvzk1iHbuHi91pws5B7iajTX9KTtJ4bh2tCh";

    //Shared:
    //Mainnet: 4ASsE7j5vthM2QB3k2EvV4UqRUsjsrUXF5Sr4s1ZYmvj5MJNpmF44TDgbeMwk1ifxWYStS3wBRv5YHcnPyRtP7Rh7CDYGdW
    //Testnet: A1zQiNPMDFoM2QB3k2EvV4UqRUsjsrUXF5Sr4s1ZYmvj5MJNpmF44TDgbeMwk1ifxWYStS3wBRv5YHcnPyRtP7Rh77ETMQF
    const SHARED_ADDRESS: &str =
        "A1zQiNPMDFoM2QB3k2EvV4UqRUsjsrUXF5Sr4s1ZYmvj5MJNpmF44TDgbeMwk1ifxWYStS3wBRv5YHcnPyRtP7Rh77ETMQF";
    //Testnet: Multisig wallet joint private view key: 182767d3437c2d4638a6d007c55bd73f60c13a49883f87b2087e77cc89a5c901
    const JOINT_PRIVATE_VIEW_KEY: &str =
        "182767d3437c2d4638a6d007c55bd73f60c13a49883f87b2087e77cc89a5c901";

    // Alice generates a keypair
    let (k_a, p_a) = keys_from("8eb8a1fd0f2c42fa7508a8883addb0860a0c5e44c1c14605abb385375c533609");
    println!(
        "Alice: {} / {}",
        hex::encode(k_a.as_bytes()),
        hex::encode(p_a.compress().as_bytes())
    );
    // Bob generates a keypair
    let (k_b, p_b) = keys_from("73ee459dd8a774afdbffafe6879ebc3b925fb23ceec9ac631f4ae02acff05f07");
    println!(
        "Bob  : {} / {}",
        hex::encode(k_b.as_bytes()),
        hex::encode(p_b.compress().as_bytes())
    );

    let secret_a = scalar_from("000000000000000000000000000000000000000000000000000000000000000000000001");
    let secret_b = scalar_from("000000000000000000000000000000000000000000000000000000000000000000000001");

    // They exchange their public keys and create multisig wallets
    let rpc = SimpleRequestRpc::new("http://localhost:25070".into()).await?;
    let mut wallet_a = MultisigWallet::new(rpc.clone(), k_a.clone(), p_a, p_b, None)?;
    let mut wallet_b = MultisigWallet::new(rpc.clone(), k_b.clone(), p_b, p_a, None)?;

    assert_eq!(
        wallet_a.joint_public_spend_key(),
        wallet_b.joint_public_spend_key(),
        "Shared spend keys should be identical"
    );
    println!("Multisig wallet address for Alice: {}", wallet_a.address().to_string());
    println!("Multisig wallet address for Bob  : {}", wallet_b.address().to_string());
    assert_eq!(
        wallet_a.address().to_string(),
        SHARED_ADDRESS,
        "Shared spend keys should be deterministic"
    );
    println!("Multisig wallet joint private view key: {}", hex::encode(wallet_a.joint_private_view_key().to_bytes()));
    assert_eq!(
        hex::encode(wallet_a.joint_private_view_key().to_bytes()),
        JOINT_PRIVATE_VIEW_KEY,
        "Shared joint private view key should be deterministic"
    );

    println!("Creating signing state machine...");

    // Try load outputs
    for wallet in [&mut wallet_a, &mut wallet_b] {
        let must_scan = match wallet.load("demo_wallet.bin") {
            Ok(loaded) if loaded > 0 => {
                println!("Wallet loaded successfully. {loaded} outputs found");
                false
            }
            Ok(_) => {
                println!("No outputs in wallet, starting fresh. This will take a while...");
                true
            }
            Err(e) => {
                println!("Failed to load wallet: {e}, starting fresh. This will take a while...");
                true
            }
        };
        if must_scan {
            println!("must_scan");
            let outputs = wallet.scan().await?;
            println!("{outputs} outputs found in scan");
            let saved = wallet.save("demo_wallet.bin").map_err(|e| RpcError::InternalError(e.to_string()))?;
            println!("Saved {saved} outputs to disk");
        }
    }
    println!("Outputs loaded");

    // Pay Alice's external wallet
    let alice_wallet = MoneroAddress::from_str(Network::Testnet, ALICE_ADDRESS).unwrap();
    let payment = vec![(alice_wallet, 1_000u64)]; // Placeholder for payment, should be replaced with actual payment data

    wallet_a.prepare(payment.clone()).await?;
    println!("Alice prepared");

    wallet_b.prepare(payment.clone()).await?;
    println!("Bob prepared");

    info!("Preprocessing step completed for both wallets");

    let pp_b: Vec<Preprocess<Ed25519, monero_serai::ringct::clsag::ClsagAddendum>> = wallet_b.my_pre_process_data().unwrap();
    let pp_a = wallet_a.my_pre_process_data().unwrap();

    wallet_a.partial_sign(pp_b)?;
    info!("Partial Signing completed for Alice");

    wallet_b.partial_sign(pp_a)?;
    info!("Partial Signing completed for Bob");

    let ss_a_real: Vec<modular_frost::sign::SignatureShare<ciphersuite::Ed25519>> = wallet_a.my_signing_shares().unwrap();
    info!("Signing shares prepared for Alice: {}", ss_a_real.len());
    println!("Signing shares for Alice: {}", ss_a_real.len());
    for share in &ss_a_real {
        println!("{:?}", get_signatureshare_scalar(share));
    }

    let ss_b_real: Vec<SignatureShare<Ed25519>> = wallet_b.my_signing_shares().unwrap();
    info!("Signing shares prepared for Bob: {}", ss_b_real.len());

    let ss_a_encrypted = make_adapted_shares(ss_a_real, secret_a);
    match wallet_b.sign(ss_a_encrypted.clone()) {
        Ok(_) => {
            println!("Encrypted signing shares for Alice incorrectly usable");
            std::process::exit(1);
        },
        Err(err) => {
            info!("Encrypted signing shares for Alice verified unusable");
        }
    };
    println!("Encrypted signing shares for Alice: {}", ss_a_encrypted.len());
    for share in &ss_a_encrypted {
        println!("{:?}", get_signatureshare_scalar(share));
    }

    let ss_b_encrypted = make_adapted_shares(ss_b_real, secret_b);
    match wallet_a.sign(ss_b_encrypted.clone()) {
        Ok(_) => {
            println!("Encrypted signing shares for Bob incorrectly usable");
            std::process::exit(1);
        },
        Err(err) => {
            info!("Encrypted signing shares for Bob verified unusable");
        }
    };

    // They exchange their adaptor secrets
    let ss_b_adapted = adapt_shares(ss_b_encrypted, secret_b);

    let tx_a: Transaction = wallet_a.sign(ss_b_adapted)?;
    info!("Alice's transaction signed successfully");

    let ss_a_adapted = adapt_shares(ss_a_encrypted, secret_a);

    let tx_b: Transaction = wallet_b.sign(ss_a_adapted)?;
    info!("Bob's transaction signed successfully");

    println!("Wallet transaction from Alice: {}", hex::encode(tx_a.hash()));
    println!("Wallet transaction from Bob: {}", hex::encode(tx_b.hash()));

    println!("Sighash A: {}", hex::encode(tx_a.signature_hash().unwrap()));
    println!("Sighash B: {}", hex::encode(tx_b.signature_hash().unwrap()));

    println!("weight A: {}", tx_a.weight());
    println!("weight B: {}", tx_b.weight());

    publish_transaction(wallet_a.rpc(), &tx_a).await?;
    Ok(())
}

fn get_signatureshare_scalar(share: &SignatureShare<Ed25519>) -> Scalar {
    //Read
    let mut buf = vec![];
    share.write(&mut buf).unwrap();
    let mut repr: [u8; 32] = [0u8; 32];
    repr.copy_from_slice(&buf[0..32]);
    let s = Scalar::from_repr(repr).unwrap();
    s
}
unsafe fn update_signatureshare(original: &mut SignatureShare<Ed25519>, new_value: Scalar) {
    // Ensure the types are compatible for transmute
    assert_eq!(mem::size_of::<SignatureShare<Ed25519>>(), mem::size_of::<Scalar>());
    assert_eq!(mem::align_of::<SignatureShare<Ed25519>>(), mem::align_of::<Scalar>());

    // Transmute the new value into the memory of the original
    *original = mem::transmute(new_value);
}

fn make_adapted_shares(signature_shares: Vec<SignatureShare<Ed25519>>, secret: Scalar) -> Vec<SignatureShare<Ed25519>> {
    //TODO: ensure this is a deep copy!
    let mut adapted_shares = signature_shares.clone();

    for (i, share) in signature_shares.iter().enumerate() {
        //Read
        let mut buf = vec![];
        share.write(&mut buf).unwrap();
        let mut repr: [u8; 32] = [0u8; 32];
        repr.copy_from_slice(&buf[0..32]);
        let s = Scalar::from_repr(repr).unwrap();

        //Update
        let s_adapted = s + secret;

        //Write
        //adapted_shares[i] = s_adapted;
        unsafe {
            update_signatureshare(&mut adapted_shares[i], s_adapted);
        }
    }
    adapted_shares
}

fn adapt_shares(adapted_signature_shares: Vec<SignatureShare<Ed25519>>, secret: Scalar) -> Vec<SignatureShare<Ed25519>> {
    //TODO: ensure this is a deep copy!
    let mut real_shares = adapted_signature_shares.clone();

    for (i, share) in adapted_signature_shares.iter().enumerate() {
        //Read
        let mut buf = vec![];
        share.write(&mut buf).unwrap();
        let mut repr: [u8; 32] = [0u8; 32];
        repr.copy_from_slice(&buf[0..32]);
        let s = Scalar::from_repr(repr).unwrap();

        //Update
        let s_adapted = s - secret;

        //Write
        //real_shares[i] = s_adapted;
        unsafe {
            update_signatureshare(&mut real_shares[i], s_adapted);
        }
    }
    real_shares
}

fn keys_from(s: &str) -> (Zeroizing<Scalar>, EdwardsPoint) {
    let bytes = hex::decode(s).unwrap();
    let mut repr = [0u8; 32];
    repr.copy_from_slice(&bytes[0..32]);
    let secret = Scalar::from_repr(repr).unwrap();
    let public = EdwardsPoint(ED25519_BASEPOINT_TABLE * &secret.0);
    (Zeroizing::new(secret), public)
}

fn scalar_from(s: &str) -> Scalar {
    let bytes = hex::decode(s).unwrap();
    let mut repr = [0u8; 32];
    repr.copy_from_slice(&bytes[0..32]);
    let scalar = Scalar::from_repr(repr).unwrap();
    scalar
}

async fn publish_transaction(rpc: &SimpleRequestRpc, tx: &Transaction) -> Result<(), RpcError> {
    #[allow(dead_code)]
    #[derive(Debug, Deserialize)]
    struct SendRawResponse {
        status: String,
        double_spend: bool,
        fee_too_low: bool,
        invalid_input: bool,
        invalid_output: bool,
        low_mixin: bool,
        not_relayed: bool,
        overspend: bool,
        too_big: bool,
        too_few_outputs: bool,
        reason: String,
    }

    let res: SendRawResponse = rpc
        .rpc_call(
            "send_raw_transaction",
            Some(json!({ "tx_as_hex": hex::encode(tx.serialize()), "do_sanity_checks": true })),
        )
        .await?;

    println!("{res:?}");

    Ok(())
}
