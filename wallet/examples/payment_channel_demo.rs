use ciphersuite::group::ff::PrimeField;
use dalek_ff_group::Scalar;
use libgrease::crypto::keys::Curve25519PublicKey;
use log::info;
use modular_frost::curve::Ed25519;
use modular_frost::sign::{SignatureShare, Writable};
use monero_rpc::RpcError;
use monero_serai::transaction::Transaction;
use monero_simple_request_rpc::SimpleRequestRpc;
use monero_wallet::address::{MoneroAddress, Network};
use rand_core::OsRng;
use std::mem;
use std::ptr;
use wallet::errors::WalletError;
use wallet::multisig_wallet::MultisigWallet;
use wallet::publish_transaction;
use wallet::utils::scalar_from;

#[tokio::main]
async fn main() -> Result<(), WalletError> {
    env_logger::try_init().unwrap_or_else(|_| {
        eprintln!("Failed to initialize logger, using default settings");
    });

    //Top:
    //Mainnet: 46PAiPrNjr2XS82k2ovp5EUYLzBt9pYNW2LXUFsZiv8S3Mt21FZ5qQaAroko1enzw3eGr9qC7X1D7Geoo2RrAotYPvzt9vB
    //Testnet: 9wviCeWe2D8XS82k2ovp5EUYLzBt9pYNW2LXUFsZiv8S3Mt21FZ5qQaAroko1enzw3eGr9qC7X1D7Geoo2RrAotYPwq9Gm8
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
        "4ASsE7j5vthM2QB3k2EvV4UqRUsjsrUXF5Sr4s1ZYmvj5MJNpmF44TDgbeMwk1ifxWYStS3wBRv5YHcnPyRtP7Rh7CDYGdW";
    //Mainnet or Testnet: Multisig wallet joint private view key: 182767d3437c2d4638a6d007c55bd73f60c13a49883f87b2087e77cc89a5c901
    const JOINT_PRIVATE_VIEW_KEY: &str = "182767d3437c2d4638a6d007c55bd73f60c13a49883f87b2087e77cc89a5c901";

    // Alice generates a keypair
    let (k_a, p_a) =
        Curve25519PublicKey::keypair_from_hex("8eb8a1fd0f2c42fa7508a8883addb0860a0c5e44c1c14605abb385375c533609")
            .unwrap();
    println!("Alice: {} / {}", k_a.as_hex(), p_a.as_hex());
    // Bob generates a keypair
    let (k_b, p_b) =
        Curve25519PublicKey::keypair_from_hex("73ee459dd8a774afdbffafe6879ebc3b925fb23ceec9ac631f4ae02acff05f07")
            .unwrap();
    println!("Bob  : {} / {}", k_b.as_hex(), p_b.as_hex());

    let secret_a = scalar_from("0000000000000000000000000000000000000000000000000000000000000001");
    let secret_b = scalar_from("0000000000000000000000000000000000000000000000000000000000000001");

    // They exchange their public keys and create multisig wallets
    let rpc = SimpleRequestRpc::new("http://localhost:25070".into()).await?;
    let mut wallet_a = MultisigWallet::new(rpc.clone(), k_a.clone(), &p_a, &p_b, None)?;
    let mut wallet_b = MultisigWallet::new(rpc.clone(), k_b.clone(), &p_b, &p_a, None)?;

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
    println!(
        "Multisig wallet joint private view key: {}",
        wallet_a.joint_private_view_key().as_hex()
    );
    assert_eq!(
        wallet_a.joint_private_view_key().as_hex(),
        JOINT_PRIVATE_VIEW_KEY,
        "Shared joint private view key should be deterministic"
    );

    println!("Joint Secret view key: {}", wallet_a.joint_private_view_key().as_hex());
    println!("Joint Public view key: {}", wallet_a.joint_public_view_key().as_hex());
    println!("Joint Public spend key: {}", wallet_a.joint_public_view_key().as_hex());
    println!("Creating signing state machine...");

    // Try load outputs
    for wallet in [&mut wallet_a, &mut wallet_b] {
        let must_scan = match wallet.load("demo_wallet.bin") {
            Ok(loaded) if loaded > 0 => {
                info!("Wallet loaded successfully. {loaded} outputs found");
                false
            }
            Ok(_) => {
                info!("No outputs in wallet, starting fresh. This will take a while...");
                true
            }
            Err(e) => {
                info!("Failed to load wallet: {e}, starting fresh. This will take a while...");
                true
            }
        };
        if must_scan {
            info!("must_scan");
            let outputs = wallet.scan(None).await?;
            info!("{outputs} outputs found in scan");
            let saved = wallet.save("demo_wallet.bin").map_err(|e| RpcError::InternalError(e.to_string()))?;
            info!("Saved {saved} outputs to disk");
        }
    }
    info!("Outputs loaded");

    //INIT/UPDATE
    // Pay Alice's external wallet
    let alice_wallet = MoneroAddress::from_str(Network::Testnet, ALICE_ADDRESS).unwrap();
    let bob_wallet = MoneroAddress::from_str(Network::Testnet, BOB_ADDRESS).unwrap();
    let payment = vec![(alice_wallet, 1_000u64), (bob_wallet, 1_000u64)]; // Placeholder for payment, should be replaced with actual payment data

    info!("Alice preparing...");
    wallet_a.prepare(payment.clone(), &mut OsRng).await?;
    info!("Alice prepared");

    info!("Bob preparing...");
    wallet_b.prepare(payment, &mut OsRng).await?;
    info!("Bob prepared");

    info!("Preprocessing step completed for both wallets");

    let pp_b = wallet_b.my_pre_process_data().unwrap();
    let pp_a = wallet_a.my_pre_process_data().unwrap();

    wallet_a.partial_sign(&pp_b)?;
    info!("Partial Signing completed for Alice");

    wallet_b.partial_sign(&pp_a)?;
    info!("Partial Signing completed for Bob");

    let ss_a_real: Vec<modular_frost::sign::SignatureShare<ciphersuite::Ed25519>> =
        vec![wallet_a.my_signing_share().unwrap()];
    info!("Signing shares prepared for Alice: {}", ss_a_real.len());
    info!("Signing shares for Alice: {}", ss_a_real.len());
    for share in &ss_a_real {
        info!("{:?}", get_signatureshare_scalar(share));
    }

    let ss_b_real: Vec<SignatureShare<Ed25519>> = vec![wallet_b.my_signing_share().unwrap()];
    info!("Signing shares prepared for Bob: {}", ss_b_real.len());
    info!("Signing shares for Bob: {}", ss_b_real.len());
    for share in &ss_b_real {
        info!("{:?}", get_signatureshare_scalar(share));
    }

    let mut ss_a_encrypted = ss_a_real.clone();
    make_adapted_shares(&ss_a_real, &mut ss_a_encrypted, secret_a).unwrap();
    info!("Encrypted signing shares for Alice: {}", ss_a_encrypted.len());
    for share in &ss_a_encrypted {
        info!("{:?}", get_signatureshare_scalar(share));
    }
    //Verify changed
    for (i, _) in ss_a_real.iter().enumerate() {
        assert_ne!(
            get_signatureshare_scalar(&ss_a_real[i]),
            get_signatureshare_scalar(&ss_a_encrypted[i])
        );
    }

    let mut ss_b_encrypted = ss_b_real.clone();
    make_adapted_shares(&ss_b_real, &mut ss_b_encrypted, secret_b).unwrap();
    info!("Encrypted signing shares for Bob: {}", ss_b_encrypted.len());
    for share in &ss_b_encrypted {
        info!("{:?}", get_signatureshare_scalar(share));
    }
    //Verify changed
    for (i, _) in ss_b_real.iter().enumerate() {
        assert_ne!(
            get_signatureshare_scalar(&ss_b_real[i]),
            get_signatureshare_scalar(&ss_b_encrypted[i])
        );
    }

    //CLOSE
    // They exchange their adaptor secrets
    let ss_b_adapted = adapt_shares(ss_b_encrypted, secret_b);
    info!("Alice adapted Bob's shares: {}", ss_b_adapted.len());
    for share in &ss_b_adapted {
        info!("{:?}", get_signatureshare_scalar(share));
    }
    //Verify unchanged
    for (i, _) in ss_b_adapted.iter().enumerate() {
        assert_eq!(
            get_signatureshare_scalar(&ss_b_real[i]),
            get_signatureshare_scalar(&ss_b_adapted[i])
        );
    }

    let tx_a: Transaction = wallet_a.sign(&ss_b_adapted[0])?;
    info!("Alice's transaction signed successfully");

    let ss_a_adapted = adapt_shares(ss_a_encrypted, secret_a);
    info!("Bob adapted Alice's shares");

    let tx_b: Transaction = wallet_b.sign(&ss_a_adapted[0])?;
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
    // Safety: This function transmutes between SignatureShare<Ed25519> and Scalar.
    // The caller must ensure that:
    // 1. The types have the same size and alignment (checked by assertions)
    // 2. The Scalar value represents a valid SignatureShare<Ed25519>    // Ensure the types are compatible for transmute
    assert_eq!(mem::size_of::<SignatureShare<Ed25519>>(), mem::size_of::<Scalar>());
    assert_eq!(mem::align_of::<SignatureShare<Ed25519>>(), mem::align_of::<Scalar>());

    // Transmute the Scalar to SignatureShare<Ed25519>
    let new_struct: SignatureShare<Ed25519> = mem::transmute_copy(&new_value);

    // Write the new value directly into the target's memory
    ptr::write(original as *mut SignatureShare<Ed25519>, new_struct);
}

fn make_adapted_shares(
    signature_shares: &Vec<SignatureShare<Ed25519>>,
    adapted_shares: &mut Vec<SignatureShare<Ed25519>>,
    secret: Scalar,
) -> Result<(), RpcError> {
    assert_eq!(signature_shares.len(), adapted_shares.len());
    let length = signature_shares.len();

    for i in 0..length {
        //Read
        let mut buf = vec![];
        signature_shares[i].write(&mut buf).unwrap();
        let mut repr: [u8; 32] = [0u8; 32];
        repr.copy_from_slice(&buf[0..32]);
        let s = Scalar::from_repr(repr).unwrap();

        //Update
        let s_adapted = s + secret;
        assert_ne!(s, s_adapted);

        //Write
        //adapted_shares[i] = s_adapted;
        unsafe {
            update_signatureshare(&mut adapted_shares[i], s_adapted);
        }
    }

    //Verify changed
    for i in 0..length {
        assert_ne!(
            get_signatureshare_scalar(&signature_shares[i]),
            get_signatureshare_scalar(&adapted_shares[i])
        );
    }

    Ok(())
}

fn adapt_shares(
    adapted_signature_shares: Vec<SignatureShare<Ed25519>>,
    secret: Scalar,
) -> Vec<SignatureShare<Ed25519>> {
    let mut real_shares = adapted_signature_shares.clone();

    //Read
    let mut buf = vec![];
    real_shares.write(&mut buf).unwrap();
    let mut repr: [u8; 32] = [0u8; 32];
    repr.copy_from_slice(&buf[0..32]);
    let s = Scalar::from_repr(repr).unwrap();

    //Update
    let s_adapted = s - secret;

    //Write
    //real_shares[i] = s_adapted;
    unsafe {
        update_signatureshare(&mut real_shares[0], s_adapted);
    }
    real_shares
}
