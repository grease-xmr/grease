use libgrease::crypto::keys::{Curve25519PublicKey, Curve25519Secret};
use monero_rpc::RpcError;
use monero_simple_request_rpc::SimpleRequestRpc;
use monero_wallet::address::{MoneroAddress, Network};
use wallet::utils::publish_transaction;
use wallet::virtual_wallet::{MultisigWallet, WalletError};
use wallet::watch_only::WatchOnlyWallet;

#[tokio::main]
async fn main() -> Result<(), WalletError> {
    env_logger::try_init().unwrap_or_else(|_| {
        eprintln!("Failed to initialize logger, using default settings");
    });
    const ALICE: &str =
        "43i4pVer2tNFELvfFEEXxmbxpwEAAFkmgN2wdBiaRNcvYcgrzJzVyJmHtnh2PWR42JPeDVjE8SnyK3kPBEjSixMsRz8TncK";

    // Alice generates a keypair
    let (k_a, p_a) =
        Curve25519PublicKey::keypair_from_hex("8eb8a1fd0f2c42fa7508a8883addb0860a0c5e44c1c14605abb385375c533609")
            .unwrap();
    println!("Alice: {} / {}", k_a.as_hex(), p_a.as_hex());
    // Bob generates a keypair
    // Bob's address: 4BH2vFAir1iQCwi2RxgQmsL1qXmnTR9athNhpK31DoMwJgkpFUp2NykFCo4dXJnMhU7w9UZx7uC6qbNGuePkRLYcFo4N7p3
    let (k_b, p_b) =
        Curve25519PublicKey::keypair_from_hex("73ee459dd8a774afdbffafe6879ebc3b925fb23ceec9ac631f4ae02acff05f07")
            .unwrap();
    println!("Bob  : {} / {}", k_b.as_hex(), p_b.as_hex());

    // They exchange their public keys and create multisig wallets
    let rpc = SimpleRequestRpc::new("http://localhost:25070".into()).await?;
    let mut wallet_a = MultisigWallet::new(rpc.clone(), k_a, &p_a, &p_b, None)?;
    let mut wallet_b = MultisigWallet::new(rpc.clone(), k_b, &p_b, &p_a, None)?;

    assert_eq!(
        wallet_a.joint_public_spend_key(),
        wallet_b.joint_public_spend_key(),
        "Shared spend keys should be identical"
    );
    println!("Multisig wallet address for Alice: {}", wallet_a.address().to_string());
    println!("Multisig wallet address for Bob  : {}", wallet_b.address().to_string());

    println!("Joint Secret view key: {}", wallet_a.joint_private_view_key().as_hex());
    println!("Joint Public view key: {}", wallet_a.joint_public_view_key().as_hex());
    println!("Joint Public spend key: {}", wallet_a.joint_public_spend_key().as_hex());
    println!("Creating signing state machine...");

    // Pay Alice's external wallet
    let alice_wallet = MoneroAddress::from_str(Network::Mainnet, ALICE).unwrap();
    let payment = vec![(alice_wallet, 1_000u64)]; // Placeholder for payment, should be replaced with actual payment data

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
            let outputs = wallet.scan(None).await?;
            println!("{outputs} outputs found in scan");
            let saved = wallet.save("demo_wallet.bin").map_err(|e| RpcError::InternalError(e.to_string()))?;
            println!("Saved {saved} outputs to disk");
        }
    }
    println!("Outputs loaded");

    let _ = test_watch_only(
        wallet_a.joint_private_view_key(),
        wallet_a.joint_public_spend_key(),
        wallet_a.birthday(),
    )
    .await;

    wallet_b.prepare(payment.clone()).await?;
    wallet_a.prepare(payment.clone()).await?;

    println!("Preprocessing step completed for both wallets");

    wallet_a.partial_sign(wallet_b.my_pre_process_data().unwrap())?;
    println!("Partial Signing completed for Alice");
    let pp = wallet_a.my_pre_process_data().unwrap();
    wallet_b.partial_sign(pp)?;
    println!("Partial Signing completed for Bob");

    let ss = wallet_b.my_signing_shares().unwrap();

    println!("Signing shares prepared for Bob: {}", ss.len());

    let tx_a = wallet_a.sign(ss)?;
    println!("Alice's transaction signed successfully");
    let tx_b = wallet_b.sign(wallet_a.my_signing_shares().unwrap())?;
    println!("Bob's transaction signed successfully");

    println!("Wallet transaction from Alice: {}", hex::encode(tx_a.hash()));
    println!("Wallet transaction from Bob: {}", hex::encode(tx_b.hash()));

    println!("Sighash A: {}", hex::encode(tx_a.signature_hash().unwrap()));
    println!("Sighash B: {}", hex::encode(tx_b.signature_hash().unwrap()));

    println!("weight A: {}", tx_a.weight());
    println!("weight B: {}", tx_b.weight());

    publish_transaction(wallet_a.rpc(), &tx_a).await?;
    Ok(())
}

async fn test_watch_only(private_view_key: &Curve25519Secret, public_spend_key: &Curve25519PublicKey, birthday: u64) {
    let rpc = SimpleRequestRpc::new("http://localhost:25070".into()).await.expect("Failed to start rpc");
    let mut watch_only = WatchOnlyWallet::new(rpc, private_view_key.clone(), public_spend_key.clone(), Some(birthday))
        .expect("Unable to create wallet");
    let result = watch_only.scan(None, None).await.expect("Failed to scan wallet");
    println!("Watch-only wallet scanned, found {} outputs", result);
}
