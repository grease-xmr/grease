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

#[tokio::main]
async fn main() -> Result<(), WalletError> {
    env_logger::try_init().unwrap_or_else(|_| {
        eprintln!("Failed to initialize logger, using default settings");
    });
    const ALICE: &str =
        "43i4pVer2tNFELvfFEEXxmbxpwEAAFkmgN2wdBiaRNcvYcgrzJzVyJmHtnh2PWR42JPeDVjE8SnyK3kPBEjSixMsRz8TncK";
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
    // They exchange their public keys and create multisig wallets
    let rpc = SimpleRequestRpc::new("http://localhost:25070".into()).await?;
    let mut wallet_a = MultisigWallet::new(rpc.clone(), k_a, p_a, p_b, None)?;
    let mut wallet_b = MultisigWallet::new(rpc.clone(), k_b, p_b, p_a, None)?;

    assert_eq!(
        wallet_a.joint_public_spend_key(),
        wallet_b.joint_public_spend_key(),
        "Shared spend keys should be identical"
    );
    println!("Multisig wallet address for Alice: {}", wallet_a.address().to_string());
    println!("Multisig wallet address for Bob  : {}", wallet_b.address().to_string());

    println!("Creating signing state machine...");

    // Pay Alice's external wallet
    let alice_wallet = MoneroAddress::from_str(Network::Mainnet, ALICE).unwrap();
    let payment = vec![(alice_wallet, 1_000u64)]; // Placeholder for payment, should be replaced with actual payment data

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
            let outputs = wallet.scan().await?;
            info!("{outputs} outputs found in scan");
            let saved = wallet.save("demo_wallet.bin").map_err(|e| RpcError::InternalError(e.to_string()))?;
            info!("Saved {saved} outputs to disk");
        }
    }

    wallet_b.prepare(payment.clone()).await?;
    wallet_a.prepare(payment.clone()).await?;

    info!("Preprocessing step completed for both wallets");

    wallet_a.partial_sign(wallet_b.my_pre_process_data().unwrap())?;
    info!("Partial Signing completed for Alice");
    let pp = wallet_a.my_pre_process_data().unwrap();
    wallet_b.partial_sign(pp)?;
    info!("Partial Signing completed for Bob");

    let ss = wallet_b.my_signing_shares().unwrap();

    info!("Signing shares prepared for Bob: {}", ss.len());

    let tx_a = wallet_a.sign(ss)?;
    info!("Alice's transaction signed successfully");
    let tx_b = wallet_b.sign(wallet_a.my_signing_shares().unwrap())?;
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

fn keys_from(s: &str) -> (Zeroizing<Scalar>, EdwardsPoint) {
    let bytes = hex::decode(s).unwrap();
    let mut repr = [0u8; 32];
    repr.copy_from_slice(&bytes[0..32]);
    let secret = Scalar::from_repr(repr).unwrap();
    let public = EdwardsPoint(ED25519_BASEPOINT_TABLE * &secret.0);
    (Zeroizing::new(secret), public)
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
