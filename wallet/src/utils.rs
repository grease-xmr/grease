use ciphersuite::group::ff::{Field, PrimeField};
use ciphersuite::group::GroupEncoding;
use dalek_ff_group::{dalek::Scalar as DScalar, EdwardsPoint, Scalar, ED25519_BASEPOINT_TABLE};
use monero_rpc::RpcError;
use monero_simple_request_rpc::SimpleRequestRpc;
use monero_wallet::{
    address::{AddressType, MoneroAddress, Network},
    block::Block,
    ringct::RctType,
    rpc::{FeeRate, Rpc},
    transaction::Transaction,
    Scanner, ViewPair, WalletOutput, DEFAULT_LOCK_WINDOW,
};
use rand_core::{OsRng, RngCore};
use serde::Deserialize;
use serde_json::json;
use std::ops::Deref;
use zeroize::Zeroizing;

pub fn keypair() -> (Zeroizing<Scalar>, EdwardsPoint) {
    let secret = Zeroizing::new(Scalar::random(OsRng));
    let public = EdwardsPoint(ED25519_BASEPOINT_TABLE * &secret.0);
    (secret, public)
}

pub fn random_key() -> [u8; 32] {
    let mut result = [0u8; 32];
    OsRng.fill_bytes(&mut result);
    result
}

pub fn scalar_as_hex(scalar: &Scalar) -> String {
    hex::encode(scalar.0.to_bytes())
}

pub fn point_as_hex(point: &EdwardsPoint) -> String {
    hex::encode(point.0.compress().as_bytes())
}

pub fn hex_to_point(hex: &str) -> Result<EdwardsPoint, String> {
    let mut repr = [0u8; 32];
    hex::decode_to_slice(&hex, &mut repr).map_err(|e| format!("Hex decode failed: {}", e))?;
    let point: Option<EdwardsPoint> = EdwardsPoint::from_bytes(&repr).into();
    match point {
        Some(p) => Ok(p),
        None => Err("String does not decode into a valid point".to_string()),
    }
}

pub fn hex_to_scalar(hex: &str) -> Result<Scalar, String> {
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(&hex, &mut bytes).map_err(|e| e.to_string())?;
    let decoded: Option<DScalar> = DScalar::from_canonical_bytes(bytes).into();
    match decoded {
        Some(v) => {
            let scalar = Scalar(v);
            Ok(scalar)
        }
        None => Err("string does not represent a canonical scalar".to_string()),
    }
}

pub fn ring_len(rct_type: RctType) -> usize {
    match rct_type {
        RctType::ClsagBulletproof => 11,
        RctType::ClsagBulletproofPlus => 16,
        _ => panic!("ring size unknown for RctType"),
    }
}

pub fn random_address() -> (Scalar, ViewPair, MoneroAddress) {
    let spend = Scalar::random(&mut OsRng);
    let spend_pub = ED25519_BASEPOINT_TABLE * &spend.0;
    let view = Zeroizing::new(Scalar::random(&mut OsRng).0);
    (
        spend,
        ViewPair::new(spend_pub, view.clone()).unwrap(),
        MoneroAddress::new(
            Network::Mainnet,
            AddressType::Legacy,
            spend_pub,
            view.deref() * ED25519_BASEPOINT_TABLE,
        ),
    )
}

pub async fn mine_until_unlocked(rpc: &SimpleRequestRpc, addr: &MoneroAddress, tx_hash: [u8; 32]) -> Block {
    // mine until tx is in a block
    let mut height = rpc.get_height().await.unwrap();
    let mut found = false;
    let mut block = None;
    while !found {
        let inner_block = rpc.get_block_by_number(height - 1).await.unwrap();
        found = match inner_block.transactions.iter().find(|&&x| x == tx_hash) {
            Some(_) => {
                block = Some(inner_block);
                true
            }
            None => {
                height = rpc.generate_blocks(addr, 1).await.unwrap().1 + 1;
                false
            }
        }
    }

    // Mine until tx's outputs are unlocked
    for _ in 0..(DEFAULT_LOCK_WINDOW - 1) {
        rpc.generate_blocks(addr, 1).await.unwrap();
    }

    block.unwrap()
}

// Mines 60 blocks and returns an unlocked miner TX output.
pub async fn get_miner_tx_output(rpc: &SimpleRequestRpc, view: &ViewPair) -> WalletOutput {
    let mut scanner = Scanner::new(view.clone());

    // Mine 60 blocks to unlock a miner TX
    let start = rpc.get_height().await.unwrap();
    rpc.generate_blocks(&view.legacy_address(Network::Mainnet), 60).await.unwrap();

    let block = rpc.get_block_by_number(start).await.unwrap();
    scanner.scan(rpc.get_scannable_block(block).await.unwrap()).unwrap().ignore_additional_timelock().swap_remove(0)
}

/// Make sure the weight and fee match the expected calculation.
pub fn check_weight_and_fee(tx: &Transaction, fee_rate: FeeRate) {
    let Transaction::V2 { proofs: Some(proofs), .. } = tx else { panic!("TX wasn't RingCT") };
    let fee = proofs.base.fee;

    let weight = tx.weight();
    let expected_weight = fee_rate.calculate_weight_from_fee(fee);
    assert_eq!(weight, expected_weight);

    let expected_fee = fee_rate.calculate_fee_from_weight(weight);
    assert_eq!(fee, expected_fee);
}

/// Sets up a local Monero network by creating a new RPC connection to a running node at `url` and then mining to 110
/// blocks if necessary to ensure decoy availability.
pub async fn setup_localnet(url: &str, addr: &MoneroAddress) -> SimpleRequestRpc {
    let rpc = SimpleRequestRpc::new(url.to_string()).await.unwrap();
    const BLOCKS_TO_MINE: usize = 110;
    // Only run once
    if rpc.get_height().await.unwrap() > BLOCKS_TO_MINE {
        return rpc;
    }
    // Mine enough blocks to ensure decoy availability
    rpc.generate_blocks(&addr, BLOCKS_TO_MINE).await.unwrap();
    rpc
}

pub async fn publish_transaction(rpc: &SimpleRequestRpc, tx: &Transaction) -> Result<(), RpcError> {
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

pub fn keys_from(s: &str) -> (Zeroizing<Scalar>, EdwardsPoint) {
    let bytes = hex::decode(s).unwrap();
    let mut repr = [0u8; 32];
    repr.copy_from_slice(&bytes[0..32]);
    let secret = Scalar::from_repr(repr).unwrap();
    let public = EdwardsPoint(ED25519_BASEPOINT_TABLE * &secret.0);
    (Zeroizing::new(secret), public)
}

pub fn scalar_from(s: &str) -> Scalar {
    let bytes = hex::decode(s).unwrap();
    let mut repr = [0u8; 32];
    repr.copy_from_slice(&bytes[0..32]);
    let scalar = Scalar::from_repr(repr).unwrap();
    scalar
}
