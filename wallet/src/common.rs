use crate::errors::WalletError;
use crate::{DScalar, MoneroAddress, SubaddressIndex};
use ciphersuite::{Ciphersuite, Ed25519};
use libgrease::cryptography::keys::{Curve25519PublicKey, Curve25519Secret};
use log::*;
use monero_rpc::{FeeRate, Rpc, RpcError};
use monero_serai::ringct::RctType;
use monero_serai::transaction::Transaction;
use monero_simple_request_rpc::SimpleRequestRpc;
use monero_wallet::send::{Change, SendError, SignableTransaction};
use monero_wallet::{OutputWithDecoys, Scanner, ViewPair, WalletOutput};
use rand_core::{CryptoRng, RngCore};
use serde::Deserialize;
use serde_json::json;
use zeroize::Zeroizing;

pub const MAX_OUTPUTS: usize = 16;
pub const MINIMUM_FEE: u64 = 1_500_000;

/// Scans the blockchain for outputs owned by the wallet.
///
/// Returns a tuple containing a vector of found outputs and the next block number to scan.
pub async fn scan_wallet(
    rpc: &SimpleRequestRpc,
    start: u64,
    end: Option<u64>,
    public_spend_key: &Curve25519PublicKey,
    private_view_key: &Curve25519Secret,
) -> Result<(Vec<WalletOutput>, u64), RpcError> {
    let k = private_view_key.to_dalek_scalar();
    let p = public_spend_key.as_point();
    let pair = ViewPair::new(p.0, k).map_err(|e| RpcError::InternalError(e.to_string()))?;
    let mut scanner = Scanner::new(pair);
    let height = match end {
        Some(h) => h,
        None => rpc.get_height().await.map(|height| height as u64)?,
    };
    let mut scanned = 0u64;
    let mut found = 0usize;
    let mut result = Vec::new();
    debug!("Scanning wallet from {start} to {height}");
    for block_num in start..height {
        let block = rpc.get_block_by_number(block_num as usize).await?;
        let scannable = rpc.get_scannable_block(block).await?;
        let outputs = scanner.scan(scannable).map_err(|e| RpcError::InternalError(e.to_string()))?;
        scanned += 1;
        let outputs = outputs.ignore_additional_timelock();
        if !outputs.is_empty() {
            debug!("Scanned {} outputs for block {block_num}", outputs.len());
            found += outputs.len();
            result.extend(outputs);
        }
    }
    debug!("Scanned {scanned} blocks. {found} outputs found");
    Ok((result, start + scanned))
}

pub async fn publish_transaction(rpc: &SimpleRequestRpc, tx: &Transaction) -> Result<(), WalletError> {
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

    if res.double_spend {
        return Err(WalletError::DoubleSpend);
    }
    if res.fee_too_low {
        return Err(WalletError::FeeTooLow);
    }
    if res.invalid_input {
        return Err(WalletError::InvalidInput);
    }
    if res.invalid_output {
        return Err(WalletError::InvalidOutput);
    }
    if res.low_mixin {
        return Err(WalletError::LowMixin);
    }
    if res.not_relayed {
        return Err(WalletError::NotRelayed);
    }
    if res.overspend {
        return Err(WalletError::Overspend);
    }
    if res.too_big {
        return Err(WalletError::TooBig);
    }
    if res.too_few_outputs {
        return Err(WalletError::TooFewOutputs);
    }
    info!("Transaction published successfully");
    Ok(())
}

// Credit to Serai Project for this function
pub async fn create_signable_tx<R: Send + Sync + RngCore + CryptoRng>(
    rpc: &SimpleRequestRpc,
    rng: &mut R,
    inputs: Vec<WalletOutput>,
    payments: Vec<(MoneroAddress, u64)>,
    change: Change,
    tx_data: Vec<Vec<u8>>,
) -> Result<SignableTransaction, WalletError> {
    // max payments must take change into account
    if payments.len() + 1 > MAX_OUTPUTS {
        return Err(WalletError::SendError(SendError::TooManyOutputs));
    }
    if inputs.is_empty() {
        return Err(WalletError::SendError(SendError::NoInputs));
    }
    let fee_rate = FeeRate::new(MINIMUM_FEE, 1000)?;
    // Get reference block
    let refblock_height = rpc.get_height().await? - 1;
    let block = rpc.get_block_by_number(refblock_height).await?;

    // Determine the RCT proofs to make based off the hard fork
    let (rct_type, ring_len) = match block.header.hardfork_version {
        14 => (RctType::ClsagBulletproof, 10),
        15 | 16 => (RctType::ClsagBulletproofPlus, 16),
        _ => return Err(WalletError::SendError(SendError::UnsupportedRctType)),
    };
    let mut inputs_actual = Vec::with_capacity(inputs.len());
    for input in inputs {
        inputs_actual.push(
            OutputWithDecoys::fingerprintable_deterministic_new(rng, rpc, ring_len, refblock_height, input.clone())
                .await?,
        );
    }
    let inputs = inputs_actual;
    let id = inputs.first().unwrap().key().compress().to_bytes();
    let id = Zeroizing::new(id);
    let tx = SignableTransaction::new(rct_type, id, inputs, payments, change, tx_data, fee_rate)?;
    Ok(tx)
}

pub(crate) fn view_key(spend_key: &Curve25519PublicKey, index: u64) -> Zeroizing<DScalar> {
    let mut data = [0u8; 32 + 8];
    data[..32].copy_from_slice(spend_key.to_compressed().as_bytes());
    data[32..].copy_from_slice(&index.to_le_bytes());
    let k = Ed25519::hash_to_F(b"Grease Wallet", &data);
    Zeroizing::new(k.0)
}

pub(crate) fn create_change(public_spend_key: &Curve25519PublicKey) -> Result<Change, WalletError> {
    let vk = view_key(public_spend_key, 0);
    let pair = ViewPair::new(public_spend_key.as_point().0, vk).map_err(|e| WalletError::KeyError(e.to_string()))?;
    let index = SubaddressIndex::new(0, 1).expect("not to fail with valid hardcoded params");
    Ok(Change::new(pair, Some(index)))
}
