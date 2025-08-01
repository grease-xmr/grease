use blake2::Digest;
use dalek_ff_group::dalek::constants::ED25519_BASEPOINT_POINT;
use dalek_ff_group::{dalek::Scalar as DScalar, EdwardsPoint, Scalar};
use modular_frost::curve::Ed25519;
use monero_simple_request_rpc::SimpleRequestRpc;
use rand_chacha::ChaCha20Rng;
use std::collections::HashMap;
use std::mem;
use std::path::Path;
use zeroize::Zeroizing;

use crate::common::{create_change, create_signable_tx, MINIMUM_FEE};
use crate::errors::WalletError;
use libgrease::amount::MoneroAmount;
use libgrease::crypto::keys::{Curve25519PublicKey, Curve25519Secret};
use libgrease::crypto::zk_objects::AdaptedSignature;
use libgrease::crypto::zk_objects::GenericPoint;
use libgrease::monero::data_objects::MultisigWalletData;
use log::*;
use modular_frost::dkg::musig::musig;
use modular_frost::dkg::DkgError;
use modular_frost::sign::{Preprocess, PreprocessMachine, SignMachine, SignatureMachine, SignatureShare, Writable};
use modular_frost::{Participant, ThresholdKeys};
use monero::{Address as UAddress, AddressType as UAddressType};
use monero_rpc::{Rpc, RpcError, ScannableBlock};
use monero_serai::block::Block;
use monero_serai::ringct::clsag::ClsagAddendum;
use monero_serai::transaction::Transaction;
use monero_wallet::address::{AddressType, MoneroAddress, Network};
use monero_wallet::send::{SignableTransaction, TransactionSignMachine, TransactionSignatureMachine};
use monero_wallet::{Scanner, ViewPair, WalletOutput};
use rand_core::{CryptoRng, RngCore, SeedableRng};

pub type MoneroPreprocess = Preprocess<Ed25519, ClsagAddendum>;

pub struct MultisigWallet {
    rpc: SimpleRequestRpc,
    my_spend_key: Curve25519Secret,
    my_public_key: Curve25519PublicKey,
    sorted_pubkeys: [Curve25519PublicKey; 2],
    musig_keys: ThresholdKeys<Ed25519>,
    joint_private_view_key: Curve25519Secret,
    joint_public_view_key: Curve25519PublicKey,
    joint_public_spend_key: Curve25519PublicKey,
    birthday: u64,
    known_outputs: Vec<WalletOutput>,
    preprocess_data: Option<Vec<MoneroPreprocess>>,
    sign_machine: Option<TransactionSignMachine>,
    shared_spend_key: Option<SignatureShare<Ed25519>>,
    final_signer: Option<TransactionSignatureMachine>,
}

impl MultisigWallet {
    pub fn new(
        rpc: SimpleRequestRpc,
        spend_key: Curve25519Secret,
        public_spend_key: &Curve25519PublicKey,
        peer_pubkey: &Curve25519PublicKey,
        birthday: Option<u64>,
    ) -> Result<Self, WalletError> {
        let mut pubkeys = [public_spend_key.clone(), peer_pubkey.clone()];
        sort_pubkeys(&mut pubkeys);
        let musig_keys = musig_2_of_2(&spend_key, &pubkeys)
            .map_err(|_| WalletError::KeyError("MuSig key generation failed".into()))?;
        let (jprv_vk, j_pub_vk) = musig_dh_viewkey(&spend_key, peer_pubkey);
        let joint_private_view_key = Curve25519Secret::from(jprv_vk.0);
        let joint_public_view_key = Curve25519PublicKey::from(j_pub_vk.0);
        let joint_public_spend_key = Curve25519PublicKey::from(musig_keys.group_key().0);
        Ok(MultisigWallet {
            rpc,
            my_spend_key: spend_key,
            my_public_key: public_spend_key.clone(),
            sorted_pubkeys: pubkeys,
            musig_keys,
            joint_private_view_key,
            joint_public_view_key,
            joint_public_spend_key,
            birthday: birthday.unwrap_or_default(),
            known_outputs: Vec::new(),
            preprocess_data: None,
            sign_machine: None,
            shared_spend_key: None,
            final_signer: None,
        })
    }

    /// Set the wallet's birthday, which is the block height from which the wallet should start scanning to the
    /// current block height.
    pub async fn reset_birthday(&mut self) -> Result<u64, WalletError> {
        let height = self.rpc.get_height().await? as u64;
        self.birthday = height;
        Ok(height)
    }

    pub fn birthday(&self) -> u64 {
        self.birthday
    }

    pub fn my_public_key(&self) -> &Curve25519PublicKey {
        &self.my_public_key
    }

    pub fn peer_public_key(&self) -> &Curve25519PublicKey {
        if self.sorted_pubkeys[0] == self.my_public_key {
            &self.sorted_pubkeys[1]
        } else {
            &self.sorted_pubkeys[0]
        }
    }

    pub fn from_serializable(rpc: SimpleRequestRpc, data: MultisigWalletData) -> Result<Self, WalletError> {
        let mut sorted_pubkeys = data.sorted_pubkeys;
        sort_pubkeys(&mut sorted_pubkeys);
        let peer_pubkey = if data.my_public_key == sorted_pubkeys[0] { &sorted_pubkeys[1] } else { &sorted_pubkeys[0] };
        let musig_keys = musig_2_of_2(&data.my_spend_key, &sorted_pubkeys)
            .map_err(|_| WalletError::KeyError("MuSig key generation failed".into()))?;
        let (joint_private_view_key, joint_public_view_key) = musig_dh_viewkey(&data.my_spend_key, peer_pubkey);
        let joint_private_view_key = Curve25519Secret::from(joint_private_view_key.0);
        let joint_public_view_key = Curve25519PublicKey::from(joint_public_view_key.0);
        let joint_public_spend_key = musig_keys.group_key();
        let joint_public_spend_key = Curve25519PublicKey::from(joint_public_spend_key.0);
        let known_outputs = data.known_outputs;
        let known_outputs =
            Self::read_outputs(known_outputs.as_slice()).map_err(|e| WalletError::DeserializeError(e.to_string()))?;
        Ok(Self {
            rpc,
            my_spend_key: data.my_spend_key,
            my_public_key: data.my_public_key,
            sorted_pubkeys,
            musig_keys,
            joint_private_view_key,
            joint_public_view_key,
            joint_public_spend_key,
            birthday: data.birthday,
            known_outputs,
            preprocess_data: None,
            sign_machine: None,
            shared_spend_key: None,
            final_signer: None,
        })
    }

    pub fn address(&self) -> MoneroAddress {
        MoneroAddress::new(
            Network::Mainnet,
            AddressType::Legacy,
            self.joint_public_spend_key.as_point(),
            self.joint_public_view_key.as_point(),
        )
    }

    pub fn my_spend_key(&self) -> &Curve25519Secret {
        &self.my_spend_key
    }

    pub async fn get_height(&self) -> Result<u64, RpcError> {
        self.rpc.get_height().await.map(|height| height as u64)
    }

    pub async fn get_block_by_number(&self, block_num: u64) -> Result<Block, RpcError> {
        self.rpc.get_block_by_number(block_num as usize).await
    }

    async fn get_scannable_block(&self, block: Block) -> Result<ScannableBlock, RpcError> {
        self.rpc.get_scannable_block(block).await
    }

    pub async fn scan(&mut self, start: Option<u64>) -> Result<usize, RpcError> {
        let k = self.joint_private_view_key.as_zscalar().clone();
        let pair = ViewPair::new(self.joint_public_spend_key.as_point(), k)
            .map_err(|e| RpcError::InternalError(e.to_string()))?;
        let mut scanner = Scanner::new(pair);
        let height = self.get_height().await?;
        let mut scanned = 0usize;
        let mut found = 0usize;
        let start = start.unwrap_or(self.birthday);
        for block_num in start..height {
            let block = self.get_block_by_number(block_num).await?;
            let scannable = self.get_scannable_block(block).await?;
            let outputs = scanner.scan(scannable).map_err(|e| RpcError::InternalError(e.to_string()))?;
            scanned += 1;
            let outputs = outputs.not_additionally_locked();
            if !outputs.is_empty() {
                debug!("Scanned {} outputs for block {block_num}", outputs.len());
                found += outputs.len();
                self.known_outputs.extend(outputs);
            }
        }
        debug!("Scanned {scanned} blocks. {found} outputs found");
        Ok(found)
    }

    pub fn import_output(&mut self, serialized: &Vec<u8>) -> Result<(), WalletError> {
        let mut reader = serialized.as_slice();
        let output = WalletOutput::read(&mut reader).map_err(|e| WalletError::DeserializeError(e.to_string()))?;
        self.known_outputs.push(output);
        Ok(())
    }

    pub fn outputs(&self) -> &[WalletOutput] {
        &self.known_outputs
    }

    pub fn rpc(&self) -> &SimpleRequestRpc {
        &self.rpc
    }

    pub fn find_spendable_outputs(&self, min_amount: u64) -> Result<Vec<WalletOutput>, WalletError> {
        if self.known_outputs.is_empty() {
            return Err(WalletError::InsufficientFunds);
        }
        let mut result = Vec::new();
        let mut total = 0;
        for output in &self.known_outputs {
            result.push(output.clone());
            total += output.commitment().amount;
            if total >= min_amount {
                return Ok(result);
            }
        }
        Err(WalletError::InsufficientFunds)
    }

    pub fn joint_public_spend_key(&self) -> &Curve25519PublicKey {
        &self.joint_public_spend_key
    }

    pub fn joint_public_view_key(&self) -> &Curve25519PublicKey {
        &self.joint_public_view_key
    }

    pub fn joint_private_view_key(&self) -> &Curve25519Secret {
        &self.joint_private_view_key
    }

    async fn pre_process<R: Send + Sync + RngCore + CryptoRng>(
        &self,
        payments: Vec<(MoneroAddress, u64)>,
        rng: &mut R,
    ) -> Result<SignableTransaction, WalletError> {
        let rpc = self.rpc();
        let change = create_change(self.joint_public_spend_key())?;
        let spend_total = MINIMUM_FEE + payments.iter().map(|(_, amount)| *amount).sum::<u64>();
        // If this returns, there is guaranteed to be at least one input
        let inputs = self.find_spendable_outputs(spend_total)?;
        create_signable_tx(rpc, rng, inputs, payments, change, vec![]).await
    }

    /// If you need to restore the wallet to an exact know last state, you should call `prepare` with the RNG
    /// returned by this function.
    pub fn deterministic_rng(&self) -> ChaCha20Rng {
        // Use the spend key as a seed for the RNG, which is unique to this wallet instance
        let bytes = self.joint_private_view_key.as_scalar().as_bytes();
        let hashed = blake2::Blake2b512::digest(bytes);
        let mut seed = [0; 32];
        seed.copy_from_slice(&hashed[..32]);
        ChaCha20Rng::from_seed(seed)
    }

    /// Prepare the multisig wallet for signing a transaction. The nonce is a random value that
    /// a. Must be get private and
    /// b. Never be reused (unless deterministically reconstructing this wallet).
    pub async fn prepare<R: Send + Sync + RngCore + CryptoRng>(
        &mut self,
        payments: Vec<(MoneroAddress, u64)>,
        rng: &mut R,
    ) -> Result<(), WalletError> {
        let signable = self.pre_process(payments, rng).await?;
        let machine = signable.multisig(self.musig_keys.clone())?;
        let (machine, preprocess) = machine.preprocess(rng);
        if preprocess.len() != 1 {
            return Err(WalletError::KeyError(format!(
                "Expected exactly one preprocess. Got {}",
                preprocess.len()
            )));
        }
        self.preprocess_data = Some(preprocess);
        self.sign_machine = Some(machine);
        Ok(())
    }

    pub fn my_pre_process_data(&self) -> Option<Vec<u8>> {
        self.preprocess_data.as_ref().and_then(|v| {
            v.first().map(|pp| {
                let mut buf = Vec::with_capacity(160);
                pp.write(&mut buf).unwrap();
                buf
            })
        })
    }

    pub fn partial_sign(&mut self, peer_data: &[u8]) -> Result<(), WalletError> {
        if self.sign_machine.is_none() || self.preprocess_data.is_none() {
            return Err(WalletError::KeyError("Sign machine or preprocess data not initialized".into()));
        }
        let data = peer_data.to_vec();
        let machine = self.sign_machine.take().unwrap();
        let preprocess = machine
            .read_preprocess(&mut data.as_slice())
            .map_err(|e| WalletError::SigningError(format!("Invalid preprocess data: {e}")))?;
        let commitments = self.assign_commitments(preprocess);
        let (tx_machine, mut shares) = machine.sign(commitments, &[])?;
        if shares.len() != 1 {
            error!(
                "There should only ever be one signature share, in a 2-of-2 wallet but got {}",
                shares.len()
            );
        }
        self.shared_spend_key = Some(shares.remove(0));
        self.final_signer = Some(tx_machine);
        Ok(())
    }

    pub fn verify_adapted_signature(&self, _adapted: &AdaptedSignature) -> Result<(), WalletError> {
        // TODO: Implement verification logic for adapted signatures
        Ok(())
    }

    pub fn my_signing_share(&self) -> Option<SignatureShare<Ed25519>> {
        self.shared_spend_key.clone()
    }

    pub fn adapt_signature(
        &self,
        witness: &Curve25519Secret,
        statement: &GenericPoint,
    ) -> Result<AdaptedSignature, WalletError> {
        let real_sig = self
            .my_signing_share()
            .ok_or_else(|| WalletError::SigningError("No signature share available to adapt".into()))?;
        let real_sig = signature_share_to_secret(real_sig);
        let adapted = real_sig.as_scalar() + witness.as_scalar();
        Ok(AdaptedSignature::new(&Curve25519Secret::from(adapted), statement))
    }

    pub fn bytes_to_signature_share(&self, bytes: &[u8]) -> Result<SignatureShare<Ed25519>, WalletError> {
        let mut reader = bytes;
        let machine = self.final_signer.as_ref().ok_or_else(|| {
            WalletError::SigningError("Call partial_sign before trying to read a signature share".into())
        })?;
        let mut share = machine
            .read_share(&mut reader)
            .map_err(|e| WalletError::SigningError(format!("Invalid signature share: {e}")))?;
        if share.len() != 1 {
            return Err(WalletError::SigningError(
                "There should only be 1 share in a 2-of-2 wallet".into(),
            ));
        }
        Ok(share.remove(0))
    }
    pub fn extract_true_signature(
        &self,
        adapted: &AdaptedSignature,
        offset: &Curve25519Secret,
    ) -> Result<SignatureShare<Ed25519>, WalletError> {
        let sig = adapted.as_scalar() - offset.as_scalar();
        let bytes = sig.as_bytes();
        let sig = self.bytes_to_signature_share(bytes)?;
        Ok(sig)
    }

    pub fn sign(&mut self, peer_share: &SignatureShare<Ed25519>) -> Result<Transaction, WalletError> {
        if self.final_signer.is_none() || self.shared_spend_key.is_none() {
            return Err(WalletError::KeyError("Final signer or shares not initialized".into()));
        }
        let machine = self.final_signer.take().unwrap();
        let shares = self.assign_shares(vec![peer_share.clone()]);
        let tx = machine.complete(shares)?;
        debug!("Final signing completed");
        Ok(tx)
    }

    fn participants(&self) -> (Participant, Participant) {
        let first = self.sorted_pubkeys[0] == self.my_public_key;
        if first {
            (Participant::new(1).unwrap(), Participant::new(2).unwrap())
        } else {
            (Participant::new(2).unwrap(), Participant::new(1).unwrap())
        }
    }

    fn assign_commitments(&self, peer_data: Vec<MoneroPreprocess>) -> HashMap<Participant, Vec<MoneroPreprocess>> {
        let mut commitments = HashMap::new();
        let (me, them) = self.participants();
        trace!("Assigning commitments for participants: me={:?} and they={:?}", me, them);
        commitments.insert(them, peer_data);
        commitments
    }

    fn assign_shares(
        &self,
        peer_shares: Vec<SignatureShare<Ed25519>>,
    ) -> HashMap<Participant, Vec<SignatureShare<Ed25519>>> {
        let mut shares = HashMap::new();
        let (me, them) = self.participants();
        trace!("Assigning commitments for participants: me={:?} and they={:?}", me, them);
        shares.insert(them, peer_shares);
        shares
    }

    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<usize, std::io::Error> {
        let mut file = std::fs::File::create(path)?;
        let result = self.known_outputs.iter().map(|output| output.write(&mut file)).collect::<Result<Vec<_>, _>>()?;
        info!("Saved known outputs");
        Ok(result.len())
    }

    pub fn load<P: AsRef<Path>>(&mut self, path: P) -> Result<usize, std::io::Error> {
        let mut file = std::fs::File::open(path)?;
        let mut n = 0;
        while let Ok(output) = WalletOutput::read(&mut file) {
            self.known_outputs.push(output);
            n += 1;
        }
        Ok(n)
    }

    pub fn read_outputs(outputs: &[Vec<u8>]) -> Result<Vec<WalletOutput>, std::io::Error> {
        let wallet_outputs = outputs
            .iter()
            .map(|output| {
                let mut reader = output.as_slice();
                WalletOutput::read(&mut reader)
            })
            .collect::<Result<Vec<WalletOutput>, _>>()?;
        Ok(wallet_outputs)
    }

    pub fn serializable(&self) -> MultisigWalletData {
        let mut known_outputs = Vec::with_capacity(self.known_outputs.len());
        self.outputs().iter().for_each(|output| {
            let mut buf = Vec::with_capacity(size_of::<WalletOutput>());
            output.write(&mut buf).expect("Failed to write output to buffer");
            known_outputs.push(buf);
        });
        MultisigWalletData {
            my_spend_key: self.my_spend_key.clone(),
            my_public_key: self.my_public_key.clone(),
            sorted_pubkeys: self.sorted_pubkeys.clone(),
            joint_private_view_key: self.joint_private_view_key.clone(),
            joint_public_spend_key: self.joint_public_spend_key.clone(),
            birthday: self.birthday,
            known_outputs,
        }
    }
}

/// Converts a vector of payments from the state machine into one that can be used by the wallet.
/// Also accounts for fees.
pub fn translate_payments(
    unadjusted: [(UAddress, MoneroAmount); 2],
    fee: MoneroAmount,
) -> Result<Vec<(MoneroAddress, u64)>, WalletError> {
    if unadjusted[0].1 + unadjusted[1].1 <= fee {
        return Err(WalletError::InsufficientFunds);
    };
    // split fee equally between the two addresses if possible
    let fee = fee.to_piconero();
    let fair_share = fee / 2;
    let fee_0 = unadjusted[0].1.to_piconero().min(fair_share);
    let val0 = unadjusted[0].1.to_piconero() - fee_0;
    let val1 = unadjusted[1].1.to_piconero() - (fee - fee_0);
    Ok(vec![
        (convert_address(unadjusted[0].0), val0),
        (convert_address(unadjusted[1].0), val1),
    ])
}

pub fn signature_share_to_secret(signature: SignatureShare<Ed25519>) -> Curve25519Secret {
    // Safety: SignatureShare<Ed25519> is a wrapper around a DScalar, as is Curve25519Secret
    let sig = unsafe {
        let scalar: DScalar = mem::transmute(signature);
        scalar
    };
    Curve25519Secret::from(sig)
}

pub fn signature_share_to_bytes(secret: &SignatureShare<Ed25519>) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64);
    secret.write(&mut buf).expect("Failed to write signature share to buffer");
    trace!("signature_share_to_bytes buf={}", buf.len());
    buf
}

pub fn convert_address(address: UAddress) -> MoneroAddress {
    let kind = match address.addr_type {
        UAddressType::Standard => AddressType::Legacy,
        UAddressType::Integrated(v) => AddressType::LegacyIntegrated(v.0),
        UAddressType::SubAddress => AddressType::Subaddress,
    };
    let network = match address.network {
        monero::Network::Mainnet => Network::Mainnet,
        monero::Network::Testnet => Network::Testnet,
        monero::Network::Stagenet => Network::Stagenet,
    };
    let spend = address.public_spend.point.decompress().expect("Addresses weren't compatible?");
    let view = address.public_view.point.decompress().expect("Addresses weren't compatible?");
    MoneroAddress::new(network, kind, spend, view)
}

fn musig_context(keys: &[Curve25519PublicKey; 2]) -> [u8; 64 + 5] {
    let mut result = [0u8; 64 + 5];
    result[..5].copy_from_slice(b"Musig");
    result[5..5 + 32].copy_from_slice(keys[0].as_compressed().as_bytes());
    result[5 + 32..5 + 64].copy_from_slice(keys[1].as_compressed().as_bytes());
    result
}

fn sort_pubkeys(keys: &mut [Curve25519PublicKey; 2]) {
    keys.sort_unstable_by(|a, b| a.as_compressed().as_bytes().cmp(b.as_compressed().as_bytes()));
}

fn musig_2_of_2(
    secret: &Curve25519Secret,
    sorted_pubkeys: &[Curve25519PublicKey; 2],
) -> Result<ThresholdKeys<Ed25519>, DkgError<()>> {
    let context = musig_context(sorted_pubkeys);
    let secret = Zeroizing::new(Scalar(*secret.as_scalar()));
    let pubkeys: [EdwardsPoint; 2] =
        [EdwardsPoint(sorted_pubkeys[0].as_point()), EdwardsPoint(sorted_pubkeys[1].as_point())];
    let core = musig(&context[..], &secret, &pubkeys)?;
    Ok(ThresholdKeys::new(core))
}

fn musig_dh_viewkey(secret: &Curve25519Secret, other_key: &Curve25519PublicKey) -> (Zeroizing<Scalar>, EdwardsPoint) {
    let shared = other_key.as_point() * secret.as_scalar();
    let hashed =
        blake2::Blake2b512::new().chain_update(b"MuSigViewKey").chain_update(shared.compress().as_bytes()).finalize();
    let mut bytes = [0u8; 64];
    bytes[..].copy_from_slice(hashed.as_slice());
    let private_view_key = Scalar(DScalar::from_bytes_mod_order_wide(&bytes));
    let public_view_key = EdwardsPoint(private_view_key.0 * ED25519_BASEPOINT_POINT);
    (Zeroizing::new(private_view_key), public_view_key)
}
