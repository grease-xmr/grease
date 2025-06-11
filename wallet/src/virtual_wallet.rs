use blake2::Digest;
use dalek_ff_group::dalek::constants::ED25519_BASEPOINT_POINT;
use dalek_ff_group::{dalek::Scalar as DScalar, EdwardsPoint, Scalar};
use modular_frost::curve::{Ciphersuite, Ed25519};
use monero_simple_request_rpc::SimpleRequestRpc;
use rand_chacha::ChaCha20Rng;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::Path;
use zeroize::Zeroizing;

use libgrease::crypto::keys::{Curve25519PublicKey, Curve25519Secret};
use libgrease::monero::data_objects::MultisigWalletData;
use log::debug;
use modular_frost::dkg::musig::musig;
use modular_frost::dkg::DkgError;
use modular_frost::sign::{Preprocess, PreprocessMachine, SignMachine, SignatureMachine, SignatureShare};
use modular_frost::{FrostError, Participant, ThresholdKeys, ThresholdParams};
use monero_rpc::{FeeRate, Rpc, RpcError, ScannableBlock};
use monero_serai::block::Block;
use monero_serai::ringct::clsag::ClsagAddendum;
use monero_serai::ringct::RctType;
use monero_serai::transaction::Transaction;
use monero_wallet::address::{AddressType, MoneroAddress, Network, SubaddressIndex};
use monero_wallet::send::{
    Change, SendError, SignableTransaction, TransactionSignMachine, TransactionSignatureMachine,
};
use monero_wallet::{OutputWithDecoys, Scanner, ViewPair, WalletOutput};
use rand_core::{OsRng, SeedableRng};
use thiserror::Error;

pub type Commitment = Preprocess<Ed25519, ClsagAddendum>;

#[derive(Debug, Clone, Error)]
pub enum WalletError {
    #[error("RPC Error: {0}")]
    RpcError(#[from] RpcError),
    #[error("Key Error: {0}")]
    KeyError(String),
    #[error("Not enough funds in wallet, or blockchain needs to be scanned")]
    InsufficientFunds,
    #[error("Transaction creation error: {0}")]
    SendError(#[from] SendError),
    #[error("Multisig protocol error: {0}")]
    FrostError(#[from] FrostError),
    #[error("Error deserializing: {0}")]
    DeserializeError(String),
}

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
    preprocess_data: Option<Vec<Commitment>>,
    sign_machine: Option<TransactionSignMachine>,
    shares: Option<Vec<SignatureShare<Ed25519>>>,
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
            shares: None,
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
        let peer_pubkey =
            if &data.my_public_key == &sorted_pubkeys[0] { &sorted_pubkeys[1] } else { &sorted_pubkeys[0] };
        let musig_keys = musig_2_of_2(&data.my_spend_key, &sorted_pubkeys)
            .map_err(|_| WalletError::KeyError("MuSig key generation failed".into()))?;
        let (joint_private_view_key, joint_public_view_key) = musig_dh_viewkey(&data.my_spend_key, peer_pubkey);
        let joint_private_view_key = Curve25519Secret::from(joint_private_view_key.0);
        let joint_public_view_key = Curve25519PublicKey::from(joint_public_view_key.0);
        let joint_public_spend_key = musig_keys.group_key();
        let joint_public_spend_key = Curve25519PublicKey::from(joint_public_spend_key.0);
        let known_outputs =
            hex::decode(&data.known_outputs).map_err(|e| WalletError::DeserializeError(e.to_string()))?;
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
            shares: None,
            final_signer: None,
        })
    }

    pub fn address(&self) -> MoneroAddress {
        MoneroAddress::new(
            Network::Mainnet,
            AddressType::Legacy,
            self.joint_public_spend_key.as_point().clone(),
            self.joint_public_view_key.as_point().clone(),
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
        let pair = ViewPair::new(self.joint_public_spend_key.as_point().clone(), k)
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

    pub fn get_change_output(&self) -> Result<Change, WalletError> {
        let key = self.joint_public_spend_key();
        let vk = view_key(key, 0);
        let pair = ViewPair::new(key.as_point().clone(), vk).map_err(|e| WalletError::KeyError(e.to_string()))?;
        let index = SubaddressIndex::new(0, 1).expect("not to fail with valid hardcoded params");
        Ok(Change::new(pair, Some(index)))
    }

    async fn pre_process(&self, payments: Vec<(MoneroAddress, u64)>) -> Result<SignableTransaction, WalletError> {
        const MAX_OUTPUTS: usize = 16;
        const MINIMUM_FEE: u64 = 1_500_000;
        // max payments must take change into account
        if payments.len() + 1 > MAX_OUTPUTS {
            return Err(WalletError::SendError(SendError::TooManyOutputs));
        }
        if self.known_outputs.is_empty() {
            return Err(WalletError::SendError(SendError::NoInputs));
        }
        let fee_rate = FeeRate::new(MINIMUM_FEE, 1000)?;
        // Get reference block
        let refblock_height = self.get_height().await? as usize - 1;
        let block = self.rpc.get_block_by_number(refblock_height).await?;

        // Determine the RCT proofs to make based off the hard fork
        let (rct_type, ring_len) = match block.header.hardfork_version {
            14 => (RctType::ClsagBulletproof, 10),
            15 | 16 => (RctType::ClsagBulletproofPlus, 16),
            _ => return Err(WalletError::SendError(SendError::UnsupportedRctType)),
        };

        let spend_total = MINIMUM_FEE + payments.iter().map(|(_, amount)| *amount).sum::<u64>();

        // If this returns, there is guaranteed to be at least one input
        let inputs = self.find_spendable_outputs(spend_total)?;

        // We need a unique ID to distinguish this transaction from another transaction with an identical
        // set of payments (as our Eventualities only match over the payments). The output's ID is
        // guaranteed to be unique, making it satisfactory
        let id = inputs.first().unwrap().key().compress().to_bytes();

        // We need a deterministic RNG here with *some* seed. The unique ID means we don't pick some static seed
        // It is a public value, yet that's fine as this is assumed fully transparent.
        let mut rng = ChaCha20Rng::from_seed(id);
        let mut inputs_actual = Vec::with_capacity(inputs.len());
        for input in inputs {
            inputs_actual.push(
                OutputWithDecoys::fingerprintable_deterministic_new(
                    &mut rng,
                    &self.rpc,
                    ring_len,
                    refblock_height,
                    input.clone(),
                )
                .await?,
            );
        }
        let inputs = inputs_actual;
        // Create the change output.
        let change = self.get_change_output()?;

        let id = Zeroizing::new(id);
        let tx = SignableTransaction::new(rct_type, id, inputs, payments, change, vec![], fee_rate)?;
        Ok(tx)
    }

    pub async fn prepare(&mut self, payments: Vec<(MoneroAddress, u64)>) -> Result<(), WalletError> {
        let signable = self.pre_process(payments).await?;
        let machine = signable.multisig(self.musig_keys.clone())?;
        let (machine, preprocess) = machine.preprocess(&mut OsRng);
        if preprocess.len() != 1 {
            return Err(WalletError::KeyError(format!(
                "Expected exactly one preprocess. Got {}",
                preprocess.len()
            )));
        }
        debug!("Pre-processing complete with: {} commitments", preprocess.len());
        self.preprocess_data = Some(preprocess);
        self.sign_machine = Some(machine);
        Ok(())
    }

    pub fn my_pre_process_data(&self) -> Option<Vec<Commitment>> {
        self.preprocess_data.clone()
    }

    pub fn partial_sign(&mut self, peer_data: Vec<Commitment>) -> Result<(), WalletError> {
        if self.sign_machine.is_none() || self.preprocess_data.is_none() {
            return Err(WalletError::KeyError("Sign machine or preprocess data not initialized".into()));
        }
        let machine = self.sign_machine.take().unwrap();
        debug!("peer data length: {}", peer_data.len());
        debug!("my preprocess data length: {}", self.preprocess_data.as_ref().unwrap().len());
        let commitments = self.assign_commitments(peer_data);
        let (tx_machine, shares) = machine.sign(commitments, &[])?;
        debug!("Signing completed with {} shares", shares.len());
        self.shares = Some(shares);
        self.final_signer = Some(tx_machine);
        Ok(())
    }

    pub fn my_signing_shares(&self) -> Option<Vec<SignatureShare<Ed25519>>> {
        self.shares.clone()
    }

    pub fn sign(&mut self, peer_shares: Vec<SignatureShare<Ed25519>>) -> Result<Transaction, WalletError> {
        if self.final_signer.is_none() || self.shares.is_none() {
            return Err(WalletError::KeyError("Final signer or shares not initialized".into()));
        }
        let machine = self.final_signer.take().unwrap();
        let shares = self.assign_shares(peer_shares);
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

    fn assign_commitments(&self, peer_data: Vec<Commitment>) -> HashMap<Participant, Vec<Commitment>> {
        let mut commitments = HashMap::new();
        let (me, them) = self.participants();
        debug!("Assigning commitments for participants: me={:?} and they={:?}", me, them);
        //commitments.insert(me, self.preprocess_data.clone().expect("We should have preprocess data"));
        commitments.insert(them, peer_data);
        commitments
    }

    fn assign_shares(
        &self,
        peer_shares: Vec<SignatureShare<Ed25519>>,
    ) -> HashMap<Participant, Vec<SignatureShare<Ed25519>>> {
        let mut shares = HashMap::new();
        let (me, them) = self.participants();
        debug!("Assigning commitments for participants: me={:?} and they={:?}", me, them);
        //shares.insert(me, self.shares.clone().expect("We should have signature shares"));
        shares.insert(them, peer_shares);
        shares
    }

    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<usize, std::io::Error> {
        let mut file = std::fs::File::create(path)?;
        self.write_outputs(&mut file)
    }

    pub fn write_outputs<W: Write>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        let mut written = 0usize;
        for output in &self.known_outputs {
            match output.write(writer) {
                Ok(()) => written += 1,
                Err(e) => {
                    eprintln!("Failed to write output: {}", e);
                }
            }
        }
        Ok(written)
    }

    pub fn load<P: AsRef<Path>>(&mut self, path: P) -> Result<usize, std::io::Error> {
        let mut file = std::fs::File::open(path)?;
        let new = Self::read_outputs(&mut file)?;
        let n = new.len();
        self.known_outputs.extend_from_slice(&new);
        Ok(n)
    }

    pub fn read_outputs<R: Read>(mut reader: R) -> Result<Vec<WalletOutput>, std::io::Error> {
        let mut outputs = Vec::<WalletOutput>::new();
        while let Ok(output) = WalletOutput::read(&mut reader) {
            outputs.push(output);
        }
        Ok(outputs)
    }

    pub fn serializable(&self) -> MultisigWalletData {
        let mut buf = Vec::with_capacity(self.known_outputs.len() * size_of::<WalletOutput>());
        self.write_outputs(&mut buf).expect("Failed to write outputs to buffer");
        MultisigWalletData {
            my_spend_key: self.my_spend_key.clone(),
            my_public_key: self.my_public_key.clone(),
            sorted_pubkeys: self.sorted_pubkeys.clone(),
            joint_private_view_key: self.joint_private_view_key.clone(),
            joint_public_spend_key: self.joint_public_spend_key.clone(),
            birthday: self.birthday,
            known_outputs: hex::encode(&buf),
        }
    }
}

pub fn threshold_params(p: &Participant) -> ThresholdParams {
    ThresholdParams::new(2, 2, p.clone()).expect("not to fail with valid hardcoded params")
}

pub fn musig_context(keys: &[Curve25519PublicKey; 2]) -> [u8; 64 + 5] {
    let mut result = [0u8; 64 + 5];
    result[..5].copy_from_slice(b"Musig");
    result[5..5 + 32].copy_from_slice(keys[0].as_compressed().as_bytes());
    result[5 + 32..5 + 64].copy_from_slice(keys[1].as_compressed().as_bytes());
    result
}

pub fn sort_pubkeys(keys: &mut [Curve25519PublicKey; 2]) {
    keys.sort_unstable_by(|a, b| a.as_compressed().as_bytes().cmp(&b.as_compressed().as_bytes()));
}

pub fn musig_2_of_2(
    secret: &Curve25519Secret,
    sorted_pubkeys: &[Curve25519PublicKey; 2],
) -> Result<ThresholdKeys<Ed25519>, DkgError<()>> {
    let context = musig_context(sorted_pubkeys);
    let secret = Zeroizing::new(Scalar(secret.as_scalar().clone()));
    let pubkeys: [EdwardsPoint; 2] = [
        EdwardsPoint(sorted_pubkeys[0].as_point().clone()),
        EdwardsPoint(sorted_pubkeys[1].as_point().clone()),
    ];
    let core = musig(&context[..], &secret, &pubkeys)?;
    Ok(ThresholdKeys::new(core))
}

pub fn musig_dh_viewkey(
    secret: &Curve25519Secret,
    other_key: &Curve25519PublicKey,
) -> (Zeroizing<Scalar>, EdwardsPoint) {
    let shared = other_key.as_point() * secret.as_scalar();
    let hashed =
        blake2::Blake2b512::new().chain_update(b"MuSigViewKey").chain_update(shared.compress().as_bytes()).finalize();
    let mut bytes = [0u8; 64];
    bytes[..].copy_from_slice(hashed.as_slice());
    let private_view_key = Scalar(DScalar::from_bytes_mod_order_wide(&bytes));
    let public_view_key = EdwardsPoint(private_view_key.0 * ED25519_BASEPOINT_POINT);
    (Zeroizing::new(private_view_key), public_view_key)
}

pub async fn get_highest_block(rpc: &SimpleRequestRpc) -> Result<Block, RpcError> {
    let height = rpc.get_height().await?;
    rpc.get_block_by_number(height - 1).await
}

pub fn view_key(spend_key: &Curve25519PublicKey, index: u64) -> Zeroizing<DScalar> {
    let mut data = [0u8; 32 + 8];
    data[..32].copy_from_slice(spend_key.as_compressed().as_bytes());
    data[32..].copy_from_slice(&index.to_le_bytes());
    let k = Ed25519::hash_to_F(b"GreaseMultisig", &data);
    Zeroizing::new(k.0)
}
