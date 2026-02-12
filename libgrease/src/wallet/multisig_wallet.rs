use crate::amount::MoneroAmount;
use crate::channel_id::ChannelId;
use crate::cryptography::adapter_signature::AdaptedSignature;
use crate::cryptography::keys::{Curve25519PublicKey, Curve25519Secret};
use crate::payment_channel::multisig_keyring::{musig_2_of_2, musig_dh_viewkey, sort_pubkeys};
use crate::payment_channel::multisig_negotioation::MultisigWalletKeyNegotiation;
use crate::payment_channel::{ChannelRole, HasRole};
use crate::wallet::common::{create_change, create_signable_tx, MINIMUM_FEE};
use crate::wallet::errors::WalletError;
use crate::XmrScalar;
use blake2::Digest;
use dalek_ff_group::dalek::Scalar as DScalar;
use log::*;
use modular_frost::curve::Ed25519;
use modular_frost::sign::{Preprocess, PreprocessMachine, SignMachine, SignatureMachine, SignatureShare, Writable};
use modular_frost::{Participant, ThresholdKeys};
use monero::{Address as UAddress, AddressType as UAddressType, Network};
use monero_rpc::{Rpc, RpcError, ScannableBlock};
use monero_serai::block::Block;
use monero_serai::ringct::clsag::ClsagAddendum;
use monero_serai::transaction::Transaction;
use monero_simple_request_rpc::SimpleRequestRpc;
use monero_wallet::address::{AddressType, MoneroAddress, Network as MoneroNetwork};
use monero_wallet::send::{SignableTransaction, TransactionSignMachine, TransactionSignatureMachine};
use monero_wallet::{Scanner, ViewPair, WalletOutput};
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, OsRng, RngCore, SeedableRng};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use std::mem;
use std::path::Path;
use std::sync::{Arc, RwLock};

pub type MoneroPreprocess = Preprocess<Ed25519, ClsagAddendum>;
pub type AdaptSig = AdaptedSignature<Ed25519>;

#[derive(Serialize)]
pub struct MultisigWallet {
    #[serde(
        deserialize_with = "crate::monero::helpers::deserialize_network",
        serialize_with = "crate::monero::helpers::serialize_network"
    )]
    network: Network,
    role: ChannelRole,
    rpc_url: String,
    #[serde(skip)]
    rpc: Arc<RwLock<Option<Arc<SimpleRequestRpc>>>>,
    my_spend_key: Curve25519Secret,
    my_public_key: Curve25519PublicKey,
    sorted_pubkeys: [Curve25519PublicKey; 2],
    #[serde(skip)]
    musig_keys: ThresholdKeys<Ed25519>,
    #[serde(skip)]
    joint_private_view_key: Curve25519Secret,
    #[serde(skip)]
    joint_public_view_key: Curve25519PublicKey,
    #[serde(skip)]
    joint_public_spend_key: Curve25519PublicKey,
    birthday: u64,
    #[serde(
        serialize_with = "crate::wallet::helpers::serialize_outputs",
        deserialize_with = "crate::wallet::helpers::deserialize_outputs"
    )]
    known_outputs: Vec<WalletOutput>,
    peer_preprocess_data: Option<Vec<u8>>,
    // The signing state machine can't be cloned or serialized. After cloning or deserialization, you have to make another async call to
    // `prepare` to initialize it. We only store the preprocess data so that we avoid an async call when we want to sign the tx
    #[serde(skip)]
    preprocess_data: Option<Vec<MoneroPreprocess>>,
    #[serde(skip)]
    sign_machine: Option<TransactionSignMachine>,
    #[serde(skip)]
    shared_spend_key: Option<SignatureShare<Ed25519>>,
    #[serde(skip)]
    final_signer: Option<TransactionSignatureMachine>,
}

impl Debug for MultisigWallet {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("MultisigWallet")?;
        f.write_str(&format!("({}, {})", self.role, self.rpc_url))
    }
}

impl Clone for MultisigWallet {
    fn clone(&self) -> Self {
        // Recompute musig_keys since ThresholdKeys doesn't impl Clone
        let musig_keys = musig_2_of_2(&self.my_spend_key, &self.sorted_pubkeys)
            .expect("Failed to recompute musig keys during clone");

        MultisigWallet {
            network: self.network,
            role: self.role,
            rpc_url: self.rpc_url.clone(),
            rpc: Arc::clone(&self.rpc),
            my_spend_key: self.my_spend_key.clone(),
            my_public_key: self.my_public_key.clone(),
            sorted_pubkeys: self.sorted_pubkeys,
            musig_keys,
            joint_private_view_key: self.joint_private_view_key.clone(),
            joint_public_view_key: self.joint_public_view_key.clone(),
            joint_public_spend_key: self.joint_public_spend_key.clone(),
            birthday: self.birthday,
            known_outputs: self.known_outputs.clone(),
            peer_preprocess_data: self.peer_preprocess_data.clone(),
            preprocess_data: None,
            sign_machine: None,
            shared_spend_key: None,
            final_signer: None,
        }
    }
}

/// Generate the adapter signature message for a commitment transaction.
///
/// This binds the signature to the channel ID and state index, ensuring
/// the adapted signature is only valid for the specific commitment transaction state.
/// Both parties can compute this message independently before the transaction is built.
///
/// # Parameters
/// - `channel_id`: The unique channel identifier
/// - `state_index`: The state update index (0 for initial commitment)
/// - `customer_amount`: Customer's balance in piconero
/// - `merchant_amount`: Merchant's balance in piconero
pub fn commitment_tx_message(
    channel_id: &ChannelId,
    state_index: u64,
    customer_amount: u64,
    merchant_amount: u64,
) -> Vec<u8> {
    use blake2::Blake2b512;
    use flexible_transcript::{DigestTranscript, Transcript};

    let mut transcript = DigestTranscript::<Blake2b512>::new(b"Grease CommitmentTx v1");
    transcript.append_message(b"channel_id", channel_id.as_str().as_bytes());
    transcript.append_message(b"state_index", state_index.to_le_bytes());
    transcript.append_message(b"customer_amount", customer_amount.to_le_bytes());
    transcript.append_message(b"merchant_amount", merchant_amount.to_le_bytes());
    transcript.challenge(b"commitment_tx_message").to_vec()
}

impl MultisigWallet {
    pub fn new(
        network: Network,
        rpc_url: impl Into<String>,
        spend_key: Curve25519Secret,
        public_spend_key: &Curve25519PublicKey,
        peer_pubkey: &Curve25519PublicKey,
        birthday: Option<u64>,
        role: ChannelRole,
    ) -> Result<Self, WalletError> {
        let mut pubkeys = [*public_spend_key, *peer_pubkey];
        sort_pubkeys(&mut pubkeys);
        let musig_keys = musig_2_of_2(&spend_key, &pubkeys)
            .map_err(|_| WalletError::KeyError("MuSig key generation failed".into()))?;
        let (jprv_vk, j_pub_vk) = musig_dh_viewkey(&spend_key, peer_pubkey);
        let joint_private_view_key = Curve25519Secret::from(jprv_vk.0);
        let joint_public_view_key = Curve25519PublicKey::from(j_pub_vk);
        let joint_public_spend_key = Curve25519PublicKey::from(musig_keys.group_key());
        Ok(MultisigWallet {
            network,
            rpc_url: rpc_url.into(),
            rpc: Arc::new(RwLock::new(None)),
            my_spend_key: spend_key,
            my_public_key: *public_spend_key,
            sorted_pubkeys: pubkeys,
            musig_keys,
            joint_private_view_key,
            joint_public_view_key,
            joint_public_spend_key,
            birthday: birthday.unwrap_or_default(),
            known_outputs: Vec::new(),
            preprocess_data: None,
            peer_preprocess_data: None,
            sign_machine: None,
            shared_spend_key: None,
            final_signer: None,
            role,
        })
    }

    /// Lazily connect to the Monero RPC if not already connected and return a thread-safe reference to it.
    pub async fn rpc_connection(&self) -> Result<Arc<SimpleRequestRpc>, WalletError> {
        let lock =
            self.rpc.as_ref().read().map_err(|e| {
                WalletError::InternalError(format!("Failed to acquire read lock on RPC connection: {e}"))
            })?;
        if let Some(rpc) = lock.as_ref() {
            Ok(Arc::clone(rpc))
        } else {
            drop(lock);
            let mut lock = self.rpc.as_ref().write().unwrap();
            // Double check if another thread has already initialized the RPC connection while we were waiting for the write lock
            if let Some(rpc) = lock.as_ref() {
                Ok(Arc::clone(rpc))
            } else {
                let rpc = SimpleRequestRpc::new(self.rpc_url.clone()).await?;
                let rpc = Arc::new(rpc);
                *lock = Some(Arc::clone(&rpc));
                Ok(rpc)
            }
        }
    }

    /// Set the wallet's birthday, which is the block height from which the wallet should start scanning to the
    /// current block height.
    pub async fn reset_birthday(&mut self) -> Result<u64, WalletError> {
        let height = self.get_height().await?;
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

    pub fn address(&self) -> MoneroAddress {
        let network = match self.network {
            Network::Mainnet => MoneroNetwork::Mainnet,
            Network::Testnet => MoneroNetwork::Testnet,
            Network::Stagenet => MoneroNetwork::Stagenet,
        };
        MoneroAddress::new(
            network,
            AddressType::Legacy,
            self.joint_public_spend_key.as_point().0,
            self.joint_public_view_key.as_point().0,
        )
    }

    pub fn my_spend_key(&self) -> &Curve25519Secret {
        &self.my_spend_key
    }

    pub async fn get_height(&self) -> Result<u64, WalletError> {
        let rpc = self.rpc_connection().await?;
        let height = rpc.get_height().await.map(|height| height as u64)?;
        Ok(height)
    }

    pub async fn get_block_by_number(&self, block_num: u64) -> Result<Block, WalletError> {
        let rpc = self.rpc_connection().await?;
        let block = rpc.get_block_by_number(block_num as usize).await?;
        Ok(block)
    }

    async fn get_scannable_block(&self, block: Block) -> Result<ScannableBlock, WalletError> {
        let rpc = self.rpc_connection().await?;
        let block = rpc.get_scannable_block(block).await?;
        Ok(block)
    }

    pub async fn scan(&mut self, start: Option<u64>) -> Result<usize, WalletError> {
        let k = self.joint_private_view_key.to_dalek_scalar();
        let pair = ViewPair::new(self.joint_public_spend_key.as_point().0, k)
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
            let outputs = outputs.ignore_additional_timelock();
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

    pub fn rpc_url(&self) -> &str {
        self.rpc_url.as_str()
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

    /// If you need to restore the wallet to an exact known last state, you should call `prepare` with the RNG
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
    /// a. Must be treated as private and
    /// b. Never be reused (unless deterministically reconstructing this wallet).
    pub async fn prepare<R: Send + Sync + RngCore + CryptoRng>(
        &mut self,
        payments: Vec<(MoneroAddress, u64)>,
        rng: &mut R,
    ) -> Result<(), WalletError> {
        let signable = self.pre_process(payments, rng).await?;
        let machine = signable.multisig(&self.musig_keys)?;
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

    /// Sign the multisig transaction prepared by `prepare`.
    ///
    /// This function will return an error if
    /// * `prepare` has not been called, or
    /// *  if the preprocess data from the peer has not been set via `set_peer_process_data`
    pub fn partial_sign(&mut self) -> Result<(), WalletError> {
        if self.sign_machine.is_none() || self.preprocess_data.is_none() {
            return Err(WalletError::KeyError("Sign machine or preprocess data not initialized".into()));
        }
        if self.peer_preprocess_data.is_none() {
            return Err(WalletError::KeyError("Peer preprocess data not set".into()));
        }
        let data = self.peer_preprocess_data.clone().unwrap();
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

    pub fn my_signing_share(&self) -> Option<SignatureShare<Ed25519>> {
        self.shared_spend_key.clone()
    }

    pub fn set_peer_process_data(&mut self, data: Vec<u8>) {
        self.peer_preprocess_data = Some(data);
    }

    pub fn adapt_signature(&self, witness: &Curve25519Secret, msg: &[u8]) -> Result<AdaptSig, WalletError> {
        let secret = self
            .my_signing_share()
            .ok_or_else(|| WalletError::SigningError("No signature share available to adapt".into()))?;
        let secret = signature_share_to_scalar(secret);
        let mut rng = OsRng;
        let adapted = AdaptSig::sign(&secret, witness.as_scalar(), msg, &mut rng);
        Ok(adapted)
    }

    pub fn verify_adapted_signature(&self, adapted: &AdaptSig, msg: &[u8]) -> Result<(), WalletError> {
        let p = self.peer_public_key().as_point();
        match adapted.verify(&p, msg) {
            true => Ok(()),
            false => Err(WalletError::SigningError("Adapted signature verification failed".into())),
        }
    }

    pub fn extract_true_signature(
        &self,
        adapted: &AdaptSig,
        offset: &XmrScalar,
        msg: &[u8],
    ) -> Result<SignatureShare<Ed25519>, WalletError> {
        let p = self.peer_public_key().as_point();
        let true_sig = adapted.adapt(offset, &p, msg).map_err(|_| {
            WalletError::SigningError("Incorrect offset supplied. Adapter signature verification failed".into())
        })?;
        let bytes = true_sig.s().as_bytes();
        let share = self.bytes_to_signature_share(bytes)?;
        Ok(share)
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

    pub fn sign(&mut self, peer_share: SignatureShare<Ed25519>) -> Result<Transaction, WalletError> {
        if self.final_signer.is_none() || self.shared_spend_key.is_none() {
            return Err(WalletError::KeyError("Final signer or shares not initialized".into()));
        }
        let machine = self.final_signer.take().unwrap();
        let shares = self.assign_shares(vec![peer_share]);
        let tx = machine.complete(shares)?;
        debug!("Final signing completed");
        Ok(tx)
    }

    /// Test-only: inject a synthetic signing share for testing adapter signatures.
    ///
    /// This bypasses the full MuSig2 signing flow, allowing tests to verify
    /// adapter signature generation and verification without RPC calls.
    #[cfg(any(test, feature = "mocks"))]
    pub fn inject_test_signing_share(&mut self, scalar: &crate::XmrScalar) {
        // Safety: SignatureShare<Ed25519> is a newtype around Ed25519::F (Scalar)
        let share: SignatureShare<Ed25519> = unsafe { std::mem::transmute(scalar.0) };
        self.shared_spend_key = Some(share);
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

    async fn pre_process<R: Send + Sync + RngCore + CryptoRng>(
        &self,
        payments: Vec<(MoneroAddress, u64)>,
        rng: &mut R,
    ) -> Result<SignableTransaction, WalletError> {
        let rpc = self.rpc_connection().await?;
        let change = create_change(self.joint_public_spend_key())?;
        let spend_total = MINIMUM_FEE + payments.iter().map(|(_, amount)| *amount).sum::<u64>();
        // If this returns, there is guaranteed to be at least one input
        let inputs = self.find_spendable_outputs(spend_total)?;
        create_signable_tx(rpc.as_ref(), rng, inputs, payments, change, vec![]).await
    }
}

impl HasRole for MultisigWallet {
    fn role(&self) -> ChannelRole {
        self.role
    }
}

impl TryFrom<MultisigWalletKeyNegotiation> for MultisigWallet {
    type Error = WalletError;

    fn try_from(neg: MultisigWalletKeyNegotiation) -> Result<Self, Self::Error> {
        let peer_public_key = neg.peer_public_key.ok_or_else(|| {
            WalletError::InternalError(
                "Cannot convert from MultisigWalletKeyNegotiation: Missing peer public key ".into(),
            )
        })?;
        Self::new(
            neg.network,
            neg.rpc_url,
            neg.partial_spend_key,
            &neg.public_key,
            peer_public_key.public_key_ref(),
            Some(neg.birthday),
            neg.role,
        )
    }
}

/// Custom deserialize for [`MultisigWallet`]: deserialize the serialized fields via a
/// helper struct, then recompute the derived `#[serde(skip)]` fields via [`Self::new`].
///
/// Field names must match those produced by `#[derive(Serialize)]` on [`MultisigWallet`].
/// The peer public key is recovered from `sorted_pubkeys`. The `joint_*` and `musig_keys`
/// fields are recomputed by `Self::new()`.
impl<'de> Deserialize<'de> for MultisigWallet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            #[serde(deserialize_with = "crate::monero::helpers::deserialize_network")]
            network: Network,
            role: ChannelRole,
            rpc_url: String,
            my_spend_key: Curve25519Secret,
            my_public_key: Curve25519PublicKey,
            sorted_pubkeys: [Curve25519PublicKey; 2],
            birthday: u64,
            #[serde(deserialize_with = "crate::wallet::helpers::deserialize_outputs")]
            known_outputs: Vec<WalletOutput>,
            peer_preprocess_data: Option<Vec<u8>>,
        }
        let h = Helper::deserialize(deserializer)?;
        // Derive peer pubkey: it's the entry in sorted_pubkeys that isn't our own.
        let peer_pubkey =
            if h.sorted_pubkeys[0] == h.my_public_key { h.sorted_pubkeys[1] } else { h.sorted_pubkeys[0] };
        let mut wallet = Self::new(
            h.network,
            h.rpc_url,
            h.my_spend_key,
            &h.my_public_key,
            &peer_pubkey,
            Some(h.birthday),
            h.role,
        )
        .map_err(serde::de::Error::custom)?;
        wallet.known_outputs = h.known_outputs;
        wallet.peer_preprocess_data = h.peer_preprocess_data;
        Ok(wallet)
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

pub fn signature_share_to_scalar(signature: SignatureShare<Ed25519>) -> XmrScalar {
    // Safety: SignatureShare<Ed25519> is a wrapper around a DScalar, as is XmrScalar
    let val = unsafe {
        let scalar: DScalar = mem::transmute(signature);
        scalar
    };
    XmrScalar(val)
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
        Network::Mainnet => MoneroNetwork::Mainnet,
        Network::Testnet => MoneroNetwork::Testnet,
        Network::Stagenet => MoneroNetwork::Stagenet,
    };
    let spend = address.public_spend.point.decompress().expect("Addresses weren't compatible?");
    let view = address.public_view.point.decompress().expect("Addresses weren't compatible?");
    MoneroAddress::new(network, kind, spend, view)
}
