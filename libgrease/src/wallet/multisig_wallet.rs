use crate::amount::MoneroAmount;
use crate::channel_id::ChannelId;
use crate::cryptography::adapter_signature::AdaptedSignature;
use crate::cryptography::keys::{Curve25519PublicKey, Curve25519Secret};
use crate::payment_channel::multisig_keyring::{musig_2_of_2, musig_dh_viewkey, sort_pubkeys};
use crate::payment_channel::multisig_negotiation::MultisigWalletKeyNegotiation;
use crate::payment_channel::{ChannelRole, HasRole};
use crate::wallet::common::{create_change, create_signable_tx, MINIMUM_FEE};
use crate::wallet::errors::WalletError;
use crate::{XmrPoint, XmrScalar};
use blake2::Digest;
use curve25519_dalek::Scalar as DScalar;
use log::*;
use crate::Ed25519;
use modular_frost::sign::{PreprocessMachine, SignMachine, SignatureMachine, Writable};
use modular_frost::{Participant, ThresholdKeys};
use monero::{Address as UAddress, AddressType as UAddressType, Network};
use crate::wallet::common::block_count;
use crate::wallet::MoneroRpc;
use monero_interface::prelude::*;
use monero_oxide::block::Block;
use monero_oxide::ed25519::{Point as MoneroPoint, Scalar as MoneroScalar};
use monero_oxide::transaction::Transaction;
use monero_wallet::address::{AddressType, MoneroAddress, Network as MoneroNetwork};
use monero_wallet::send::{SignableTransaction, TransactionSignMachine, TransactionSignatureMachine};
use monero_wallet::{Scanner, ViewPair, WalletOutput};
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, OsRng, RngCore, SeedableRng};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use std::path::Path;
use std::sync::Arc;
use zeroize::Zeroizing;
use tokio::sync::RwLock;

pub type AdaptSig = AdaptedSignature<Ed25519>;

// monero-wallet 0.2 replaced the transparent `Vec<Preprocess<..>>` / `HashMap<.., Vec<SignatureShare<..>>>`
// with opaque newtypes, and does not re-export them from `send::multisig`. They are named here through the
// machine traits that produce and consume them, which is the only route the crate offers.
/// A whole-transaction FROST preprocess: one CLSAG preprocess per input.
pub type MoneroPreprocess = <TransactionSignMachine as SignMachine<Transaction>>::Preprocess;
/// A whole-transaction FROST signature share: one CLSAG share per input.
pub type MoneroSignatureShare = <TransactionSignMachine as SignMachine<Transaction>>::SignatureShare;

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
    rpc: Arc<RwLock<Option<Arc<MoneroRpc>>>>,
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
    preprocess_data: Option<MoneroPreprocess>,
    #[serde(skip)]
    sign_machine: Option<TransactionSignMachine>,
    // Our own signing share, kept as the scalar it encodes. `TransactionSignatureShare` is opaque in
    // monero-wallet 0.2 and constructible only through a signature machine, and everything grease does with
    // this value — adapting a signature, handing it to the state machine — is scalar-level anyway.
    #[serde(skip)]
    shared_spend_key: Option<XmrScalar>,
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

/// Generate the canonical message for the commitment transaction *held by* `holder` at `state_index`.
///
/// Both parties can compute this independently, before the transaction is built, so it is what the state's
/// adaptor signature and its [`UpdateRecord`](crate::grease_protocol::update_record::UpdateRecord) commit to.
///
/// Each party holds its own closing transaction for a state and broadcasts it on a unilateral close, so `holder`
/// separates the pair: the two adaptor signatures exchanged for one state are then never over the same bytes,
/// and a package presented in the counterparty's direction cannot verify.
///
/// # Parameters
/// - `channel_id`: The unique channel identifier
/// - `state_index`: The state update index (0 for initial commitment)
/// - `holder`: The party that holds — and would broadcast — this closing transaction
/// - `customer_amount`: Customer's balance in piconero
/// - `merchant_amount`: Merchant's balance in piconero
pub fn commitment_tx_message(
    channel_id: &ChannelId,
    state_index: u64,
    holder: ChannelRole,
    customer_amount: u64,
    merchant_amount: u64,
) -> Vec<u8> {
    use blake2::Blake2b512;
    use flexible_transcript::{DigestTranscript, Transcript};

    let mut transcript = DigestTranscript::<Blake2b512>::new(b"Grease CommitmentTx v2");
    transcript.append_message(b"channel_id", channel_id.as_str().as_bytes());
    transcript.append_message(b"state_index", state_index.to_le_bytes());
    transcript.append_message(b"holder", holder.to_string());
    transcript.append_message(b"customer_amount", customer_amount.to_le_bytes());
    transcript.append_message(b"merchant_amount", merchant_amount.to_le_bytes());
    transcript.challenge(b"commitment_tx_message").to_vec()
}

/// The MuSig participant index `i`, which is always in range for the 2-of-2 signing set.
fn participant(i: u16) -> Participant {
    Participant::new(i).expect("1 and 2 are valid participant indices")
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
        let joint_private_view_key = Curve25519Secret::from(*jprv_vk);
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
    pub async fn rpc_connection(&self) -> Result<Arc<MoneroRpc>, WalletError> {
        {
            let lock = self.rpc.read().await;
            if let Some(rpc) = lock.as_ref() {
                return Ok(Arc::clone(rpc));
            }
        }
        let mut lock = self.rpc.write().await;
        // Double check if another task has already initialized the RPC connection while we were waiting for the write lock
        if let Some(rpc) = lock.as_ref() {
            Ok(Arc::clone(rpc))
        } else {
            let rpc = crate::wallet::connect_to_rpc(self.rpc_url.clone()).await?;
            let rpc = Arc::new(rpc);
            *lock = Some(Arc::clone(&rpc));
            Ok(rpc)
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
            MoneroPoint::from(self.joint_public_spend_key.as_point().0),
            MoneroPoint::from(self.joint_public_view_key.as_point().0),
        )
    }

    pub fn my_spend_key(&self) -> &Curve25519Secret {
        &self.my_spend_key
    }

    /// The generator this wallet's linking tag is taken against: `H_p(P)` for the joint public spend key `P`,
    /// the generator Monero uses for the key image of an output paying to `P`.
    fn linking_tag_generator(&self) -> XmrPoint {
        // `monero_serai::generators::hash_to_point` became `ed25519::Point::biased_hash`: the same Elligator-2
        // map, now in constant time.
        XmrPoint(MoneroPoint::biased_hash(self.joint_public_spend_key.to_compressed().to_bytes()).into())
    }

    /// This party's share of the funding output's linking tag, `L_F = x · H_p(P)`.
    ///
    /// `x` is the *joint* spend key, which neither party holds on its own, so neither can compute `L_F` alone.
    /// Each side contributes `λ_i·s_i·H_p(P)` for its own interpolated MuSig share and the two partials sum to
    /// `L_F` — the standard Monero multisig key-image construction. Send this to the peer and combine the two
    /// with [`linking_tag`](Self::linking_tag).
    pub fn partial_linking_tag(&self) -> Result<XmrPoint, WalletError> {
        let view = self
            .musig_keys
            .view(vec![participant(1), participant(2)])
            .map_err(|e| WalletError::KeyError(format!("Could not interpolate the 2-of-2 signing set: {e:?}")))?;
        Ok(self.linking_tag_generator() * **view.secret_share())
    }

    /// Combine our partial linking tag with the peer's to obtain the funding output's linking tag `L_F`.
    ///
    /// Addition is commutative, so both parties derive an identical `L_F` and therefore an identical final
    /// channel id.
    pub fn linking_tag(&self, peer_partial: &XmrPoint) -> Result<XmrPoint, WalletError> {
        Ok(self.partial_linking_tag()? + peer_partial)
    }

    /// The number of blocks on the chain, which is one past the tip's number.
    ///
    /// This is the count, not the tip's number: [`scan`](Self::scan) uses it as an exclusive upper bound and
    /// [`reset_birthday`](Self::reset_birthday) stores it as "the next block to scan".
    pub async fn get_height(&self) -> Result<u64, WalletError> {
        let rpc = self.rpc_connection().await?;
        block_count(rpc.as_ref()).await
    }

    pub async fn get_block_by_number(&self, block_num: u64) -> Result<Block, WalletError> {
        let rpc = self.rpc_connection().await?;
        let block = rpc.block_by_number(block_num as usize).await?;
        Ok(block)
    }

    async fn get_scannable_block(&self, block: Block) -> Result<ScannableBlock, WalletError> {
        let rpc = self.rpc_connection().await?;
        let block = rpc.expand_to_scannable_block(block).await?;
        Ok(block)
    }

    pub async fn scan(&mut self, start: Option<u64>) -> Result<usize, WalletError> {
        let spend = MoneroPoint::from(self.joint_public_spend_key.as_point().0);
        let view = Zeroizing::new(MoneroScalar::from(*self.joint_private_view_key.to_dalek_scalar()));
        let pair = ViewPair::new(spend, view).map_err(|e| WalletError::KeyError(e.to_string()))?;
        let mut scanner = Scanner::new(pair);
        let height = self.get_height().await?;
        let mut scanned = 0usize;
        let mut found = 0usize;
        let start = start.unwrap_or(self.birthday);
        for block_num in start..height {
            let block = self.get_block_by_number(block_num).await?;
            let scannable = self.get_scannable_block(block).await?;
            let outputs = scanner.scan(scannable).map_err(|e| WalletError::InternalError(e.to_string()))?;
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

    pub fn import_output(&mut self, serialized: &[u8]) -> Result<(), WalletError> {
        let mut reader = serialized;
        let output = crate::wallet::helpers::read_output(&mut reader)
            .map_err(|e| WalletError::DeserializeError(e.to_string()))?;
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
        let mut total = 0u64;
        let result: Vec<WalletOutput> = self
            .known_outputs
            .iter()
            .take_while(|output| {
                let needs_more = total < min_amount;
                total += output.commitment().amount;
                needs_more
            })
            .cloned()
            .collect();
        if total >= min_amount {
            Ok(result)
        } else {
            Err(WalletError::InsufficientFunds)
        }
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
        let machine = signable.multisig(self.musig_keys.clone())?;
        let (machine, preprocess) = machine.preprocess(rng);
        self.preprocess_data = Some(preprocess);
        self.sign_machine = Some(machine);
        Ok(())
    }

    /// Our preprocess, on the wire.
    ///
    /// `TransactionPreprocess` writes its per-input preprocesses back to back, so for the single-input
    /// transaction grease signs this is byte-identical to writing that one preprocess — which is what the
    /// peer's `read_preprocess` expects to read.
    pub fn my_pre_process_data(&self) -> Option<Vec<u8>> {
        self.preprocess_data.as_ref().map(|preprocess| {
            let mut buf = Vec::with_capacity(160);
            preprocess.write(&mut buf).expect("writing to a Vec cannot fail");
            buf
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
        let (tx_machine, share) = machine.sign(commitments, &[])?;
        self.shared_spend_key = Some(signature_share_to_scalar(&share));
        self.final_signer = Some(tx_machine);
        Ok(())
    }

    /// Our own signing share for the prepared transaction, as the scalar it encodes.
    ///
    /// The channel funds a single output, so a transaction signature share is one CLSAG share, which is one
    /// scalar. That scalar is what the adaptor-signature layer signs with.
    pub fn my_signing_share(&self) -> Option<XmrScalar> {
        self.shared_spend_key
    }

    pub fn set_peer_process_data(&mut self, data: Vec<u8>) {
        self.peer_preprocess_data = Some(data);
    }

    pub fn adapt_signature(&self, witness: &Curve25519Secret, msg: &[u8]) -> Result<AdaptSig, WalletError> {
        let secret = self
            .my_signing_share()
            .ok_or_else(|| WalletError::SigningError("No signature share available to adapt".into()))?;
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
    ) -> Result<MoneroSignatureShare, WalletError> {
        let p = self.peer_public_key().as_point();
        let true_sig = adapted.adapt(offset, &p, msg).map_err(|_| {
            WalletError::SigningError("Incorrect offset supplied. Adapter signature verification failed".into())
        })?;
        let bytes = true_sig.s().as_bytes();
        let share = self.bytes_to_signature_share(bytes)?;
        Ok(share)
    }

    /// Parse a peer's signature share from the wire.
    ///
    /// `read_share` is the only way to build a `TransactionSignatureShare`: the type is opaque in
    /// monero-wallet 0.2 precisely so a share can only come from the machine that will consume it.
    pub fn bytes_to_signature_share(&self, bytes: &[u8]) -> Result<MoneroSignatureShare, WalletError> {
        let mut reader = bytes;
        let machine = self.final_signer.as_ref().ok_or_else(|| {
            WalletError::SigningError("Call partial_sign before trying to read a signature share".into())
        })?;
        machine
            .read_share(&mut reader)
            .map_err(|e| WalletError::SigningError(format!("Invalid signature share: {e}")))
    }

    pub fn sign(&mut self, peer_share: MoneroSignatureShare) -> Result<Transaction, WalletError> {
        if self.final_signer.is_none() || self.shared_spend_key.is_none() {
            return Err(WalletError::KeyError("Final signer or shares not initialized".into()));
        }
        let machine = self.final_signer.take().unwrap();
        let shares = self.assign_shares(peer_share);
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
        self.shared_spend_key = Some(*scalar);
    }

    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<usize, std::io::Error> {
        let mut file = std::fs::File::create(path)?;
        let result = self.known_outputs.iter().map(|output| output.write(&mut file)).collect::<Result<Vec<_>, _>>()?;
        info!("Saved known outputs");
        Ok(result.len())
    }

    /// Load the outputs [`save`](Self::save) wrote, in either the current or the pre-monero-oxide layout.
    ///
    /// The file is a run of records with no delimiter, so it is read whole and peeled one record at a time.
    pub fn load<P: AsRef<Path>>(&mut self, path: P) -> Result<usize, std::io::Error> {
        let outputs = crate::wallet::helpers::read_outputs(&std::fs::read(path)?)?;
        let n = outputs.len();
        self.known_outputs.extend(outputs);
        Ok(n)
    }

    pub fn read_outputs(outputs: &[Vec<u8>]) -> Result<Vec<WalletOutput>, std::io::Error> {
        outputs.iter().map(|output| crate::wallet::helpers::read_output(&mut output.as_slice())).collect()
    }

    fn participants(&self) -> (Participant, Participant) {
        let first = self.sorted_pubkeys[0] == self.my_public_key;
        if first {
            (Participant::new(1).unwrap(), Participant::new(2).unwrap())
        } else {
            (Participant::new(2).unwrap(), Participant::new(1).unwrap())
        }
    }

    fn assign_commitments(&self, peer_data: MoneroPreprocess) -> HashMap<Participant, MoneroPreprocess> {
        let mut commitments = HashMap::new();
        let (me, them) = self.participants();
        trace!("Assigning commitments for participants: me={:?} and they={:?}", me, them);
        commitments.insert(them, peer_data);
        commitments
    }

    fn assign_shares(
        &self,
        peer_shares: MoneroSignatureShare,
    ) -> HashMap<Participant, MoneroSignatureShare> {
        let mut shares = HashMap::new();
        let (me, them) = self.participants();
        trace!("Assigning shares for participants: me={:?} and they={:?}", me, them);
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
        // A channel is funded by exactly one output, and the rest of the signing path depends on it: a
        // transaction preprocess and a signature share are per-input, and grease sends and adapts a single one
        // of each. monero-wallet 0.2 made both types opaque, so this is the last point at which the assumption
        // can be checked.
        if inputs.len() != 1 {
            return Err(WalletError::KeyError(format!(
                "A multisig channel transaction must spend exactly one output. Got {}",
                inputs.len()
            )));
        }
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

pub fn signature_share_to_secret(signature: &MoneroSignatureShare) -> Curve25519Secret {
    Curve25519Secret::from(signature_share_to_dalek_scalar(signature))
}

pub fn signature_share_to_scalar(signature: &MoneroSignatureShare) -> XmrScalar {
    signature_share_to_dalek_scalar(signature)
}

pub fn signature_share_to_bytes(secret: &MoneroSignatureShare) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64);
    secret.write(&mut buf).expect("Failed to write signature share to buffer");
    trace!("signature_share_to_bytes buf={}", buf.len());
    buf
}

/// Decode a signature share through its canonical 32-byte serialization.
///
/// A share is written as the little-endian canonical encoding of the underlying scalar, so the bytes always
/// re-parse. For the single-input transaction grease signs, a `TransactionSignatureShare` is exactly one such
/// scalar. A failure means the upstream wire format changed underneath us; panicking is strictly better than
/// feeding a wrong scalar into a signature.
fn signature_share_to_dalek_scalar(signature: &MoneroSignatureShare) -> DScalar {
    let bytes = signature_share_to_bytes(signature);
    let bytes: [u8; 32] = bytes.try_into().expect("a single-input signature share must serialize to 32 bytes");
    Option::<DScalar>::from(DScalar::from_canonical_bytes(bytes))
        .expect("a signature share must serialize to a canonical scalar")
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
    MoneroAddress::new(network, kind, MoneroPoint::from(spend), MoneroPoint::from(view))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cryptography::keys::{Curve25519Secret, PublicKey};
    use crate::wallet::utils::random_key;
    use ciphersuite::group::Group;
    use std::str::FromStr;

    fn test_wallet() -> MultisigWallet {
        let my_secret = Curve25519Secret::random(&mut OsRng);
        let my_public = Curve25519PublicKey::from_secret(&my_secret);
        let peer_public = Curve25519PublicKey::from_secret(&Curve25519Secret::random(&mut OsRng));
        MultisigWallet::new(Network::Mainnet, "http://localhost:18081", my_secret, &my_public, &peer_public, None, ChannelRole::Merchant)
            .expect("wallet")
    }

    /// The signing share is the key the adaptor layer signs with, so an injected share must reach
    /// `adapt_signature` unchanged.
    ///
    /// This replaces K-23's layout guard over `inject_test_signing_share`'s `mem::transmute`. monero-wallet 0.2
    /// made `TransactionSignatureShare` opaque and constructible only through a signature machine, so the share
    /// is now held as the scalar it encodes and the transmute is gone — leaving the value, not the layout, as
    /// the thing worth asserting.
    #[test]
    fn injected_share_is_the_key_the_adaptor_signs_with() {
        let mut wallet = test_wallet();
        (0..16).for_each(|_| {
            let scalar = DScalar::from_bytes_mod_order(random_key());
            wallet.inject_test_signing_share(&scalar);
            assert_eq!(wallet.my_signing_share().expect("injected share"), scalar);

            let witness = Curve25519Secret::random(&mut OsRng);
            let adapted = wallet.adapt_signature(&witness, b"msg").expect("adapt");
            assert!(adapted.verify(&(XmrPoint::generator() * scalar), b"msg"));
        });
    }

    /// The encoding contract between the adaptor layer and `read_share`.
    ///
    /// `extract_true_signature` completes a pre-signature and hands the resulting `s` straight to
    /// `bytes_to_signature_share`, which parses it as a share. That only holds while `s`'s 32 bytes are the
    /// canonical little-endian encoding of the scalar a share is read from — the same property K-23 pinned from
    /// the share's side, asserted here from the side that is still reachable without a signing machine.
    #[test]
    fn an_adapted_signature_s_is_a_canonically_encoded_scalar() {
        (0..16).for_each(|_| {
            let secret = DScalar::from_bytes_mod_order(random_key());
            let witness = DScalar::from_bytes_mod_order(random_key());
            let adapted = AdaptSig::sign(&secret, &witness, b"msg", &mut OsRng);
            let signature = adapted.adapt(&witness, &(XmrPoint::generator() * secret), b"msg").expect("adapt");

            let bytes = *signature.s().as_bytes();
            assert_eq!(Option::<DScalar>::from(DScalar::from_canonical_bytes(bytes)), Some(*signature.s()));
        });
    }

    /// A channel id spelled out as a literal — the frozen one from `channel_id.rs`'s own known-answer vector — so
    /// these vectors depend on no derivation but the one under test.
    const CHANNEL_ID: &str = "XGC0845ec076e64984475627c8c1a154defceaeea2ce3cd39c55b02823b4f70a4";
    /// The frozen `commitment_tx_message` output, split only to fit the line width.
    const COMMITMENT_TX_V2: &str = concat!(
        "a87752639885160a555a6eb8ce2b5142f56a571f4e379267062fa5690ed188da",
        "37e55a17d9456b3a0b922dc8623deb283035301c434ad328472279da5e0c4712",
    );
    const SECRET_A: &str = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00";
    const SECRET_B: &str = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f00";

    /// Freezes the closing-transaction message under the live `"Grease CommitmentTx v2"` domain tag. Crosses
    /// `flexible-transcript`'s `DigestTranscript` (member tagging and little-endian length prefixes) and
    /// `blake2 0.10`'s `Blake2b512`, both of which the serai migration replaces.
    #[test]
    fn commitment_tx_message_is_frozen() {
        let id = ChannelId::from_str(CHANNEL_ID).expect("valid channel id");
        let message = commitment_tx_message(&id, 7, ChannelRole::Customer, 1_250_000_000_000, 750_000_000_000);
        assert_eq!(hex::encode(&message), COMMITMENT_TX_V2);
    }

    /// `holder` is what separates the two parties' closing transactions for one state, so the merchant-held
    /// message must differ from the customer-held one above under otherwise identical inputs.
    #[test]
    fn commitment_tx_message_separates_the_holders() {
        let id = ChannelId::from_str(CHANNEL_ID).expect("valid channel id");
        let customer = commitment_tx_message(&id, 7, ChannelRole::Customer, 1_250_000_000_000, 750_000_000_000);
        let merchant = commitment_tx_message(&id, 7, ChannelRole::Merchant, 1_250_000_000_000, 750_000_000_000);
        assert_ne!(customer, merchant);
    }

    /// Freezes the signing-determinism entry point end to end: fixed spend key and peer key -> joint private view
    /// key -> `Blake2b512` seed -> `ChaCha20Rng`. Crosses `blake2 0.10` and `rand_chacha`; the joint view key it
    /// starts from is itself pinned in `payment_channel::multisig_keyring`.
    #[test]
    fn deterministic_rng_stream_is_frozen() {
        let secret = Curve25519Secret::from_hex(SECRET_A).expect("canonical scalar");
        let my_public = Curve25519PublicKey::from_secret(&secret);
        let peer_public =
            Curve25519PublicKey::from_secret(&Curve25519Secret::from_hex(SECRET_B).expect("canonical scalar"));
        let wallet = MultisigWallet::new(
            Network::Mainnet,
            "http://localhost:18081",
            secret,
            &my_public,
            &peer_public,
            None,
            ChannelRole::Merchant,
        )
        .expect("wallet");

        // The wallet's own view of the joint keys, pinned here as well as in the keyring module: this is the
        // path production actually takes. The spend key moved with the `musig` crate swap — see
        // `payment_channel::multisig_keyring::musig_group_key_is_frozen` — while the view key, and so the
        // ChaCha20 stream derived from it, did not.
        assert_eq!(
            wallet.joint_public_spend_key().as_hex(),
            "d84486c8b988b72aacee390bb88bde734332d4c06a383f27874428f833ad7319"
        );
        assert_eq!(
            wallet.joint_public_view_key().as_hex(),
            "98d67ed9ddeaedcd87506a35a28ecc62e0f8cca85ae1aa4467d25942ec49bec8"
        );

        let mut rng = wallet.deterministic_rng();
        let mut out = [0u8; 32];
        rng.fill_bytes(&mut out);
        assert_eq!(hex::encode(out), "aef20e8b94d84274f37b898951d8047f760a783077a02a9eee682f692d153a03");
    }

}
