use crate::amount::MoneroAmount;
use crate::balance::Balances;
use crate::channel_id::{ChannelId, ChannelIdMetadata};
use crate::channel_metadata::{DynamicChannelMetadata, StaticChannelMetadata};
use crate::cryptography::adapter_signature::{AdaptedSignature, SchnorrSignature};
use crate::cryptography::dleq::{Dleq, DleqProof};
use crate::cryptography::keys::{Curve25519PublicKey, Curve25519Secret, PublicKeyCommitment};
use crate::cryptography::pok::KesPoKProofs;
use crate::cryptography::secret_encryption::{EncryptedSecret, SecretWithRole};
use crate::cryptography::serializable_secret::SerializableSecret;
use crate::cryptography::{ChannelWitness, Offset};
use crate::grease_protocol::channel_keys::{self, ChannelNonce, EphemeralChannelId};
use crate::grease_protocol::establish_channel::{payload_signature_message, ChannelInitPackage, EstablishError};
use crate::grease_protocol::kes_establishing::KesInitBundle;
use crate::grease_protocol::multisig_wallet::{HasPublicKey, HasSecretKey, LinkedMultisigWallets, SharedPublicKey};
use crate::grease_protocol::utils::Readable;
use crate::impls::multisig::MultisigWalletKeyRing;
use crate::monero::data_objects::{TransactionId, TransactionRecord};
use crate::multisig::MultisigWalletData;
use crate::payment_channel::{ChannelRole, HasRole};
use crate::state_machine::error::LifeCycleError;
use crate::state_machine::lifecycle::ChannelState;
use crate::state_machine::open_channel::EstablishedChannelState;
use ciphersuite::{Ciphersuite, Ed25519};
use grease_grumpkin::Grumpkin;
use log::*;
use modular_frost::curve::Curve as FrostCurve;
use monero::Network;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::marker::PhantomData;
use zeroize::{Zeroize, Zeroizing};
//------------------------------------   Establishing Channel State  ------------------------------------------------//

/// State for a channel being established.
///
/// This state provides the cryptographic operations needed during channel establishment
/// including wallet key exchange, KES client setup, and adapter signature verification.
///
/// The generic parameter `SF` specifies the SNARK-friendly curve (defaults to Grumpkin).
/// The generic parameter `KC` specifies the Curve that the KES has elected to use. By default, the KES uses Ed25519,
/// the same curve as Monero.
#[derive(Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct EstablishingState<SF = Grumpkin, KC = Ed25519>
where
    SF: FrostCurve,
    KC: FrostCurve,
    Ed25519: Dleq<SF> + Dleq<KC>,
{
    pub(crate) metadata: StaticChannelMetadata<KC>,
    pub(crate) multisig_wallet: Option<MultisigWalletData>,
    #[serde(
        serialize_with = "crate::helpers::serialize_tx_map",
        deserialize_with = "crate::helpers::deserialize_tx_map"
    )]
    pub(crate) funding_transaction_ids: HashMap<TransactionId, TransactionRecord>,
    pub(crate) kes_proof: Option<KesPoKProofs<KC>>,
    /// Data used to watch for the funding transaction. Implementation agnostic.
    #[serde(
        serialize_with = "crate::helpers::option_to_hex",
        deserialize_with = "crate::helpers::option_from_hex",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub(crate) funding_tx_pipe: Option<Vec<u8>>,

    /// The channel nonce ($\hat{k}_a$ or $\hat{k}_b$) with its ECDH-MC shared secret.
    pub(crate) channel_nonce: ChannelNonce<KC>,
    // --- Protocol Context Fields (ephemeral, not serialized) ---
    /// Wallet key ring for the multisig protocol during establishment.
    #[serde(skip)]
    pub(crate) wallet_keyring: Option<MultisigWalletKeyRing>,
    /// The initial adapter offset encrypted for the KES.
    #[serde(skip)]
    /// The encrypted initial adapter offset to be sent to the KES, ($chi$).
    pub(crate) encrypted_offset: Option<EncryptedSecret<KC>>,
    /// The peer's encrypted initial adapter offset to be sent to the KES, ($chi$).
    #[serde(skip)]
    pub(crate) peer_encrypted_offset: Option<EncryptedSecret<KC>>,
    /// Peer's DLEQ proof received during establishment (public data).
    #[serde(skip)]
    pub(crate) peer_dleq_proof: Option<DleqProof<KC, Ed25519>>,
    /// My DLEQ proof for the initial adapter offset (public data).
    #[serde(skip)]
    pub(crate) dleq_proof: Option<DleqProof<KC, Ed25519>>,
    /// My adapted signature for the initial channel close transaction (public data).
    #[serde(skip)]
    pub(crate) adapted_sig: Option<AdaptedSignature<Ed25519>>,
    /// Peer's adapted signature for the initial channel close transaction received during establishment (public data).
    #[serde(skip)]
    pub(crate) peer_adapted_sig: Option<AdaptedSignature<Ed25519>>,
    /// The channel witness, kept between `initialize_channel_secrets` and `generate_init_package`.
    /// Ephemeral — not serialized or cloned.
    #[serde(skip)]
    pub(crate) channel_witness: Option<ChannelWitness<KC>>,
    /// Our payload signature (signs our init package fields with ephemeral key).
    #[serde(skip)]
    pub(crate) payload_sig: Option<SchnorrSignature<KC>>,
    /// Peer's payload signature received during init package exchange.
    #[serde(skip)]
    pub(crate) peer_payload_sig: Option<SchnorrSignature<KC>>,
    /// Peer's nonce public key from their init package.
    #[serde(skip)]
    pub(crate) peer_nonce_pubkey: Option<KC::G>,
    #[serde(skip)]
    _sf: PhantomData<SF>,
}

/// Type alias for the default curve types (Grumpkin + Ed25519).
pub type DefaultEstablishingState = EstablishingState<Grumpkin>;

impl<SF, KC> Clone for EstablishingState<SF, KC>
where
    SF: FrostCurve,
    KC: FrostCurve,
    Ed25519: Dleq<SF> + Dleq<KC>,
{
    fn clone(&self) -> Self {
        Self {
            metadata: self.metadata.clone(),
            multisig_wallet: self.multisig_wallet.clone(),
            funding_transaction_ids: self.funding_transaction_ids.clone(),
            kes_proof: self.kes_proof.clone(),
            funding_tx_pipe: self.funding_tx_pipe.clone(),
            channel_nonce: self.channel_nonce.clone(),
            wallet_keyring: self.wallet_keyring.clone(),
            peer_dleq_proof: self.peer_dleq_proof.clone(),
            dleq_proof: None,
            adapted_sig: None,
            peer_adapted_sig: self.peer_adapted_sig.clone(),
            peer_encrypted_offset: self.peer_encrypted_offset.clone(),
            channel_witness: None,
            payload_sig: None,
            peer_payload_sig: None,
            peer_nonce_pubkey: None,
            _sf: PhantomData,
            encrypted_offset: None,
        }
    }
}

impl<SF, KC> EstablishingState<SF, KC>
where
    SF: FrostCurve,
    KC: FrostCurve,
    Ed25519: Dleq<SF> + Dleq<KC>,
{
    pub fn to_channel_state(self) -> ChannelState<SF, KC> {
        ChannelState::Establishing(self)
    }

    pub fn requirements_met(&self) -> bool {
        let mut missing = Vec::with_capacity(10);
        if self.multisig_wallet.is_none() {
            missing.push("Multisig wallet")
        }
        if self.kes_proof.is_none() {
            missing.push("KES proof");
        }
        // Add checks for all other Optional fields in this struct:
        if self.peer_dleq_proof.is_none() {
            missing.push("Peer DLEQ proof");
        }
        if self.peer_adapted_sig.is_none() {
            missing.push("Peer adapted signature");
        }
        if self.peer_encrypted_offset.is_none() {
            missing.push("Peer encrypted offset for KES");
        }
        if self.encrypted_offset.is_none() {
            missing.push("Encrypted offset for KES");
        }
        if self.dleq_proof.is_none() {
            missing.push("DLEQ proof for adapter signature offset");
        }
        if self.adapted_sig.is_none() {
            missing.push("Adapted signature for initial channel state");
        }
        if self.wallet_keyring.is_none() {
            missing.push("Wallet keyring");
        }
        if self.payload_sig.is_none() {
            missing.push("Payload signature");
        }
        if self.peer_payload_sig.is_none() {
            missing.push("Peer payload signature");
        }
        if self.funding_tx_pipe.is_none() {
            error!("Funding transaction pipe data is required to detect channel funding, but it is missing.");
            missing.push("Funding transaction pipe data. We will never be able to detect if this channel is funded without this.");
        }
        if !self.is_fully_funded() {
            missing.push("Funding transaction fully funded");
        }
        if !missing.is_empty() {
            let msg = missing.join(", ");
            debug!("EstablishingState requirements not met: {msg}");
            false
        } else {
            debug!("EstablishingState requirements met");
            true
        }
    }

    pub fn multisig_address(&self, network: Network) -> Option<String> {
        self.multisig_wallet.as_ref().map(|w| w.address(network).to_string())
    }

    fn is_fully_funded(&self) -> bool {
        let required = self.metadata.initial_balance().total();
        let result = self.funding_total() >= required;
        trace!(
            "is_fully_funded-- total {}, required {required}: {result}",
            self.funding_total()
        );
        result
    }

    pub fn funding_total(&self) -> MoneroAmount {
        self.funding_transaction_ids.values().map(|r| r.amount).sum()
    }
    pub fn multisig_wallet_data(&self) -> Option<&MultisigWalletData> {
        self.multisig_wallet.as_ref()
    }

    pub fn wallet_created(&mut self, wallet: MultisigWalletData) {
        debug!("Multisig wallet has been created.");
        let old = self.multisig_wallet.replace(wallet);
        if old.is_some() {
            warn!("Wallet state was already set and has been replaced.");
        }
    }

    /// Can be used to save (e.g. a unix pipe or filename) that will be used to watch for the funding transaction.
    /// Once the funding tx is broadcast, call `funding_tx_confirmed` to update the state.
    pub fn save_funding_tx_pipe(&mut self, funding_tx_pipe: Vec<u8>) {
        debug!("Saving funding transaction pipe data");
        let old = self.funding_tx_pipe.replace(funding_tx_pipe);
        if old.is_some() {
            warn!("Funding transaction pipe data was already set and has been replaced.");
        }
    }

    pub fn kes_created(&mut self, kes_info: KesPoKProofs<KC>) {
        let old = self.kes_proof.replace(kes_info);
        if old.is_some() {
            warn!("KES proof was already set and has been replaced.");
        }
    }

    pub fn funding_tx_confirmed(&mut self, transaction: TransactionRecord) {
        debug!("Funding transaction broadcasted");
        self.funding_transaction_ids.insert(transaction.transaction_id.clone(), transaction);
    }

    /// Generate secrets for this channel.
    ///
    /// This generates a wallet key ring for the establishment phase as well as
    /// a random channel witness (valid in both Ed25519 and KC), then:
    /// 1. Generates a DLEQ proof showing the witness is the same discrete log on both curves
    /// 2. Encrypts the offset to the KES public key from metadata
    /// 3. Stores the witness for adapter signature generation in [`generate_init_package`]
    ///
    /// The adapter signature is deferred to `generate_init_package` because it signs a
    /// commitment transaction message that requires the full channel metadata (peer data).
    pub fn generate_channel_secrets<R: RngCore + CryptoRng>(&mut self, rng: &mut R) -> Result<(), EstablishError>
    where
        KC::F: ciphersuite::group::ff::PrimeFieldBits,
    {
        let role = HasRole::role(self);
        let keyring = MultisigWalletKeyRing::random(rng, role);
        self.wallet_keyring = Some(keyring);
        let witness = ChannelWitness::<KC>::random_with_rng(rng);
        let (proof, public_points) =
            <Ed25519 as Dleq<KC>>::generate_dleq(rng, &witness).map_err(EstablishError::DleqGenerationError)?;
        self.dleq_proof = Some(DleqProof::new(proof, public_points));

        let kes_pubkey = self.metadata.kes_configuration().kes_public_key;
        let snark_scalar = witness.as_snark_scalar();
        let secret_with_role = SecretWithRole::new(snark_scalar, HasRole::role(self));
        self.encrypted_offset = Some(EncryptedSecret::encrypt(
            secret_with_role,
            &kes_pubkey,
            rng,
            b"GreaseEncryptToKES",
        ));

        self.channel_witness = Some(witness);
        debug!("Channel secrets initialized: DLEQ proof, encrypted offset, and witness stored.");
        Ok(())
    }

    #[allow(clippy::result_large_err)]
    pub fn next(self) -> Result<EstablishedChannelState<SF, KC>, (Self, LifeCycleError)> {
        debug!("Trying to move from Establishing to Established state");
        if !self.requirements_met() {
            debug!("Cannot change from Establishing to Established because all requirements are not met");
            return Err((self, LifeCycleError::InvalidStateTransition));
        }
        debug!("Transitioning to Established wallet state");
        let dynamic = DynamicChannelMetadata::new(self.metadata.initial_balance(), 0);
        let open_channel = EstablishedChannelState {
            metadata: self.metadata,
            dynamic,
            multisig_wallet: self.multisig_wallet.unwrap(),
            funding_transactions: self.funding_transaction_ids,
            current_update: None,
        };
        Ok(open_channel)
    }
}

// --- Absorbed methods from removed EstablishProtocolCommon/Customer/Merchant traits ---

impl<SF, KC> EstablishingState<SF, KC>
where
    SF: FrostCurve,
    KC: FrostCurve,
    Ed25519: Dleq<SF> + Dleq<KC>,
{
    /// Provide access to the channel ID metadata.
    pub fn channel_id_metadata(&self) -> &ChannelIdMetadata<KC> {
        self.metadata.channel_id()
    }

    /// Provide access to the multisig wallet key ring.
    pub fn wallet(&self) -> &MultisigWalletKeyRing {
        self.wallet_keyring.as_ref().expect("Protocol context not initialized. Call init_protocol_context first.")
    }

    /// Provide mutable access to the multisig wallet key ring.
    pub fn wallet_mut(&mut self) -> &mut MultisigWalletKeyRing {
        self.wallet_keyring.as_mut().expect("Protocol context not initialized. Call init_protocol_context first.")
    }

    /// Set the peer's adapted signature.
    pub fn set_peer_adapted_signature(&mut self, adapted_signature: AdaptedSignature<Ed25519>) {
        self.peer_adapted_sig = Some(adapted_signature);
    }

    /// Set the peer's DLEQ proof.
    pub fn set_peer_dleq_proof(&mut self, dleq_proof: DleqProof<KC, Ed25519>) {
        self.peer_dleq_proof = Some(dleq_proof);
    }

    /// Read the peer's shared public key (includes role) from the given reader and store it.
    pub fn store_peer_shared_public_key<R: std::io::Read>(&mut self, reader: &mut R) -> Result<(), EstablishError> {
        let shared_pubkey = SharedPublicKey::read(reader)?;
        let my_role = HasRole::role(self);
        if shared_pubkey.role() == my_role {
            return Err(EstablishError::InvalidDataFromPeer(format!(
                "Peer public key has incompatible role. It should be {} but received {}",
                my_role.other(),
                shared_pubkey.role()
            )));
        }
        self.wallet_mut().set_peer_public_key(shared_pubkey);
        Ok(())
    }

    /// Read the peer's adapted signature from the given reader and store it.
    pub fn store_peer_adapted_signature<R: std::io::Read>(&mut self, reader: &mut R) -> Result<(), EstablishError> {
        let adapted_signature = AdaptedSignature::<Ed25519>::read(reader)?;
        self.set_peer_adapted_signature(adapted_signature);
        Ok(())
    }

    /// Read the peer's public key commitment from the given reader and store it (customer-side).
    pub fn store_wallet_commitment<R: std::io::Read>(&mut self, reader: &mut R) -> Result<(), EstablishError> {
        let commitment =
            PublicKeyCommitment::read(reader).map_err(|e| EstablishError::InvalidCommitment(e.to_string()))?;
        self.wallet_mut().set_peer_public_key_commitment(commitment);
        Ok(())
    }

    /// Verify that the merchant's public key matches the previously stored commitment (customer-side).
    pub fn verify_merchant_public_key(&self) -> Result<(), EstablishError> {
        self.wallet().verify_peer_public_key()?;
        Ok(())
    }
}

// --- HasRole, HasPublicKey, HasSecretKey implementations ---

impl<SF, KC> HasRole for EstablishingState<SF, KC>
where
    SF: FrostCurve,
    KC: FrostCurve,
    Ed25519: Dleq<SF> + Dleq<KC>,
{
    fn role(&self) -> ChannelRole {
        self.metadata.role()
    }
}

impl<SF, KC> HasPublicKey for EstablishingState<SF, KC>
where
    SF: FrostCurve,
    KC: FrostCurve,
    Ed25519: Dleq<SF> + Dleq<KC>,
{
    fn public_key(&self) -> Curve25519PublicKey {
        self.wallet_keyring
            .as_ref()
            .map(|k| k.public_key())
            .expect("Protocol context not initialized. Call init_protocol_context first.")
    }
}

impl<SF, KC> HasSecretKey for EstablishingState<SF, KC>
where
    SF: FrostCurve,
    KC: FrostCurve,
    Ed25519: Dleq<SF> + Dleq<KC>,
{
    fn secret_key(&self) -> Curve25519Secret {
        self.wallet_keyring
            .as_ref()
            .map(|k| k.secret_key())
            .expect("Protocol context not initialized. Call init_protocol_context first.")
    }
}

// --- Peer info accessors ---

impl<SF, KC> EstablishingState<SF, KC>
where
    SF: FrostCurve,
    KC: FrostCurve,
    Ed25519: Dleq<SF> + Dleq<KC>,
{
    pub fn peer_dleq_proof(&self) -> Option<&DleqProof<KC, Ed25519>> {
        self.peer_dleq_proof.as_ref()
    }

    pub fn peer_public_key(&self) -> Option<Curve25519PublicKey> {
        self.wallet_keyring.as_ref().and_then(|k| k.peer_public_key().ok())
    }

    pub fn peer_adapted_signature(&self) -> Option<&AdaptedSignature<Ed25519>> {
        self.peer_adapted_sig.as_ref()
    }

    pub fn peer_encrypted_offset(&self) -> Option<&EncryptedSecret<KC>> {
        self.peer_encrypted_offset.as_ref()
    }

    /// Set the peer's encrypted offset.
    pub fn set_peer_encrypted_offset(&mut self, offset: EncryptedSecret<KC>) {
        self.peer_encrypted_offset = Some(offset);
    }

    /// Verify the peer's payload signature from a [`ChannelInitPackage`].
    ///
    /// The signature is verified against the `nonce_pubkey` included in the package.
    /// Identity of the signer is established through the DLEQ proof and adapter
    /// signature verification performed after this step.
    fn verify_payload_signature(&self, package: &ChannelInitPackage<KC>) -> Result<(), EstablishError> {
        let t0 = package.dleq_proof.public_points.snark_point();
        let channel_id = self.metadata.channel_id().name();
        let dw = self.metadata.kes_configuration().dispute_window;
        let msg = payload_signature_message::<KC>(&channel_id, &package.encrypted_offset, dw, t0);
        if !package.payload_signature.verify(&package.nonce_pubkey, &msg) {
            return Err(EstablishError::InvalidPayloadSignature(
                "Peer's payload signature does not verify against nonce key".into(),
            ));
        }
        Ok(())
    }

    /// Generate a [`ChannelInitPackage`] containing an encrypted offset, adapted signature,
    /// and DLEQ proof for the initial channel state.
    ///
    /// The adapter signature is generated here (rather than in `initialize_channel_secrets`)
    /// because it signs a commitment transaction message built from the full channel metadata.
    ///
    /// Requires that `init_protocol_context()` has been called.
    pub fn generate_init_package<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Result<ChannelInitPackage<KC>, EstablishError> {
        // Generate the adapter signature on first call using the stored channel witness
        if self.adapted_sig.is_none() {
            let witness = self
                .channel_witness
                .as_ref()
                .ok_or_else(|| EstablishError::MissingInformation("Channel witness not available".into()))?;
            let offset = *witness.offset();
            let secret_key = self.secret_key();
            let msg = commitment_transaction_message(&self.metadata, &self.metadata.initial_balance(), 0);
            self.adapted_sig = Some(AdaptedSignature::<Ed25519>::sign(secret_key.as_scalar(), &offset, &msg, rng));
        }
        let dleq_proof = self
            .dleq_proof
            .clone()
            .ok_or_else(|| EstablishError::MissingInformation("DLEQ proof not available".into()))?;
        let encrypted_offset = self
            .encrypted_offset
            .clone()
            .ok_or_else(|| EstablishError::MissingInformation("Encrypted offset not available".into()))?;
        let adapted_signature = self
            .adapted_sig
            .clone()
            .ok_or_else(|| EstablishError::MissingInformation("Adapted signature not available".into()))?;
        // Sign the payload with the raw nonce key to bind the package to channel parameters
        let payload_signature = if let Some(ref sig) = self.payload_sig {
            sig.clone()
        } else {
            let t0 = dleq_proof.public_points.snark_point();
            let channel_id = self.metadata.channel_id().name();
            let dw = self.metadata.kes_configuration().dispute_window;
            let msg = payload_signature_message::<KC>(&channel_id, &encrypted_offset, dw, t0);
            let sig = SchnorrSignature::<KC>::sign(self.channel_nonce.nonce(), &msg, rng);
            self.payload_sig = Some(sig.clone());
            sig
        };
        let nonce_pubkey = KC::generator() * self.channel_nonce.nonce();
        Ok(ChannelInitPackage { encrypted_offset, adapted_signature, dleq_proof, payload_signature, nonce_pubkey })
    }

    /// Verify that the adaptor signature offset given to the KES.
    ///
    /// Per Section 4.6 of the white paper, each peer needs to verify that the value that the counterparty gave to the
    /// KES is in fact w0.
    ///
    /// This is done in three steps:
    /// 1. Verify the DLEQ proof provided by the peer. This proves that T_0 = w_0.G on the KES' curve is the same as
    ///    Q_0 = w_0.G on Ed25519.
    /// 2. Verify that the adapted signature, (s_hat, R_0, Q_0) _would_ be a valid signature for the channel closing
    ///    transaction _if_ we knew w (where Q_0 = w_0.G), since this would give us (s, R), the signature we need.
    /// 3. Since we've established that Q blinds w, if S0 == Q, then we know that the peer provided the correct offset
    ///    to the KES.
    pub fn verify_initial_offset<B: AsRef<[u8]>>(&self, adapter_sig_msg: B) -> Result<(), EstablishError> {
        use crate::cryptography::AsXmrPoint;
        // 1. Check the adapter signature is valid.
        let sig = self
            .peer_adapted_signature()
            .ok_or_else(|| EstablishError::MissingInformation("Adapted signature".into()))?;
        let peer_pubkey =
            self.peer_public_key().ok_or_else(|| EstablishError::MissingInformation("Peer public key".into()))?;
        if !sig.verify(&peer_pubkey.as_point(), adapter_sig_msg) {
            return Err(EstablishError::InvalidDataFromPeer(
                "Adapted signature verification failed".into(),
            ));
        }
        trace!("VALID: Peer's adapted signature is valid.");
        // 2. Check that Q matches the DLEQ proof's xmr_point.
        let q0 = sig.adapter_commitment();
        let dleq_proof =
            self.peer_dleq_proof().ok_or_else(|| EstablishError::MissingInformation("DLEQ proof".into()))?;
        if q0 != *dleq_proof.public_points.as_xmr_point() {
            return Err(EstablishError::InvalidDataFromPeer(
                "Peer public key does not match DLEQ proof".into(),
            ));
        }
        trace!("Peer DLEQ proof Q0 matches adapter signature Q0.");
        // 3. Verify the DLEQ proof itself.
        dleq_proof.verify().map_err(EstablishError::AdapterSigOffsetError)?;
        trace!("Peer DLEQ proof verified successfully.");
        debug!("Adapter signature offset verified successfully.");
        Ok(())
    }

    /// Verify the KES proof-of-knowledge against both parties' offset public points.
    ///
    /// The KES proof contains bound Schnorr proofs demonstrating the KES knows each
    /// party's decrypted offset secret and its own private key. This method:
    /// 1. Extracts offset public points from own and peer DLEQ proofs (KC curve)
    /// 2. Gets the KES public key from metadata
    /// 3. Delegates to [`KesPoKProofs::verify_for`] for verification
    pub fn verify_kes_proof(&self) -> Result<(), EstablishError> {
        let kes_proof =
            self.kes_proof.as_ref().ok_or_else(|| EstablishError::MissingInformation("KES proof".into()))?;
        let my_dleq =
            self.dleq_proof.as_ref().ok_or_else(|| EstablishError::MissingInformation("Peer DLEQ proof".into()))?;
        let peer_dleq =
            self.peer_dleq_proof().ok_or_else(|| EstablishError::MissingInformation("Peer DLEQ proof".into()))?;
        let kes_pubkey = self.metadata.kes_configuration().kes_public_key;
        // Determine which offset is customer/merchant based on our role
        let (customer_offset, merchant_offset) = match HasRole::role(self) {
            ChannelRole::Customer => (my_dleq.public_points.snark_point(), peer_dleq.public_points.snark_point()),
            ChannelRole::Merchant => (peer_dleq.public_points.snark_point(), my_dleq.public_points.snark_point()),
        };
        kes_proof.verify_for(customer_offset, merchant_offset, &kes_pubkey)?;
        debug!("KES proof-of-knowledge verified successfully.");
        Ok(())
    }

    /// Encrypt the channel secret to the KES, producing an [`EphemeralChannelId`] to send to the KES.
    ///
    /// Uses the party's nonce ($\hat{k}$) and the peer's ephemeral public key from the
    /// [`KesConfiguration`](crate::key_escrow_services::configuration::KesConfiguration)
    /// to derive a shared secret via ECDH-MC, then encrypts it to the KES global public key.
    pub fn prepare_kes_channel_id<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<EphemeralChannelId<KC>, EstablishError> {
        let kes_config = self.metadata.kes_configuration();
        let channel_id = self.metadata.channel_id().name();
        Ok(channel_keys::new_ephemeral_channel_id::<KC, _, R>(
            channel_id,
            self,
            self.channel_nonce.nonce(),
            &kes_config.peer_public_key,
            &kes_config.kes_public_key,
            rng,
        ))
    }
}

// --- From conversions for proposal states ---

use crate::state_machine::proposing_channel::{AwaitingConfirmation, AwaitingProposalResponse};

/// Helper to build a [`ChannelNonce`] from a proposal's channel secret and metadata.
fn channel_nonce_from_proposal<KC: FrostCurve>(
    secret: SerializableSecret<KC::F>,
    metadata: &StaticChannelMetadata<KC>,
) -> ChannelNonce<KC> {
    let peer_pubkey = &metadata.kes_configuration().peer_public_key;
    let channel_id = metadata.channel_id().name();
    ChannelNonce::new(Zeroizing::new(*secret), peer_pubkey, &channel_id)
}

impl<SF, KC> From<AwaitingProposalResponse<SF, KC>> for EstablishingState<SF, KC>
where
    SF: FrostCurve,
    KC: FrostCurve,
    Ed25519: Dleq<SF> + Dleq<KC>,
{
    fn from(state: AwaitingProposalResponse<SF, KC>) -> Self {
        let channel_nonce = channel_nonce_from_proposal(state.channel_secret, &state.metadata);
        EstablishingState {
            metadata: state.metadata,
            multisig_wallet: None,
            funding_transaction_ids: HashMap::new(),
            kes_proof: None,
            funding_tx_pipe: None,
            channel_nonce,
            wallet_keyring: None,
            peer_dleq_proof: None,
            dleq_proof: None,
            adapted_sig: None,
            peer_adapted_sig: None,
            peer_encrypted_offset: None,
            channel_witness: None,
            payload_sig: None,
            peer_payload_sig: None,
            peer_nonce_pubkey: None,
            _sf: PhantomData,
            encrypted_offset: None,
        }
    }
}

impl<SF, KC> From<AwaitingConfirmation<SF, KC>> for EstablishingState<SF, KC>
where
    SF: FrostCurve,
    KC: FrostCurve,
    Ed25519: Dleq<SF> + Dleq<KC>,
{
    fn from(state: AwaitingConfirmation<SF, KC>) -> Self {
        let channel_nonce = channel_nonce_from_proposal(state.channel_secret, &state.metadata);
        EstablishingState {
            metadata: state.metadata,
            multisig_wallet: None,
            funding_transaction_ids: HashMap::new(),
            kes_proof: None,
            funding_tx_pipe: None,
            channel_nonce,
            wallet_keyring: None,
            peer_dleq_proof: None,
            dleq_proof: None,
            adapted_sig: None,
            peer_adapted_sig: None,
            peer_encrypted_offset: None,
            channel_witness: None,
            payload_sig: None,
            peer_payload_sig: None,
            peer_nonce_pubkey: None,
            _sf: PhantomData,
            encrypted_offset: None,
        }
    }
}

// ============================================================================
// Role-Specific Ephemeral Wrappers
// ============================================================================

/// Ephemeral wrapper around [`EstablishingState`] for merchant-specific protocol steps.
///
/// Constructed on-demand when the merchant needs to perform establishment operations,
/// then unwrapped via [`into_inner`](MerchantEstablishing::into_inner) to return the state.
pub struct MerchantEstablishing<SF = Grumpkin, KC = Ed25519>
where
    SF: FrostCurve,
    KC: FrostCurve,
    Ed25519: Dleq<SF> + Dleq<KC>,
{
    inner: EstablishingState<SF, KC>,
}

impl<SF, KC> MerchantEstablishing<SF, KC>
where
    SF: FrostCurve,
    KC: FrostCurve,
    Ed25519: Dleq<SF> + Dleq<KC>,
{
    /// Wrap an `EstablishingState`. Panics if the state is not for a merchant.
    pub fn new(state: EstablishingState<SF, KC>) -> Self {
        assert_eq!(
            HasRole::role(&state),
            ChannelRole::Merchant,
            "MerchantEstablishing requires a merchant state"
        );
        Self { inner: state }
    }

    /// Unwrap and return the underlying `EstablishingState`.
    pub fn into_inner(self) -> EstablishingState<SF, KC> {
        self.inner
    }

    /// Borrow the underlying state.
    pub fn state(&self) -> &EstablishingState<SF, KC> {
        &self.inner
    }

    /// Mutably borrow the underlying state.
    pub fn state_mut(&mut self) -> &mut EstablishingState<SF, KC> {
        &mut self.inner
    }

    /// Generate a [`ChannelInitPackage`] containing the merchant's encrypted offset,
    /// adapted signature, and DLEQ proof for the initial channel state.
    pub fn generate_init_package<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Result<ChannelInitPackage<KC>, EstablishError> {
        self.inner.generate_init_package(rng)
    }

    /// Receive and verify the customer's [`ChannelInitPackage`].
    ///
    /// Verifies the payload signature, then stores the customer's adapted signature,
    /// DLEQ proof, and encrypted offset, and verifies the initial offset using
    /// the 3-step verification (adapter sig + Q match + DLEQ).
    pub fn receive_customer_init_package(&mut self, package: ChannelInitPackage<KC>) -> Result<(), EstablishError> {
        self.inner.verify_payload_signature(&package)?;
        self.inner.peer_payload_sig = Some(package.payload_signature.clone());
        self.inner.peer_nonce_pubkey = Some(package.nonce_pubkey);
        self.inner.set_peer_encrypted_offset(package.encrypted_offset);
        self.inner.set_peer_adapted_signature(package.adapted_signature);
        self.inner.set_peer_dleq_proof(package.dleq_proof);
        let msg = commitment_transaction_message(&self.inner.metadata, &self.inner.metadata.initial_balance(), 0);
        self.inner.verify_initial_offset(msg)
    }

    /// Returns `true` if both own and peer encrypted offsets are available.
    pub fn has_both_offsets(&self) -> bool {
        self.inner.encrypted_offset.is_some() && self.inner.peer_encrypted_offset.is_some()
    }

    /// Bundle both encrypted offsets and payload signatures for forwarding to the KES.
    pub fn bundle_for_kes(&self) -> Result<KesInitBundle<KC>, EstablishError> {
        let merchant_encrypted_offset = self
            .inner
            .encrypted_offset
            .clone()
            .ok_or_else(|| EstablishError::MissingInformation("Merchant encrypted offset".into()))?;
        let customer_encrypted_offset = self
            .inner
            .peer_encrypted_offset
            .clone()
            .ok_or_else(|| EstablishError::MissingInformation("Customer encrypted offset (peer)".into()))?;
        let merchant_dleq = self
            .inner
            .dleq_proof
            .as_ref()
            .ok_or_else(|| EstablishError::MissingInformation("Merchant DLEQ proof".into()))?;
        let customer_dleq = self
            .inner
            .peer_dleq_proof
            .as_ref()
            .ok_or_else(|| EstablishError::MissingInformation("Customer DLEQ proof (peer)".into()))?;
        let merchant_payload_sig = self
            .inner
            .payload_sig
            .clone()
            .ok_or_else(|| EstablishError::MissingInformation("Merchant payload signature".into()))?;
        let customer_payload_sig = self
            .inner
            .peer_payload_sig
            .clone()
            .ok_or_else(|| EstablishError::MissingInformation("Customer payload signature (peer)".into()))?;

        let channel_id = self.inner.metadata.channel_id().name();
        let dispute_window = self.inner.metadata.kes_configuration().dispute_window;
        let merchant_t0 = *merchant_dleq.public_points.snark_point();
        let customer_t0 = *customer_dleq.public_points.snark_point();
        // Nonce pubkeys: merchant own = G * nonce, customer = stored from their init package
        let merchant_ephemeral_pubkey = KC::generator() * self.inner.channel_nonce.nonce();
        let customer_ephemeral_pubkey = self
            .inner
            .peer_nonce_pubkey
            .ok_or_else(|| EstablishError::MissingInformation("Customer nonce pubkey (peer)".into()))?;

        Ok(KesInitBundle {
            channel_id,
            dispute_window,
            customer_encrypted_offset,
            customer_t0,
            customer_ephemeral_pubkey,
            customer_payload_sig,
            merchant_encrypted_offset,
            merchant_t0,
            merchant_ephemeral_pubkey,
            merchant_payload_sig,
        })
    }

    /// Store a KES proof-of-knowledge received from the KES.
    pub fn receive_kes_proof(&mut self, proof: KesPoKProofs<KC>) {
        self.inner.kes_created(proof);
    }
}

/// Ephemeral wrapper around [`EstablishingState`] for customer-specific protocol steps.
///
/// Constructed on-demand when the customer needs to perform establishment operations,
/// then unwrapped via [`into_inner`](CustomerEstablishing::into_inner) to return the state.
pub struct CustomerEstablishing<SF = Grumpkin, KC = Ed25519>
where
    SF: FrostCurve,
    KC: FrostCurve,
    Ed25519: Dleq<SF> + Dleq<KC>,
{
    inner: EstablishingState<SF, KC>,
}

impl<SF, KC> CustomerEstablishing<SF, KC>
where
    SF: FrostCurve,
    KC: FrostCurve,
    Ed25519: Dleq<SF> + Dleq<KC>,
{
    /// Wrap an `EstablishingState`. Panics if the state is not for a customer.
    pub fn new(state: EstablishingState<SF, KC>) -> Self {
        assert_eq!(
            HasRole::role(&state),
            ChannelRole::Customer,
            "CustomerEstablishing requires a customer state"
        );
        Self { inner: state }
    }

    /// Unwrap and return the underlying `EstablishingState`.
    pub fn into_inner(self) -> EstablishingState<SF, KC> {
        self.inner
    }

    /// Borrow the underlying state.
    pub fn state(&self) -> &EstablishingState<SF, KC> {
        &self.inner
    }

    /// Mutably borrow the underlying state.
    pub fn state_mut(&mut self) -> &mut EstablishingState<SF, KC> {
        &mut self.inner
    }

    /// Generate a [`ChannelInitPackage`] containing the customer's encrypted offset,
    /// adapted signature, and DLEQ proof for the initial channel state.
    pub fn generate_init_package<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Result<ChannelInitPackage<KC>, EstablishError> {
        self.inner.generate_init_package(rng)
    }

    /// Receive and verify the merchant's [`ChannelInitPackage`].
    ///
    /// Verifies the payload signature, then stores the merchant's adapted signature,
    /// DLEQ proof, and encrypted offset, and verifies the initial offset using
    /// the 3-step verification (adapter sig + Q match + DLEQ).
    pub fn receive_merchant_init_package(&mut self, package: ChannelInitPackage<KC>) -> Result<(), EstablishError> {
        self.inner.verify_payload_signature(&package)?;
        self.inner.peer_payload_sig = Some(package.payload_signature.clone());
        self.inner.peer_nonce_pubkey = Some(package.nonce_pubkey);
        self.inner.set_peer_encrypted_offset(package.encrypted_offset);
        self.inner.set_peer_adapted_signature(package.adapted_signature);
        self.inner.set_peer_dleq_proof(package.dleq_proof);
        let msg = commitment_transaction_message(&self.inner.metadata, &self.inner.metadata.initial_balance(), 0);
        self.inner.verify_initial_offset(msg)
    }

    /// Return a reference to the customer's encrypted offset for the KES (if generated).
    pub fn encrypted_offset_for_kes(&self) -> Option<&EncryptedSecret<KC>> {
        self.inner.encrypted_offset.as_ref()
    }
}

/// Compute the commitment transaction message for a given channel state.
///
/// Uses a `DigestTranscript<Blake2b512>` to bind the adapter signature to the full
/// commitment transaction fields: channel ID hash, update count, balances, closing
/// addresses, and network.
///
/// This is an interim commitment message. The adapter signature should ultimately sign
/// the actual Monero transaction challenge, but the current MultisigWallet API does not
/// expose this. This transcript-based message will be replaced when it does.
pub(crate) fn commitment_transaction_message<KC: ciphersuite::Ciphersuite>(
    metadata: &StaticChannelMetadata<KC>,
    balances: &Balances,
    update_count: u64,
) -> Vec<u8> {
    use blake2::Blake2b512;
    use flexible_transcript::{DigestTranscript, Transcript};

    let mut transcript = DigestTranscript::<Blake2b512>::new(b"Grease CommitmentTx v1");
    transcript.append_message(b"channel_id", metadata.channel_id().hash());
    transcript.append_message(b"update_count", update_count.to_le_bytes());
    transcript.append_message(b"merchant_balance", balances.merchant.to_piconero().to_le_bytes());
    transcript.append_message(b"customer_balance", balances.customer.to_piconero().to_le_bytes());
    let closing = metadata.channel_id().closing_addresses();
    transcript.append_message(b"merchant_closing_address", closing.merchant().as_bytes());
    transcript.append_message(b"customer_closing_address", closing.customer().as_bytes());
    let network_label = match metadata.network() {
        Network::Mainnet => "mainnet",
        Network::Stagenet => "stagenet",
        Network::Testnet => "testnet",
    };
    transcript.append_message(b"network", network_label.as_bytes());
    transcript.challenge(b"commitment_tx_message").to_vec()
}

// --- LifeCycle implementation ---

use crate::state_machine::lifecycle::{LifeCycle, LifecycleStage};

impl<SF, KC> LifeCycle<KC> for EstablishingState<SF, KC>
where
    SF: FrostCurve,
    KC: FrostCurve,
    Ed25519: Dleq<SF> + Dleq<KC>,
{
    fn stage(&self) -> LifecycleStage {
        LifecycleStage::Establishing
    }

    fn metadata(&self) -> &StaticChannelMetadata<KC> {
        &self.metadata
    }

    fn balance(&self) -> Balances {
        self.metadata.initial_balance()
    }

    fn wallet_address(&self, network: Network) -> Option<String> {
        self.multisig_address(network)
    }
}
