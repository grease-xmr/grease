use crate::amount::MoneroAmount;
use crate::balance::Balances;
use crate::channel_id::ChannelIdMetadata;
use crate::channel_metadata::{DynamicChannelMetadata, StaticChannelMetadata};
use crate::cryptography::adapter_signature::{AdaptedSignature, SchnorrSignature};
use crate::cryptography::dleq::{Dleq, DleqProof};
use crate::cryptography::keys::{Curve25519PublicKey, Curve25519Secret, PublicKey, PublicKeyCommitment};
use crate::cryptography::pok::KesPoKProofs;
use crate::cryptography::secret_encryption::{EncryptedSecret, SecretWithRole};
use crate::cryptography::serializable_secret::SerializableSecret;
use crate::cryptography::{CrossCurveScalar, Offset};
use crate::grease_protocol::channel_keys::{self, ChannelNonce, EphemeralChannelId};
use crate::grease_protocol::establish_channel::{payload_signature_message, ChannelInitPackage, EstablishError};
use crate::grease_protocol::kes_establishing::KesInitBundle;
use crate::grease_protocol::multisig_wallet::{LinkedMultisigWallets, MultisigWalletError, SharedPublicKey};
use crate::monero::data_objects::{TransactionId, TransactionRecord};
use crate::payment_channel::multisig_negotioation::MultisigWalletKeyNegotiation;
use crate::payment_channel::{ChannelRole, HasRole};
use crate::state_machine::error::LifeCycleError;
use crate::state_machine::lifecycle::ChannelState;
use crate::state_machine::open_channel::EstablishedChannelState;
use crate::state_machine::proposing_channel::{AwaitingConfirmation, AwaitingProposalResponse};
use ciphersuite::Ed25519;
use grease_grumpkin::Grumpkin;
use log::*;
use modular_frost::curve::Curve as FrostCurve;
use rand_core::{CryptoRng, OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::marker::PhantomData;
use zeroize::Zeroizing;
//------------------------------------   Establishing Channel State  ------------------------------------------------//

/// State for a channel being established.
///
/// This state provides the cryptographic operations needed during channel establishment
/// including wallet key exchange, KES client setup, and adapter signature verification.
///
/// The generic parameter `SF` specifies the SNARK-friendly curve (defaults to Grumpkin).
/// The generic parameter `KC` specifies the Curve that the KES has elected to use. By default, the KES uses Ed25519,
/// the same curve as Monero.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "", deserialize = "KC::F: ciphersuite::group::ff::PrimeFieldBits"))]
pub struct EstablishingState<SF = Grumpkin, KC = Ed25519>
where
    SF: FrostCurve,
    KC: FrostCurve,
    Ed25519: Dleq<SF> + Dleq<KC>,
{
    // Variables specified at start of stage
    pub(crate) metadata: StaticChannelMetadata<KC>,
    /// The channel nonce ($\hat{k}_a$ or $\hat{k}_b$) with its ECDH-MC shared secret.
    pub(crate) channel_nonce: ChannelNonce<KC>,
    /// The encrypted initial adapter offset to be sent to the KES, ($\chi$).
    pub(crate) encrypted_offset: EncryptedSecret<KC>,
    /// My DLEQ proof for the initial adapter offset (public data).
    pub(crate) dleq_proof: DleqProof<KC, Ed25519>,
    /// The channel witness, kept between `initialize_channel_secrets` and `generate_init_package`.
    /// Encrypted at rest via [`CrossCurveScalar`]'s serde implementation.
    pub(crate) initial_adapter_offset: CrossCurveScalar<KC>,
    /// This parties half of the multisig wallet's private spend key
    pub(crate) wallet_partial_spend_key: Curve25519Secret,

    // Variables determined during the stage
    pub(crate) multisig_wallet: Option<MultisigWallet>,
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
    /// The peer's encrypted initial adapter offset to be sent to the KES, ($\chi$).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub(crate) peer_encrypted_offset: Option<EncryptedSecret<KC>>,
    /// Peer's DLEQ proof received during establishment (public data).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub(crate) peer_dleq_proof: Option<DleqProof<KC, Ed25519>>,
    /// My adapted signature for the initial channel close transaction (public data).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub(crate) adapted_sig: Option<AdaptedSignature<Ed25519>>,
    /// Peer's adapted signature for the initial channel close transaction received during establishment (public data).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub(crate) peer_adapted_sig: Option<AdaptedSignature<Ed25519>>,
    /// Our payload signature (signs our init package fields with ephemeral key).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub(crate) payload_sig: Option<SchnorrSignature<KC>>,
    /// Peer's payload signature received during init package exchange.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub(crate) peer_payload_sig: Option<SchnorrSignature<KC>>,
    /// Peer's nonce public key from their init package.
    #[serde(
        serialize_with = "crate::helpers::option_serialize_ge",
        deserialize_with = "crate::helpers::option_deserialize_ge",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub(crate) peer_nonce_pubkey: Option<KC::G>,
    #[serde(skip)]
    pub(crate) preprepare_data: Vec<u8>,
    #[serde(skip)]
    _sf: PhantomData<SF>,
}

/// Type alias for the default curve types (Grumpkin + Ed25519).
pub type DefaultEstablishingState = EstablishingState<Grumpkin>;

impl<SF, KC> EstablishingState<SF, KC>
where
    SF: FrostCurve,
    KC: FrostCurve,
    Ed25519: Dleq<SF> + Dleq<KC>,
{
    //---------------------------------------  Constructors -------------------------------------------------------//
    /// Constructor for EstablishingState.
    ///
    /// This generates a wallet key ring for the establishment phase as well as
    /// a random channel witness (valid in both Ed25519 and KC), then:
    /// 1. Generates a DLEQ proof showing the witness is the same discrete log on both curves
    /// 2. Encrypts the offset to the KES public key from metadata
    /// 3. Stores the witness for adapter signature generation in [`generate_init_package`]
    ///
    /// The adapter signature is deferred to `generate_init_package` because it signs a
    /// commitment transaction message that requires the full channel metadata (peer data).
    fn new_with_secrets<R: RngCore + CryptoRng>(
        rng: &mut R,
        metadata: StaticChannelMetadata<KC>,
        nonce: ChannelNonce<KC>,
        partial_spend_key: Curve25519Secret,
    ) -> Result<Self, EstablishError>
    where
        KC::F: ciphersuite::group::ff::PrimeFieldBits,
    {
        let role = metadata.role();
        let initial_adapter_offset = CrossCurveScalar::<KC>::random_with_rng(rng);
        let (proof, public_points) = <Ed25519 as Dleq<KC>>::generate_dleq(rng, &initial_adapter_offset)
            .map_err(EstablishError::DleqGenerationError)?;
        let dleq_proof = DleqProof::new(proof, public_points);

        let kes_pubkey = metadata.kes_configuration().kes_public_key;
        let kes_w0 = initial_adapter_offset.as_foreign_scalar();
        let kes_w0 = SecretWithRole::new(kes_w0, role);
        let domain = crate::grease_protocol::kes_establishing::kes_offset_domain(&metadata.channel_id().name());
        let encrypted_offset = EncryptedSecret::encrypt(kes_w0, &kes_pubkey, rng, domain);

        debug!("Channel secrets initialized: DLEQ proof, encrypted offset, and witness stored.");
        let this = Self {
            metadata,
            channel_nonce: nonce,
            wallet_partial_spend_key: partial_spend_key,
            encrypted_offset,
            dleq_proof,
            initial_adapter_offset,
            peer_nonce_pubkey: None,
            multisig_wallet: None,
            funding_transaction_ids: Default::default(),
            kes_proof: None,
            funding_tx_pipe: None,
            peer_encrypted_offset: None,
            peer_dleq_proof: None,
            adapted_sig: None,
            peer_adapted_sig: None,
            payload_sig: None,
            peer_payload_sig: None,
            _sf: Default::default(),
            preprepare_data: vec![],
        };
        Ok(this)
    }

    //---------------------------------------  Accessors -------------------------------------------------------//

    /// Provide access to the channel ID metadata.
    pub fn channel_id_metadata(&self) -> &ChannelIdMetadata<KC> {
        self.metadata.channel_id()
    }

    /// The partial wallet public key
    pub fn partial_wallet_public_key(&self) -> Curve25519PublicKey {
        Curve25519PublicKey::from_secret(&self.wallet_partial_spend_key)
    }

    /// The public key for this channel nonce, $hat(k)_a /cdot G$
    pub fn nonce_pubkey(&self) -> &KC::G {
        &self.channel_nonce.ephemeral_pubkey
    }

    /// Compute the per-channel KES public key ($P_g = \kappa \cdot P_K$).
    ///
    /// Both parties can derive this locally from their ECDH-MC shared secret ($\kappa$)
    /// and the global KES public key ($P_K$), without needing the KES to send it.
    ///
    /// $\kappa$ is derived from the party's own channel nonce and the peer's nonce public
    /// key (received during init package exchange), ensuring both sides compute the same
    /// value via ECDH symmetry.
    ///
    /// Returns `None` if the peer's nonce public key has not been received yet.
    pub fn kes_channel_pubkey(&self) -> Option<KC::G> {
        let peer_nonce_pk = self.peer_nonce_pubkey.as_ref()?;
        let channel_id = self.metadata.channel_id().name();
        let kappa = channel_keys::ephemeral_channel_id::<KC>(self.channel_nonce.nonce(), peer_nonce_pk, &channel_id);
        let kes_pubkey = self.metadata.kes_configuration().kes_public_key;
        Some(kes_pubkey * kappa)
    }

    pub fn peer_dleq_proof(&self) -> Option<&DleqProof<KC, Ed25519>> {
        self.peer_dleq_proof.as_ref()
    }

    pub fn peer_adapted_signature(&self) -> Option<&AdaptedSignature<Ed25519>> {
        self.peer_adapted_sig.as_ref()
    }

    pub fn peer_encrypted_offset(&self) -> Option<&EncryptedSecret<KC>> {
        self.peer_encrypted_offset.as_ref()
    }

    pub fn multisig_address(&self) -> Option<String> {
        self.multisig_wallet.as_ref().map(|w| w.address().to_string())
    }

    pub fn funding_total(&self) -> MoneroAmount {
        self.funding_transaction_ids.values().map(|r| r.amount).sum()
    }

    pub fn multisig_wallet_data(&self) -> Option<&MultisigWallet> {
        self.multisig_wallet.as_ref()
    }

    //---------------------------------------  Setters -------------------------------------------------------//

    /// Set the peer's adapted signature.
    pub fn set_peer_adapted_signature(&mut self, adapted_signature: AdaptedSignature<Ed25519>) {
        self.peer_adapted_sig = Some(adapted_signature);
    }

    /// Set the peer's DLEQ proof.
    pub fn set_peer_dleq_proof(&mut self, dleq_proof: DleqProof<KC, Ed25519>) {
        self.peer_dleq_proof = Some(dleq_proof);
    }

    /// Read the peer's adapted signature from the given reader and store it.
    pub fn store_peer_adapted_signature<R: std::io::Read>(&mut self, reader: &mut R) -> Result<(), EstablishError> {
        let adapted_signature = AdaptedSignature::<Ed25519>::read(reader)?;
        self.set_peer_adapted_signature(adapted_signature);
        Ok(())
    }

    /// Set the peer's encrypted offset.
    pub fn set_peer_encrypted_offset(&mut self, offset: EncryptedSecret<KC>) {
        self.peer_encrypted_offset = Some(offset);
    }

    pub fn wallet_created(&mut self, wallet: MultisigWallet) {
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

    /// Prepare the initial commitment transaction for signing.
    ///
    /// This creates the transaction that pays the initial balances to the closing addresses,
    /// generates MuSig2 nonces, and stores the preprocess data for exchange with the peer.
    ///
    /// After calling this, exchange preprocess data with the peer using [`preprepare_data()`]
    /// and [`receive_peer_preprocess_data()`], then call [`generate_init_package()`].
    pub async fn prepare_initial_transaction(&mut self) -> Result<(), EstablishError> {
        use crate::wallet::common::MINIMUM_FEE;
        use crate::wallet::multisig_wallet::translate_payments;

        let wallet = self
            .multisig_wallet
            .as_mut()
            .ok_or_else(|| EstablishError::MissingInformation("Multisig wallet not created yet".into()))?;

        // Build payment destinations from closing addresses and initial balance
        let closing_addrs = self.metadata.channel_id().closing_addresses();
        let balances = self.metadata.initial_balance();
        let unadjusted = [(closing_addrs.merchant, balances.merchant), (closing_addrs.customer, balances.customer)];
        let fee = MoneroAmount::from_piconero(MINIMUM_FEE);
        let payments = translate_payments(unadjusted, fee).map_err(MultisigWalletError::from)?;

        // Prepare the transaction (creates signing machine and generates nonces)
        let mut rng = wallet.deterministic_rng();
        wallet.prepare(payments, &mut rng).await.map_err(MultisigWalletError::from)?;

        // Store the preprocess data for exchange
        let pp_data = wallet
            .my_pre_process_data()
            .ok_or_else(|| EstablishError::MissingInformation("Failed to generate preprocess data".into()))?;
        self.preprepare_data = pp_data;

        Ok(())
    }

    /// Receive peer's preprocess data and complete the partial signing step.
    ///
    /// This stores the peer's preprocess data in the wallet and calls `partial_sign()`
    /// to generate our signing share. After this, [`generate_init_package()`] can be called.
    pub fn receive_peer_preprocess_data(&mut self, data: Vec<u8>) -> Result<(), EstablishError> {
        let wallet = self
            .multisig_wallet
            .as_mut()
            .ok_or_else(|| EstablishError::MissingInformation("Multisig wallet not created yet".into()))?;

        wallet.set_peer_process_data(data);
        wallet.partial_sign().map_err(MultisigWalletError::from)?;

        Ok(())
    }

    /// Returns a copy of the initial commit transaction pre-prepare data, if it exists.
    pub fn preprepare_data(&self) -> Result<Vec<u8>, EstablishError> {
        if self.preprepare_data.is_empty() {
            Err(EstablishError::MissingInformation("Preprepare data".into()))
        } else {
            Ok(self.preprepare_data.clone())
        }
    }

    //---------------------------------------  Verification -------------------------------------------------------//

    /// Verify the peer's payload signature from a [`ChannelInitPackage`].
    ///
    /// The signature is verified against the `nonce_pubkey` included in the package.
    /// Identity of the signer is established through the DLEQ proof and adapter
    /// signature verification performed after this step.
    fn verify_payload_signature(&self, package: &ChannelInitPackage<KC>) -> Result<(), EstablishError> {
        let t0 = package.dleq_proof.public_points.foreign_point();
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
        let wallet = self
            .multisig_wallet
            .as_ref()
            .ok_or_else(|| EstablishError::MissingInformation("Multisig wallet".into()))?;
        let peer_pubkey = wallet.peer_public_key().as_point();
        if !sig.verify(&peer_pubkey, adapter_sig_msg) {
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
    /// party's decrypted offset secret and the per-channel private key $k_g$. This method:
    /// 1. Extracts offset public points from own and peer DLEQ proofs (KC curve)
    /// 2. Gets the per-channel KES public key $P_g$ (set during establishment)
    /// 3. Delegates to [`KesPoKProofs::verify_for`] for verification
    pub fn verify_kes_proof(&self) -> Result<(), EstablishError> {
        let kes_proof =
            self.kes_proof.as_ref().ok_or_else(|| EstablishError::MissingInformation("KES proof".into()))?;
        let my_dleq = &self.dleq_proof;
        let peer_dleq = self
            .peer_dleq_proof()
            .ok_or_else(|| EstablishError::MissingInformation(format!("{} DLEQ proof", HasRole::role(self).other())))?;
        let kes_channel_pubkey = self.kes_channel_pubkey().ok_or_else(|| {
            EstablishError::MissingInformation(
                "KES per-channel public key (P_g) — peer nonce pubkey not received".into(),
            )
        })?;
        // Determine which offset is customer/merchant based on our role
        let (customer_offset, merchant_offset) = match HasRole::role(self) {
            ChannelRole::Customer => (my_dleq.public_points.foreign_point(), peer_dleq.public_points.foreign_point()),
            ChannelRole::Merchant => (peer_dleq.public_points.foreign_point(), my_dleq.public_points.foreign_point()),
        };
        kes_proof.verify_for(customer_offset, merchant_offset, &kes_channel_pubkey)?;
        debug!("KES proof-of-knowledge verified successfully.");
        Ok(())
    }

    //---------------------------------------  State transition ------------------------------------------------------//
    pub fn requirements_met(&self) -> bool {
        let mut missing = Vec::with_capacity(10);
        if self.multisig_wallet.is_none() {
            missing.push("Multisig wallet")
        }
        if self.kes_proof.is_none() {
            missing.push("KES PoK proofs");
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
        if self.adapted_sig.is_none() {
            missing.push("Adapted signature for initial channel state");
        }
        if self.payload_sig.is_none() {
            missing.push("Payload signature");
        }
        if self.peer_payload_sig.is_none() {
            missing.push("Peer payload signature");
        }
        if self.peer_nonce_pubkey.is_none() {
            missing.push("Peer nonce public key");
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

    pub fn to_channel_state(self) -> ChannelState<SF, KC> {
        ChannelState::Establishing(self)
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

    #[allow(clippy::result_large_err)]
    pub fn next(self) -> Result<EstablishedChannelState<SF, KC>, (Self, LifeCycleError)> {
        debug!("Trying to move from Establishing to Established state");
        if !self.requirements_met() {
            debug!("Cannot change from Establishing to Established because all requirements are not met");
            return Err((self, LifeCycleError::InvalidStateTransition));
        }
        debug!("Transitioning to Established wallet state");
        let kes_channel_pubkey = self.kes_channel_pubkey();
        let dynamic = DynamicChannelMetadata::new(self.metadata.initial_balance(), 0);
        let open_channel = EstablishedChannelState {
            metadata: self.metadata,
            dynamic,
            multisig_wallet: self.multisig_wallet.unwrap(),
            funding_transactions: self.funding_transaction_ids,
            current_update: None,
            kes_channel_pubkey,
        };
        Ok(open_channel)
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

// --- Peer info accessors ---

impl<SF, KC> EstablishingState<SF, KC>
where
    SF: FrostCurve,
    KC: FrostCurve,
    Ed25519: Dleq<SF> + Dleq<KC>,
{
    /// Generate a [`ChannelInitPackage`] containing an encrypted offset, adapted signature,
    /// and DLEQ proof for the initial channel state.
    ///
    /// The adapter signature is generated here (rather than in `initialize_channel_secrets`)
    /// because it signs a commitment transaction message built from the full channel metadata.
    ///
    /// Requires that `prepare_initial_transaction()` has been called and `partial_sign()` completed.
    pub fn generate_init_package<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Result<ChannelInitPackage<KC>, EstablishError> {
        // Check that the initial commitment transaction is ready and has been signed.
        let Some(wallet) = self.multisig_wallet.as_ref() else {
            return Err(EstablishError::MissingInformation("Multisig wallet not created yet".into()));
        };

        // Generate the commitment transaction message binding the signature to the channel state
        let msg = self.commitment_message();

        let initial_witness = Curve25519Secret::from(*self.initial_adapter_offset.offset());
        let adapted_sig = wallet.adapt_signature(&initial_witness, &msg).map_err(MultisigWalletError::from)?;
        self.adapted_sig = Some(adapted_sig.clone());
        let dleq_proof = self.dleq_proof.clone();

        let adapted_signature = self
            .adapted_sig
            .clone()
            .ok_or_else(|| EstablishError::MissingInformation("Adapted signature not available".into()))?;
        // Sign the payload with the raw nonce key to bind the package to channel parameters
        let payload_signature = self.sign_init_package(rng, &dleq_proof);
        self.payload_sig = Some(payload_signature.clone());
        let nonce_pubkey = KC::generator() * self.channel_nonce.nonce();
        let encrypted_offset = self.encrypted_offset.clone();
        Ok(ChannelInitPackage { encrypted_offset, adapted_signature, dleq_proof, payload_signature, nonce_pubkey })
    }

    /// Generate the commitment transaction message for the initial channel state.
    ///
    /// This binds the adapter signature to the channel ID and initial balances.
    pub fn commitment_message(&self) -> Vec<u8> {
        use crate::wallet::multisig_wallet::commitment_tx_message;
        let channel_id = self.metadata.channel_id().name();
        let balances = self.metadata.initial_balance();
        commitment_tx_message(&channel_id, 0, balances.customer.to_piconero(), balances.merchant.to_piconero())
    }

    fn sign_init_package<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        dleq: &DleqProof<KC, Ed25519>,
    ) -> SchnorrSignature<KC> {
        let t0 = dleq.public_points.foreign_point();
        let channel_id = self.metadata.channel_id().name();
        let dw = self.metadata.kes_configuration().dispute_window;
        let encrypted_offset = &self.encrypted_offset;
        let msg = payload_signature_message::<KC>(&channel_id, encrypted_offset, dw, t0);
        SchnorrSignature::<KC>::sign(self.channel_nonce.nonce(), &msg, rng)
    }

    /// Creates a unique channel keypair, $\kappa$ ([`EphemeralChannelId`]) to send to the KES. Both the customer and merchant know the
    /// secret key. The KES uses this value to derive a unique public key for the channel that it then shares with the parties.
    ///
    /// Uses the party's nonce ($\hat{k}$) and the peer's nonce public key (received during
    /// init package exchange) to derive a shared secret via ECDH-MC, then encrypts it to
    /// the KES global public key. Both parties derive the same shared secret via ECDH symmetry.
    pub fn generate_kes_channel_id<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<EphemeralChannelId<KC>, EstablishError> {
        let peer_nonce_pk = self
            .peer_nonce_pubkey
            .ok_or_else(|| EstablishError::MissingInformation("Peer nonce public key not received".into()))?;
        let kes_config = self.metadata.kes_configuration();
        let channel_id = self.metadata.channel_id().name();
        Ok(channel_keys::new_ephemeral_channel_id::<KC, _, R>(
            channel_id,
            self,
            self.channel_nonce.nonce(),
            &peer_nonce_pk,
            &kes_config.kes_public_key,
            rng,
        ))
    }
}

// ---------------------------------- From conversions for proposal states ------------------------------------------

/// Helper to build a [`ChannelNonce`] from a proposal's channel secret and metadata.
fn channel_nonce_from_proposal<KC: FrostCurve>(
    secret: SerializableSecret<KC::F>,
    metadata: &StaticChannelMetadata<KC>,
) -> ChannelNonce<KC> {
    let peer_pubkey = &metadata.kes_configuration().peer_public_key;
    let channel_id = metadata.channel_id().name();
    ChannelNonce::new(Zeroizing::new(*secret), peer_pubkey, &channel_id)
}

impl<SF, KC> TryFrom<AwaitingProposalResponse<SF, KC>> for EstablishingState<SF, KC>
where
    SF: FrostCurve,
    KC: FrostCurve,
    Ed25519: Dleq<SF> + Dleq<KC>,
{
    type Error = EstablishError;
    fn try_from(state: AwaitingProposalResponse<SF, KC>) -> Result<Self, Self::Error> {
        let channel_nonce = channel_nonce_from_proposal(state.channel_secret, &state.metadata);
        EstablishingState::new_with_secrets(&mut OsRng, state.metadata, channel_nonce, state.partial_spend_key)
    }
}

impl<SF, KC> TryFrom<AwaitingConfirmation<SF, KC>> for EstablishingState<SF, KC>
where
    SF: FrostCurve,
    KC: FrostCurve,
    Ed25519: Dleq<SF> + Dleq<KC>,
{
    type Error = EstablishError;
    fn try_from(state: AwaitingConfirmation<SF, KC>) -> Result<Self, Self::Error> {
        let channel_nonce = channel_nonce_from_proposal(state.channel_secret, &state.metadata);
        EstablishingState::new_with_secrets(&mut OsRng, state.metadata, channel_nonce, state.partial_spend_key)
    }
}

//---------------------------------- Role-Specific EstablishingState Wrappers ------------------------------------------

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
    wallet_setup: MerchantSetup<MultisigWalletKeyNegotiation>,
}

impl<SF, KC> MerchantEstablishing<SF, KC>
where
    SF: FrostCurve,
    KC: FrostCurve,
    Ed25519: Dleq<SF> + Dleq<KC>,
{
    /// Wrap an `EstablishingState`, returning an error if the state is not for a merchant.
    pub fn new(state: EstablishingState<SF, KC>, rpc_url: impl Into<String>) -> Result<Self, EstablishError> {
        let role = HasRole::role(&state);
        if role != ChannelRole::Merchant {
            return Err(EstablishError::WrongRole { expected: ChannelRole::Merchant, got: role });
        }
        let network = state.metadata.network();
        let w = MultisigWalletKeyNegotiation::new(
            ChannelRole::Merchant,
            network,
            state.wallet_partial_spend_key.clone(),
            rpc_url,
        );
        let wallet_setup = MerchantSetup::new(w).map_err(|e| EstablishError::MissingInformation(e.to_string()))?;
        Ok(Self { inner: state, wallet_setup })
    }

    /// Unwrap and return the underlying `EstablishingState`.
    pub fn into_inner(self) -> EstablishingState<SF, KC> {
        self.inner
    }

    /// Generate and return a commitment to the merchant's public key.
    pub fn wallet_public_key_commitment(&mut self) -> PublicKeyCommitment {
        self.wallet_setup
            .commit_to_public_key()
            .expect("MerchantEstablishing is always in valid state for send_commitment")
    }

    /// Returns the merchant's "partial" public key for the multisig wallet
    pub fn wallet_public_key(&self) -> SharedPublicKey {
        self.wallet_setup.wallet().shared_public_key()
    }

    pub fn set_customer_wallet_public_key(&mut self, key: SharedPublicKey) -> Result<(), EstablishError> {
        if key.role() != ChannelRole::Customer {
            return Err(EstablishError::WrongRole { expected: ChannelRole::Customer, got: key.role() });
        }
        self.wallet_setup.receive_peer_key(key).map_err(|e| EstablishError::MissingInformation(e.to_string()))?;
        self.wallet_setup.complete().map_err(|e| EstablishError::MissingInformation(e.to_string()))?;
        let keyring = MultisigWallet::try_from(self.wallet_setup.wallet().clone())
            .map_err(|e| EstablishError::MissingInformation(e.to_string()))?;
        self.inner.multisig_wallet = Some(keyring);
        Ok(())
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

    /// Prepare the initial commitment transaction for signing.
    ///
    /// Delegates to [`EstablishingState::prepare_initial_transaction`].
    pub async fn prepare_initial_transaction(&mut self) -> Result<(), EstablishError> {
        self.inner.prepare_initial_transaction().await
    }

    /// Returns a copy of the preprocess data for exchange with the peer.
    pub fn preprocess_data(&self) -> Result<Vec<u8>, EstablishError> {
        self.inner.preprepare_data()
    }

    /// Receive peer's preprocess data and complete partial signing.
    ///
    /// Delegates to [`EstablishingState::receive_peer_preprocess_data`].
    pub fn receive_peer_preprocess_data(&mut self, data: Vec<u8>) -> Result<(), EstablishError> {
        self.inner.receive_peer_preprocess_data(data)
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
        // Verify the adapter signature and DLEQ proof
        let msg = self.inner.commitment_message();
        self.inner.verify_initial_offset(&msg)
    }

    /// Returns `true` if both own and peer encrypted offsets are available.
    pub fn has_both_offsets(&self) -> bool {
        self.inner.peer_encrypted_offset.is_some()
    }

    /// Bundle both encrypted offsets, payload signatures, and the ephemeral channel ID
    /// ($\kappa$) for forwarding to the KES in a single message.
    ///
    /// The ephemeral channel ID is generated internally from the merchant's channel nonce
    /// and encrypted to the KES global public key.
    pub fn bundle_for_kes<R: RngCore + CryptoRng>(&self, rng: &mut R) -> Result<KesInitBundle<KC>, EstablishError> {
        let merchant_encrypted_offset = self.inner.encrypted_offset.clone();
        let customer_encrypted_offset = self
            .inner
            .peer_encrypted_offset
            .clone()
            .ok_or_else(|| EstablishError::MissingInformation("Customer encrypted offset (peer)".into()))?;
        let merchant_dleq = &self.inner.dleq_proof;
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
        let merchant_t0 = *merchant_dleq.public_points.foreign_point();
        let customer_t0 = *customer_dleq.public_points.foreign_point();
        // Nonce pubkeys: merchant own = G * nonce, customer = stored from their init package
        let merchant_ephemeral_pubkey = KC::generator() * self.inner.channel_nonce.nonce();
        let customer_ephemeral_pubkey = self
            .inner
            .peer_nonce_pubkey
            .ok_or_else(|| EstablishError::MissingInformation("Customer nonce pubkey (peer)".into()))?;

        let ephemeral_channel_id = self.inner.generate_kes_channel_id(rng)?;

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
            ephemeral_channel_id,
        })
    }

    /// Store a KES proof-of-knowledge received from the KES and verify it.
    pub fn receive_kes_proof(&mut self, proof: KesPoKProofs<KC>) -> Result<(), EstablishError> {
        self.inner.kes_created(proof);
        self.inner.verify_kes_proof()
    }

    /// Stores the details of the funding transaction, passing through to the underlying EstablishingState call.
    pub(crate) fn funding_tx_confirmed(&mut self, tx: TransactionRecord) {
        self.inner.funding_tx_confirmed(tx);
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
    wallet_setup: CustomerSetup<MultisigWalletKeyNegotiation>,
}

impl<SF, KC> CustomerEstablishing<SF, KC>
where
    SF: FrostCurve,
    KC: FrostCurve,
    Ed25519: Dleq<SF> + Dleq<KC>,
{
    /// Wrap an `EstablishingState`, returning an error if the state is not for a customer.
    pub fn new(state: EstablishingState<SF, KC>, rpc_url: impl Into<String>) -> Result<Self, EstablishError> {
        let role = HasRole::role(&state);
        if role != ChannelRole::Customer {
            return Err(EstablishError::WrongRole { expected: ChannelRole::Customer, got: role });
        }
        let network = state.metadata.network();
        let w = MultisigWalletKeyNegotiation::new(
            ChannelRole::Customer,
            network,
            state.wallet_partial_spend_key.clone(),
            rpc_url,
        );
        let wallet_setup = CustomerSetup::new(w).map_err(|e| EstablishError::MissingInformation(e.to_string()))?;
        Ok(Self { inner: state, wallet_setup })
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

    /// Store the merchant's public key commitment.
    pub fn set_merchant_wallet_public_key_commitment(&mut self, commitment: PublicKeyCommitment) {
        self.wallet_setup
            .receive_commitment(commitment)
            .expect("CustomerEstablishing is always in valid state for receive_commitment");
    }

    /// Returns the customer's "partial" public key for the multisig wallet
    pub fn wallet_public_key(&self) -> SharedPublicKey {
        self.wallet_setup.wallet().shared_public_key()
    }

    /// Set the merchant's "partial" public key for the multisig wallet.
    pub fn set_merchant_wallet_public_key(&mut self, key: SharedPublicKey) -> Result<(), EstablishError> {
        if key.role() != ChannelRole::Merchant {
            return Err(EstablishError::WrongRole { expected: ChannelRole::Merchant, got: key.role() });
        }
        self.wallet_setup.receive_peer_key(key)?;
        self.wallet_setup.verify_against_commitment()?;
        let keyring = MultisigWallet::try_from(self.wallet_setup.wallet().clone())
            .map_err(|e| EstablishError::MissingInformation(e.to_string()))?;
        self.inner.multisig_wallet = Some(keyring);
        Ok(())
    }

    /// Generate a [`ChannelInitPackage`] containing the customer's encrypted offset,
    /// adapted signature, and DLEQ proof for the initial channel state.
    pub fn generate_init_package<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Result<ChannelInitPackage<KC>, EstablishError> {
        self.inner.generate_init_package(rng)
    }

    /// Prepare the initial commitment transaction for signing.
    ///
    /// Delegates to [`EstablishingState::prepare_initial_transaction`].
    pub async fn prepare_initial_transaction(&mut self) -> Result<(), EstablishError> {
        self.inner.prepare_initial_transaction().await
    }

    /// Returns a copy of the preprocess data for exchange with the peer.
    pub fn preprocess_data(&self) -> Result<Vec<u8>, EstablishError> {
        self.inner.preprepare_data()
    }

    /// Receive peer's preprocess data and complete partial signing.
    ///
    /// Delegates to [`EstablishingState::receive_peer_preprocess_data`].
    pub fn receive_peer_preprocess_data(&mut self, data: Vec<u8>) -> Result<(), EstablishError> {
        self.inner.receive_peer_preprocess_data(data)
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
        // Verify the adapter signature and DLEQ proof
        let msg = self.inner.commitment_message();
        self.inner.verify_initial_offset(&msg)
    }

    /// Store a KES proof-of-knowledge received from the KES and verify it.
    pub fn receive_kes_proof(&mut self, proof: KesPoKProofs<KC>) -> Result<(), EstablishError> {
        self.inner.kes_created(proof);
        self.inner.verify_kes_proof()
    }

    /// Return a reference to the customer's encrypted offset for the KES (if generated).
    pub fn encrypted_offset_for_kes(&self) -> &EncryptedSecret<KC> {
        &self.inner.encrypted_offset
    }

    /// Stores the details of the funding transaction, passing through to the underlying EstablishingState call.
    pub(crate) fn funding_tx_confirmed(&mut self, tx: TransactionRecord) {
        self.inner.funding_tx_confirmed(tx);
    }
}

// --- LifeCycle implementation ---

use crate::state_machine::lifecycle::{LifeCycle, LifecycleStage};
use crate::state_machine::{CustomerSetup, MerchantSetup, SetupState};
use crate::wallet::multisig_wallet::MultisigWallet;

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

    fn wallet_address(&self) -> Option<String> {
        self.multisig_address()
    }
}
