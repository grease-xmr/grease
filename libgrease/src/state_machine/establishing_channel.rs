use crate::amount::MoneroAmount;
use crate::channel_metadata::ChannelMetadata;
use crate::cryptography::adapter_signature::AdaptedSignature;
use crate::cryptography::dleq::{Dleq, DleqProof};
use crate::cryptography::keys::{Curve25519PublicKey, Curve25519Secret, PublicKeyCommitment};
use crate::cryptography::zk_objects::KesProof;
use crate::grease_protocol::establish_channel::{
    EstablishProtocolCommon, EstablishProtocolCustomer, EstablishProtocolError, EstablishProtocolMerchant, PeerInfo,
};
use crate::grease_protocol::kes::{KesClient, KesClientError, KesSecrets};
use crate::grease_protocol::multisig_wallet::{HasPublicKey, HasSecretKey, LinkedMultisigWallets};
use crate::impls::multisig::MultisigWalletKeyRing;
use crate::monero::data_objects::{TransactionId, TransactionRecord};
use crate::multisig::MultisigWalletData;
use crate::payment_channel::{ChannelRole, HasRole};
use crate::state_machine::error::LifeCycleError;
use crate::state_machine::lifecycle::ChannelState;
use crate::state_machine::new_channel::NewChannelState;
use crate::state_machine::open_channel::EstablishedChannelState;
use blake2::Blake2b512;
use ciphersuite::Ed25519;
use log::*;
use modular_frost::curve::Curve as FrostCurve;
use monero::Network;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::marker::PhantomData;
//------------------------------------   Establishing Channel State  ------------------------------------------------//

/// State for a channel being established.
///
/// This state implements the `EstablishProtocol` traits, providing the cryptographic
/// operations needed during channel establishment including wallet key exchange,
/// KES client setup, and adapter signature verification.
///
/// The generic parameter `SF` specifies the SNARK-friendly curve used for DLEQ proofs and KES
/// operations. Use [`DefaultEstablishingState`] for the standard BabyJubJub curve.
#[derive(Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct EstablishingState<SF = grease_babyjubjub::BabyJubJub>
where
    SF: FrostCurve,
    Ed25519: Dleq<SF>,
{
    pub(crate) metadata: ChannelMetadata,
    pub(crate) multisig_wallet: Option<MultisigWalletData>,
    pub(crate) funding_transaction_ids: HashMap<TransactionId, TransactionRecord>,
    pub(crate) kes_proof: Option<KesProof>,
    /// Data used to watch for the funding transaction. Implementation agnostic.
    #[serde(
        serialize_with = "crate::helpers::option_to_hex",
        deserialize_with = "crate::helpers::option_from_hex",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub(crate) funding_tx_pipe: Option<Vec<u8>>,

    // --- Protocol Context Fields (ephemeral, not serialized) ---
    /// Wallet key ring for the multisig protocol during establishment.
    #[serde(skip)]
    pub(crate) wallet_keyring: Option<MultisigWalletKeyRing>,
    /// KES secrets and DLEQ proof for adapter signature offset (contains secrets, not cloned).
    #[serde(skip)]
    pub(crate) kes_secrets: Option<KesSecrets<SF>>,
    /// Peer's DLEQ proof received during establishment (public data).
    #[serde(skip)]
    pub(crate) peer_dleq_proof: Option<DleqProof<SF, Ed25519>>,
    /// Peer's adapted signature received during establishment (public data).
    #[serde(skip)]
    pub(crate) peer_adapted_sig: Option<AdaptedSignature<Ed25519>>,
    /// Phantom data to hold the curve type parameter.
    #[serde(skip)]
    _curve: PhantomData<SF>,
}

/// Type alias for the default curve type (BabyJubJub).
pub type DefaultEstablishingState = EstablishingState<grease_babyjubjub::BabyJubJub>;

impl<SF> Clone for EstablishingState<SF>
where
    SF: FrostCurve,
    Ed25519: Dleq<SF>,
{
    fn clone(&self) -> Self {
        Self {
            metadata: self.metadata.clone(),
            multisig_wallet: self.multisig_wallet.clone(),
            funding_transaction_ids: self.funding_transaction_ids.clone(),
            kes_proof: self.kes_proof.clone(),
            funding_tx_pipe: self.funding_tx_pipe.clone(),
            wallet_keyring: self.wallet_keyring.clone(),
            kes_secrets: None, // Contains secrets, not cloned
            peer_dleq_proof: self.peer_dleq_proof.clone(),
            peer_adapted_sig: self.peer_adapted_sig.clone(),
            _curve: PhantomData,
        }
    }
}

impl<SF> EstablishingState<SF>
where
    SF: FrostCurve,
    Ed25519: Dleq<SF>,
{
    pub fn to_channel_state(self) -> ChannelState<SF> {
        ChannelState::Establishing(self)
    }

    pub fn requirements_met(&self) -> bool {
        let mut missing = Vec::with_capacity(4);
        if self.multisig_wallet.is_none() {
            missing.push("Multisig wallet")
        }
        if self.kes_proof.is_none() {
            missing.push("KES established")
        }
        if self.kes_secrets.is_none() {
            missing.push("KES client initialized")
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
        let required = self.metadata.balances().total();
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

    pub fn kes_created(&mut self, kes_info: KesProof) {
        let old = self.kes_proof.replace(kes_info);
        if old.is_some() {
            warn!("KES proof was already set and has been replaced.");
        }
    }

    pub fn funding_tx_confirmed(&mut self, transaction: TransactionRecord) {
        debug!("Funding transaction broadcasted");
        self.funding_transaction_ids.insert(transaction.transaction_id.clone(), transaction);
    }

    /// Initialize the protocol context with a wallet key ring for the establishment phase.
    pub fn init_protocol_context<R: RngCore + CryptoRng>(&mut self, rng: &mut R) {
        let role = self.metadata.role();
        let keyring = MultisigWalletKeyRing::random(rng, role);
        self.wallet_keyring = Some(keyring);
    }

    /// Initialize the KES client using the KES public key from metadata.
    /// This is a convenience method that parses the KES public key string from metadata
    /// and calls `initialize_kes_client` from the protocol trait.
    pub fn init_kes_client_from_metadata<R: RngCore + CryptoRng>(&mut self, rng: &mut R) -> Result<(), LifeCycleError>
    where
        SF::G: ciphersuite::group::GroupEncoding<Repr = [u8; 32]>,
    {
        use ciphersuite::group::GroupEncoding;

        let kes_hex = self.metadata.kes_public_key();
        let kes_bytes = hex::decode(kes_hex)
            .map_err(|e| LifeCycleError::InternalError(format!("Failed to decode KES public key hex: {e}")))?;
        let kes_bytes_arr: [u8; 32] = kes_bytes
            .try_into()
            .map_err(|_| LifeCycleError::InternalError("KES public key must be 32 bytes".to_string()))?;
        let kes_pubkey_opt = SF::G::from_bytes(&kes_bytes_arr);
        if kes_pubkey_opt.is_none().into() {
            return Err(LifeCycleError::InternalError("Invalid KES public key bytes".to_string()));
        }
        let kes_pubkey = kes_pubkey_opt.unwrap();

        let kes_secrets = KesSecrets::generate(rng, kes_pubkey, self.metadata.role())
            .map_err(|e| LifeCycleError::InternalError(format!("Failed to initialize KES client: {e}")))?;
        self.kes_secrets = Some(kes_secrets);
        Ok(())
    }

    #[allow(clippy::result_large_err)]
    pub fn next(self) -> Result<EstablishedChannelState, (Self, LifeCycleError)> {
        debug!("Trying to move from Establishing to Established state");
        if !self.requirements_met() {
            debug!("Cannot change from Establishing to Established because all requirements are not met");
            return Err((self, LifeCycleError::InvalidStateTransition));
        }
        debug!("Transitioning to Established wallet state");
        let open_channel = EstablishedChannelState {
            metadata: self.metadata,
            multisig_wallet: self.multisig_wallet.unwrap(),
            funding_transactions: self.funding_transaction_ids,
            kes_proof: self.kes_proof.unwrap(),
            current_update: None,
        };
        Ok(open_channel)
    }
}

// --- Protocol Trait Implementations ---

impl<SF> HasRole for EstablishingState<SF>
where
    SF: FrostCurve,
    Ed25519: Dleq<SF>,
{
    fn role(&self) -> ChannelRole {
        self.metadata.role()
    }
}

impl<SF> HasPublicKey for EstablishingState<SF>
where
    SF: FrostCurve,
    Ed25519: Dleq<SF>,
{
    fn public_key(&self) -> Curve25519PublicKey {
        self.wallet_keyring
            .as_ref()
            .map(|k| k.public_key())
            .expect("Protocol context not initialized. Call init_protocol_context first.")
    }
}

impl<SF> HasSecretKey for EstablishingState<SF>
where
    SF: FrostCurve,
    Ed25519: Dleq<SF>,
{
    fn secret_key(&self) -> Curve25519Secret {
        self.wallet_keyring
            .as_ref()
            .map(|k| k.secret_key())
            .expect("Protocol context not initialized. Call init_protocol_context first.")
    }
}

impl<SF> PeerInfo<SF> for EstablishingState<SF>
where
    SF: FrostCurve,
    Ed25519: Dleq<SF>,
{
    fn peer_dleq_proof(&self) -> Option<&DleqProof<SF, Ed25519>> {
        self.peer_dleq_proof.as_ref()
    }

    fn peer_public_key(&self) -> Option<Curve25519PublicKey> {
        self.wallet_keyring.as_ref().and_then(|k| k.peer_public_key().ok())
    }

    fn peer_adapted_signature(&self) -> Option<&AdaptedSignature<Ed25519>> {
        self.peer_adapted_sig.as_ref()
    }
}

impl<SF> EstablishProtocolCommon<SF, Blake2b512> for EstablishingState<SF>
where
    SF: FrostCurve,
    Ed25519: Dleq<SF>,
{
    type MultisigWallet = MultisigWalletKeyRing;
    type KesClient = KesSecrets<SF>;

    fn new<R: RngCore + CryptoRng>(_rng: &mut R, _role: ChannelRole) -> Self {
        panic!("EstablishingState::new should not be called directly. Use From<NewChannelState> instead.")
    }

    fn initialize_kes_client<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        kes_pubkey: SF::G,
    ) -> Result<(), EstablishProtocolError> {
        let kes_secrets = KesSecrets::generate(rng, kes_pubkey, HasRole::role(self)).map_err(|e| match e {
            KesClientError::InvalidKesPublicKey => EstablishProtocolError::InvalidKesPublicKey,
        })?;
        self.kes_secrets = Some(kes_secrets);
        Ok(())
    }

    fn kes_client(&self) -> Result<&Self::KesClient, EstablishProtocolError> {
        self.kes_secrets.as_ref().ok_or_else(|| {
            EstablishProtocolError::MissingInformation("initialize_kes_client has not been called".into())
        })
    }

    fn wallet(&self) -> &Self::MultisigWallet {
        self.wallet_keyring.as_ref().expect("Protocol context not initialized. Call init_protocol_context first.")
    }

    fn wallet_mut(&mut self) -> &mut Self::MultisigWallet {
        self.wallet_keyring.as_mut().expect("Protocol context not initialized. Call init_protocol_context first.")
    }

    fn set_peer_adapted_signature(&mut self, adapted_signature: AdaptedSignature<Ed25519>) {
        self.peer_adapted_sig = Some(adapted_signature);
    }

    fn set_peer_dleq_proof(&mut self, dleq_proof: DleqProof<SF, Ed25519>) {
        self.peer_dleq_proof = Some(dleq_proof);
    }
}

impl<SF> EstablishProtocolMerchant<SF, Blake2b512> for EstablishingState<SF>
where
    SF: FrostCurve,
    Ed25519: Dleq<SF>,
{
}

impl<SF> EstablishProtocolCustomer<SF, Blake2b512> for EstablishingState<SF>
where
    SF: FrostCurve,
    Ed25519: Dleq<SF>,
{
    fn store_wallet_commitment<R: std::io::Read + ?Sized>(
        &mut self,
        reader: &mut R,
    ) -> Result<(), EstablishProtocolError> {
        use crate::grease_protocol::utils::Readable;
        let commitment =
            PublicKeyCommitment::read(reader).map_err(|e| EstablishProtocolError::InvalidCommitment(e.to_string()))?;
        self.wallet_mut().set_peer_public_key_commitment(commitment);
        Ok(())
    }

    fn verify_merchant_public_key(&self) -> Result<(), EstablishProtocolError> {
        self.wallet().verify_peer_public_key()?;
        Ok(())
    }
}

impl<SF> From<NewChannelState> for EstablishingState<SF>
where
    SF: FrostCurve,
    Ed25519: Dleq<SF>,
{
    fn from(new_channel_state: NewChannelState) -> Self {
        EstablishingState {
            metadata: new_channel_state.metadata,
            multisig_wallet: None,
            funding_transaction_ids: HashMap::new(),
            kes_proof: None,
            funding_tx_pipe: None,
            // Protocol context fields - initialized later via init_protocol_context
            wallet_keyring: None,
            kes_secrets: None,
            peer_dleq_proof: None,
            peer_adapted_sig: None,
            _curve: PhantomData,
        }
    }
}

use crate::state_machine::lifecycle::{LifeCycle, LifecycleStage};

impl<SF> LifeCycle for EstablishingState<SF>
where
    SF: FrostCurve,
    Ed25519: Dleq<SF>,
{
    fn stage(&self) -> LifecycleStage {
        LifecycleStage::Establishing
    }

    fn metadata(&self) -> &ChannelMetadata {
        &self.metadata
    }

    fn wallet_address(&self, network: Network) -> Option<String> {
        self.multisig_address(network)
    }
}
