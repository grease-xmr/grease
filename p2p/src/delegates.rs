use crate::message_types::NewChannelProposal;
use crate::Client;
use circuits::make_keypair_bjj;
use circuits::make_keypair_ed25519;
use circuits::make_scalar_bjj;
use circuits::make_scalar_ed25519;
use circuits::BBError;
use circuits::ZeroKnowledgeProofUpdate;
use libgrease::amount::{MoneroAmount, MoneroDelta};
use libgrease::channel_metadata::ChannelMetadata;
use libgrease::crypto::keys::{Curve25519PublicKey, Curve25519Secret};
use libgrease::crypto::zk_objects::PartialEncryptedKeyConst;
use libgrease::crypto::zk_objects::{
    AdaptedSignature, Comm0PrivateInputs, Comm0PublicInputs, GenericPoint, GenericScalar, KesProof,
    PartialEncryptedKey, PrivateUpdateOutputs, Proofs0, PublicProof0, PublicUpdateOutputs, PublicUpdateProof,
    UpdateProofs,
};
use libgrease::monero::data_objects::{MultisigSplitSecrets, TransactionId, TransactionRecord};
use libgrease::state_machine::error::InvalidProposal;
use log::*;
use num_bigint::BigUint;
use std::future::Future;
use std::path::Path;
use std::time::Duration;
use thiserror::Error;
use wallet::watch_only::WatchOnlyWallet;
use wallet::{connect_to_rpc, Rpc};

#[derive(Error, Debug)]
pub enum DelegateError {
    #[error("An error occurred while zkSNARK processing. {0}")]
    BBError(#[from] BBError),
    #[error("An error occurred. {0}")]
    String(String),
    #[error("NIZK DLEQ failed to verify")]
    DLEQVerify,
    #[error("Prover failed to verify its own proof")]
    SelfVerify,
    #[error("Failed to verify peer proof")]
    Verify,
}

impl From<&str> for DelegateError {
    fn from(s: &str) -> Self {
        DelegateError::String(s.to_string())
    }
}

impl From<String> for DelegateError {
    fn from(value: String) -> Self {
        DelegateError::String(value)
    }
}

//---------------------------------   Verify Channel Proposals    ------------------------------------------------------

pub trait ProposalVerifier {
    fn verify_proposal(&self, data: &NewChannelProposal) -> impl Future<Output = Result<(), InvalidProposal>> + Send;
}

//--------------------------------------   KES Shared Secret handling    -----------------------------------------------

pub trait VerifiableSecretShare {
    fn split_secret_share(
        &self,
        secret: &Curve25519Secret,
        kes_public_key: &GenericPoint,
        public_key_peer: &Curve25519PublicKey,
    ) -> Result<MultisigSplitSecrets, DelegateError>;

    /// Verifies the secret share.
    fn verify_my_shards(
        &self,
        secret_share: &Curve25519Secret,
        shards: &MultisigSplitSecrets,
    ) -> Result<(), DelegateError>;
}

//--------------------------------------  Funding Transaction handling   -----------------------------------------------

pub trait FundChannel {
    /// Register a callback to be called when the funding transaction is mined on the blockchain. When a funding
    /// transaction is detected, call `client.notify_tx_mined(tx_id)` to notify the client.
    /// TODO: pass just the method (or equivalent) instead of the whole client
    fn register_watcher(
        &self,
        name: String,
        client: Client,
        private_view_key: Curve25519Secret,
        public_spend_key: Curve25519PublicKey,
        birthday: Option<u64>,
        poll_interval: Duration,
    ) -> impl Future<Output = Result<(), DelegateError>> + Send;
}

//------------------------------   Witness0 generation and verification  -----------------------------------------------

pub trait GreaseInitializer {
    fn generate_initial_proofs(
        &self,
        input_public: &Comm0PublicInputs,
        input_private: &Comm0PrivateInputs,
        metadata: &ChannelMetadata,
        nargo_path: &Path,
    ) -> impl Future<Output = Result<Proofs0, DelegateError>> + Send;

    fn verify_initial_proofs(
        &self,
        nonce_peer: &BigUint,
        public_key_bjj_peer: &babyjubjub_rs::Point,
        kes_public_key: &babyjubjub_rs::Point,
        proof: &PublicProof0,
        metadata: &ChannelMetadata,
    ) -> impl Future<Output = Result<(), DelegateError>> + Send;
}

//----------------------------------------   Commitment TX0 ------------------------------------------------------------

/// Co-ordinate with the L2 to produce a signature from the KES that it has been set up correctly.
pub trait KesProver {
    fn create_kes_proofs(
        &self,
        channel_name: String,
        customer_key: PartialEncryptedKey,
        merchant_key: PartialEncryptedKey,
        kes_public_key: GenericPoint,
    ) -> impl Future<Output = Result<KesProof, DelegateError>> + Send;

    fn verify_kes_proofs(
        &self,
        channel_name: String,
        customer_key: PartialEncryptedKey,
        merchant_key: PartialEncryptedKey,
        kes_public_key: &GenericPoint,
        proofs: KesProof,
    ) -> impl Future<Output = Result<(), DelegateError>> + Send;
}

pub trait Updater {
    fn generate_update(
        &self,
        index: u64,
        delta: MoneroDelta,
        last_witness: &GenericScalar,
        blinding_dleq: &GenericScalar,
        metadata: &ChannelMetadata,
        nargo_path: &Path,
    ) -> impl Future<Output = Result<UpdateProofs, DelegateError>> + Send;

    fn verify_update(
        &self,
        index: u64,
        delta: MoneroDelta,
        proof: &PublicUpdateProof,
        metadata: &ChannelMetadata,
    ) -> impl Future<Output = Result<(), DelegateError>> + Send;

    fn verify_adapted_signature(
        &self,
        update_count: u64,
        peer_proof: &PublicUpdateProof,
        adapted_sig: &AdaptedSignature,
    ) -> impl Future<Output = Result<(), DelegateError>> + Send;
}

//------------------------------              Channel closing            -----------------------------------------------

pub trait ChannelClosure {
    /// Verifies that the witness (ω_i) shared by the peer is valid for the given commitment, T_i.
    fn verify_peer_witness(
        &self,
        witness_i: &GenericScalar,
        commitment: &GenericPoint,
        metadata: &ChannelMetadata,
    ) -> impl Future<Output = Result<(), DelegateError>> + Send;
}
//--------------------       Convenience all-inclusive delegate trait     ----------------------------------------------

pub trait GreaseChannelDelegate:
    Sync
    + Send
    + Clone
    + GreaseInitializer
    + Updater
    + ChannelClosure
    + ProposalVerifier
    + VerifiableSecretShare
    + FundChannel
    + KesProver
{
}

//----------------------------------------   Dummy Delegate ------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct DummyDelegate {
    pub rpc_address: String,
}

impl Default for DummyDelegate {
    fn default() -> Self {
        Self { rpc_address: "http://localhost:25070".to_string() }
    }
}

impl DummyDelegate {
    pub fn new(rpc_address: String) -> Self {
        Self { rpc_address }
    }
}

impl ProposalVerifier for DummyDelegate {
    async fn verify_proposal(&self, data: &NewChannelProposal) -> Result<(), InvalidProposal> {
        info!("DummyDelegate: Verifying proposal. {data:?}");
        Ok(())
    }
}

impl GreaseInitializer for DummyDelegate {
    async fn generate_initial_proofs(
        &self,
        _input_public: &Comm0PublicInputs,
        _input_private: &Comm0PrivateInputs,
        metadata: &ChannelMetadata,
        _nargo_path: &Path,
    ) -> Result<Proofs0, DelegateError> {
        info!("DummyDelegate: Generating initial proofs for {}", metadata.channel_id().name());

        Ok(Proofs0::default())
    }

    async fn verify_initial_proofs(
        &self,
        _nonce_peer: &BigUint,
        _public_key_bjj_peer: &babyjubjub_rs::Point,
        _kes_public_key: &babyjubjub_rs::Point,
        _proof: &PublicProof0,
        metadata: &ChannelMetadata,
    ) -> Result<(), DelegateError> {
        info!("DummyDelegate: Verifying initial proofs for {}", metadata.channel_id().name());

        Ok(())
    }
}

impl KesProver for DummyDelegate {
    async fn create_kes_proofs(
        &self,
        channel_name: String,
        _cust_key: PartialEncryptedKey,
        _m_key: PartialEncryptedKey,
        _kes_public_key: GenericPoint,
    ) -> Result<KesProof, DelegateError> {
        info!("DummyDelegate: Creating KES proofs for channel {channel_name}");
        Ok(KesProof { proof: format!("KesProof|{channel_name}").into_bytes() })
    }

    async fn verify_kes_proofs(
        &self,
        channel_name: String,
        _c_key: PartialEncryptedKey,
        _m_key: PartialEncryptedKey,
        _kes_public_key: &GenericPoint,
        proofs: KesProof,
    ) -> Result<(), DelegateError> {
        if proofs.proof == format!("KesProof|{channel_name}").into_bytes() {
            info!("DummyDelegate: KES proofs verified successfully");
            Ok(())
        } else {
            Err(DelegateError::String("Invalid KES proofs".to_string()))
        }
    }
}

impl VerifiableSecretShare for DummyDelegate {
    fn split_secret_share(
        &self,
        _secret: &Curve25519Secret,
        _kes: &GenericPoint,
        _peer: &Curve25519PublicKey,
    ) -> Result<MultisigSplitSecrets, DelegateError> {
        info!("DummyDelegate: Splitting secret share");
        //TODO: Confirm that this always the customer.
        Ok(MultisigSplitSecrets {
            peer_shard: PartialEncryptedKey(PartialEncryptedKeyConst::CustomerShard),
            kes_shard: PartialEncryptedKey(PartialEncryptedKeyConst::KesShardFromCustomer),
            t_0: GenericPoint::default(),
            c_1: GenericPoint::default(),
        })
    }

    fn verify_my_shards(&self, _share: &Curve25519Secret, _shards: &MultisigSplitSecrets) -> Result<(), DelegateError> {
        info!("DummyDelegate: Verifying secret share");
        Ok(())
    }
}

impl FundChannel for DummyDelegate {
    async fn register_watcher(
        &self,
        name: String,
        client: Client,
        private_view_key: Curve25519Secret,
        public_spend_key: Curve25519PublicKey,
        birthday: Option<u64>,
        poll_interval: Duration,
    ) -> Result<(), DelegateError> {
        info!(
            "Registering transaction watcher for channel {name} at address: {}",
            self.rpc_address
        );
        let rpc = connect_to_rpc(&self.rpc_address).await.map_err(|e| DelegateError::String(e.to_string()))?;
        let height = rpc.get_height().await.map_err(|e| DelegateError::String(e.to_string()))? as u64;
        let mut wallet = WatchOnlyWallet::new(rpc, private_view_key, public_spend_key, birthday)
            .map_err(|e| DelegateError::String(e.to_string()))?;
        info!("Watch-only wallet created with birthday {birthday:?}. Current height is {height}");
        let mut interval = tokio::time::interval(poll_interval);
        let mut client = client.clone();
        let _handle = tokio::spawn(async move {
            let mut start_height = birthday.map(|b| height.min(b)).unwrap_or(height);
            loop {
                interval.tick().await;
                let current_height = wallet.get_height().await.expect("Failed to get blockchain height");
                debug!("Scanning for funding transaction in block range {start_height}..<{current_height}");
                if let Ok(c) = wallet.scan(Some(start_height - 5), Some(current_height)).await {
                    if c > 0 {
                        break;
                    }
                    start_height = current_height;
                }
            }
            let output = wallet.outputs().first().expect("No outputs").clone();
            let amount = MoneroAmount::from(output.commitment().amount);
            let id = hex::encode(output.transaction());
            let serialized = output.serialize();
            let record =
                TransactionRecord { channel_name: name, amount, transaction_id: TransactionId { id }, serialized };
            info!("Funding transaction found: {:?}", record);
            let _ = client.notify_tx_mined(record).await.map_err(|e| {
                warn!("Failed to notify tx mined block: {:?}", e);
            });
        });
        Ok(())
    }
}

impl Updater for DummyDelegate {
    async fn generate_update(
        &self,
        index: u64,
        delta: MoneroDelta,
        _witness: &GenericScalar,
        _blinding_dleq: &GenericScalar,
        _metadata: &ChannelMetadata,
        _nargo_path: &Path,
    ) -> Result<UpdateProofs, DelegateError> {
        info!("DummyDelegate: Generating update {index} proof for channel.  {}", delta.amount);
        let mut rng = rand::rng();
        // The witnesses need to be valid scalars
        let next_witness = Curve25519Secret::random(&mut rng);
        let witness_i = GenericScalar(next_witness.as_scalar().to_bytes());
        let (_, t_prev) = make_keypair_bjj(&mut rng);
        let (_, t_current) = make_keypair_bjj(&mut rng);
        let (_, s_current) = make_keypair_ed25519(&mut rng);
        let (_, r_bjj) = make_keypair_bjj(&mut rng);
        let (_, r_ed) = make_keypair_ed25519(&mut rng);
        let public_outputs = PublicUpdateOutputs {
            T_prev: t_prev.into(),
            T_current: t_current.into(),
            S_current: s_current.into(),
            challenge: GenericScalar::random256(&mut rng),
            rho_bjj: make_scalar_bjj(&mut rng).into(),
            rho_ed: make_scalar_ed25519(&mut rng).into(),
            R_bjj: r_bjj.into(),
            R_ed: r_ed.into(),
        };
        let private_outputs = PrivateUpdateOutputs {
            update_count: index,
            witness_i,
            delta_bjj: make_scalar_bjj(&mut rng).into(),
            delta_ed: make_scalar_ed25519(&mut rng).into(),
        };
        let zero_knowledge_proof_update = ZeroKnowledgeProofUpdate::default();
        Ok(UpdateProofs { private_outputs, public_outputs, zero_knowledge_proof_update })
    }

    async fn verify_update(
        &self,
        index: u64,
        delta: MoneroDelta,
        proof: &PublicUpdateProof,
        metadata: &ChannelMetadata,
    ) -> Result<(), DelegateError> {
        info!("Verifying update {index} proof for {} picoXMR", delta.amount);
        let expected = ZeroKnowledgeProofUpdate::default();
        if proof.zero_knowledge_proof_update == expected {
            info!(
                "Update proof verified successfully for channel {}",
                metadata.channel_id().name()
            );
            Ok(())
        } else {
            Err(DelegateError::String("Invalid update proof".to_string()))
        }
    }

    async fn verify_adapted_signature(
        &self,
        _index: u64,
        _proof: &PublicUpdateProof,
        _sig: &AdaptedSignature,
    ) -> Result<(), DelegateError> {
        info!("Dummy delegate: Verifying adapted signature");
        Ok(())
    }
}

impl ChannelClosure for DummyDelegate {
    async fn verify_peer_witness(
        &self,
        _w: &GenericScalar,
        _c: &GenericPoint,
        metadata: &ChannelMetadata,
    ) -> Result<(), DelegateError> {
        info!(
            "DummyDelegate: Verifying peer witness for channel {} is correct.",
            metadata.channel_id().name()
        );
        Ok(())
    }
}

impl GreaseChannelDelegate for DummyDelegate {}
