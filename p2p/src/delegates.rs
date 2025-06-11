use crate::data_objects::TransactionRecord;
use crate::message_types::NewChannelProposal;
use crate::Client;
use libgrease::amount::MoneroAmount;
use libgrease::channel_metadata::ChannelMetadata;
use libgrease::crypto::keys::{Curve25519PublicKey, Curve25519Secret};
use libgrease::kes::PartialEncryptedKey;
use libgrease::monero::data_objects::{MultisigSplitSecrets, TransactionId};
use libgrease::state_machine::error::InvalidProposal;
use log::*;
use std::future::Future;
use std::time::Duration;
use thiserror::Error;
use wallet::watch_only::WatchOnlyWallet;
use wallet::{connect_to_rpc, Rpc};

#[derive(Debug, Error)]
#[error("Delegate error: {0}")]
pub struct DelegateError(pub String);

//---------------------------------   Verify Channel Proposals    ------------------------------------------------------

pub trait ProposalVerifier {
    fn verify_proposal(&self, data: &NewChannelProposal) -> impl Future<Output = Result<(), InvalidProposal>> + Send;
    fn derive_channel_secret(
        &self,
        data: &NewChannelProposal,
    ) -> impl Future<Output = Result<String, DelegateError>> + Send;
}

//--------------------------------------   KES Shared Secret handling    -----------------------------------------------

pub trait VerifiableSecretShare {
    fn split_secret_share(&self, secret: &Curve25519Secret) -> Result<MultisigSplitSecrets, DelegateError>;

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
    ) -> impl Future<Output = ()> + Send;
}

//----------------------------------------   Commitment TX0 ------------------------------------------------------------

/// A curve-agnostic representation of a scalar.
#[derive(Debug, Clone, Default)]
pub struct GenericScalar([u8; 32]);
/// A curve-agnostic representation of a point.
#[derive(Debug, Clone, Default)]
pub struct GenericPoint([u8; 32]);

pub struct Comm0PrivateInputs {
    /// 𝛎_ꞷ0 - Random blinding value
    pub random_blinding: GenericScalar,
    /// Random value
    pub a1: GenericPoint,
    /// 𝛎_1 - Random value
    pub r1: GenericPoint,
    /// 𝛎_2 - Random value
    pub r2: GenericPoint,
    /// 𝛎_DLEQ - Random blinding value for DLEQ proof
    pub blinding_dleq: GenericScalar,
}

/// The outputs of the Commitment0 proofs that must be shared with the peer.
#[allow(non_snake_case)]
#[derive(Debug, Clone, Default)]
pub struct Comm0PublicOutputs {
    /// **Τ₀** - The public key/curve point on Baby Jubjub for ω₀.
    pub T_0: GenericPoint,
    /// **c₁** - Feldman commitment 1 (used in tandem with Feldman commitment 0 = Τ₀), which is a public key/curve point on Baby Jubjub.
    pub c_1: GenericPoint,
    /// **Φ₁** - The ephemeral public key/curve point on Baby Jubjub for message transportation to the peer.
    pub phi_1: GenericPoint,
    /// **χ₁** - The encrypted value of σ₁.
    pub enc_1: GenericScalar,
    /// **Φ₂** - The ephemeral public key/curve point on Baby Jubjub for message transportation to the KES (fi₂).
    pub phi_2: GenericPoint,
    /// **χ₂** - The encrypted value of σ₂ (enc₂).
    pub enc_2: GenericScalar,
    /// **S₀** - The public key/curve point on Ed25519 for ω₀.
    pub S_0: GenericPoint,
    /// **c** - The Fiat–Shamir heuristic challenge (challenge_bytes).
    pub c: GenericScalar,
    /// **ρ_BabyJubjub** - The Fiat–Shamir heuristic challenge response on the Baby Jubjub curve (response_BabyJubJub).
    pub rho_bjj: GenericScalar,
    /// **ρ_Ed25519** - The Fiat–Shamir heuristic challenge response on the Ed25519 curve (response_div_ed25519).
    pub rho_ed: GenericScalar,
}

/// The proof outputs that are stored, but not shared with the peer.
#[derive(Debug, Clone, Default)]
pub struct Comm0PrivateOutputs {
    /// **ω₀** - The root private key protecting access to the user's locked value (witness₀).
    pub omega_0: GenericScalar,
    /// **σ₁** - The split of ω₀ shared with the peer (share₁).
    pub peer_share: GenericScalar,
    /// **σ₂** - The split of ω₀ shared with the KES (share₂).
    pub kes_share: GenericScalar,
    /// **Δ_BabyJubjub** - Optimization parameter (response_div_BabyJubjub).
    pub delta_bjj: GenericScalar,
    /// **Δ_Ed25519** - Optimization parameter (response_div_BabyJubJub).
    pub delta_ed: GenericScalar,
}

#[derive(Default, Debug, Clone)]
pub struct InitialProofsResult {
    pub public_outputs: Comm0PublicOutputs,
    pub private_outputs: Comm0PrivateOutputs,
    pub proofs: Vec<u8>,
}

/// A representation of proof that the merchant has established the KES correctly using the shared secrets and the
/// agreed KES public key.
pub struct KesProofs {
    proof: Vec<u8>,
}

pub trait GreaseInitializer {
    fn generate_initial_proofs(
        &mut self,
        inputs: Comm0PrivateInputs,
        metadata: &ChannelMetadata,
    ) -> impl Future<Output = Result<InitialProofsResult, DelegateError>> + Send;

    fn verify_initial_proofs(
        &self,
        public_outputs: &Comm0PublicOutputs,
        proofs: &[u8],
        metadata: &ChannelMetadata,
    ) -> impl Future<Output = Result<(), DelegateError>> + Send;

    async fn create_kes_proofs(
        customer_key: PartialEncryptedKey,
        merchant_key: PartialEncryptedKey,
        kes_public_key: Curve25519PublicKey,
    ) -> Result<KesProofs, DelegateError>;

    async fn verify_kes_proofs(
        customer_key: PartialEncryptedKey,
        merchant_key: PartialEncryptedKey,
        kes_public_key: Curve25519PublicKey,
        proofs: KesProofs,
    ) -> Result<(), DelegateError>;
}

pub trait GreaseChannelDelegate:
    GreaseInitializer + ProposalVerifier + VerifiableSecretShare + FundChannel + Sync + Send + Clone
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

impl ProposalVerifier for DummyDelegate {
    async fn verify_proposal(&self, data: &NewChannelProposal) -> Result<(), InvalidProposal> {
        info!("DummyDelegate: Verifying proposal. {data:?}");
        Ok(())
    }

    async fn derive_channel_secret(&self, _data: &NewChannelProposal) -> Result<String, DelegateError> {
        Ok("New secret".to_string())
    }
}

impl GreaseInitializer for DummyDelegate {
    async fn generate_initial_proofs(
        &mut self,
        _in: Comm0PrivateInputs,
        metadata: &ChannelMetadata,
    ) -> Result<InitialProofsResult, DelegateError> {
        info!("DummyDelegate: Generating initial proofs for {}", metadata.channel_id().name());
        Ok(InitialProofsResult::default())
    }

    fn verify_initial_proofs(
        &self,
        _outputs: &Comm0PublicOutputs,
        _proof: &[u8],
        metadata: &ChannelMetadata,
    ) -> impl Future<Output = Result<(), DelegateError>> + Send {
        async {
            info!("DummyDelegate: Verifying initial proofs for {}", metadata.channel_id().name());
            Ok(())
        }
    }

    async fn create_kes_proofs(
        _cust_key: PartialEncryptedKey,
        _m_key: PartialEncryptedKey,
        _kes_pubkey: Curve25519PublicKey,
    ) -> Result<KesProofs, DelegateError> {
        Ok(KesProofs { proof: b"KESproof".to_vec() })
    }

    async fn verify_kes_proofs(
        _c_key: PartialEncryptedKey,
        _m_key: PartialEncryptedKey,
        _kes_pubkey: Curve25519PublicKey,
        proofs: KesProofs,
    ) -> Result<(), DelegateError> {
        if proofs.proof == b"KESproof".to_vec() {
            info!("DummyDelegate: KES proofs verified successfully");
            Ok(())
        } else {
            Err(DelegateError("Invalid KES proofs".to_string()))
        }
    }
}

impl VerifiableSecretShare for DummyDelegate {
    fn split_secret_share(&self, _secret: &Curve25519Secret) -> Result<MultisigSplitSecrets, DelegateError> {
        info!("DummyDelegate: Splitting secret share");
        Ok(MultisigSplitSecrets {
            peer_shard: PartialEncryptedKey("peer_shard".to_string()),
            kes_shard: PartialEncryptedKey("kes_shard".to_string()),
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
    ) {
        info!(" Registering transaction watcher for channel {name}");
        let rpc = connect_to_rpc(&self.rpc_address).await.expect("rpc connect error");
        let height = rpc.get_height().await.expect("Failed to get blockchain height") as u64;
        let mut wallet = WatchOnlyWallet::new(rpc, private_view_key, public_spend_key, birthday)
            .expect("Failed to create watch-only wallet");
        info!("Watch-only wallet created with birthday {birthday:?}. Current height is {height}");
        let mut interval = tokio::time::interval(Duration::from_millis(5000));
        let mut client = client.clone();
        let _ = tokio::spawn(async move {
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
            let record = TransactionRecord { channel_name: name, amount, transaction_id: TransactionId { id } };
            info!("Funding transaction found: {:?}", record);
            let _ = client.notify_tx_mined(record).await.map_err(|e| {
                warn!("Failed to notify tx mined block: {:?}", e);
            });
        });
    }
}

impl GreaseChannelDelegate for DummyDelegate {}
