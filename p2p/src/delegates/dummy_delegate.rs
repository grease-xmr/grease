//----------------------------------------   Dummy Delegate ------------------------------------------------------------

use crate::delegates::error::DelegateError;
use crate::delegates::traits::{
    ChannelClosure, GreaseChannelDelegate, GreaseInitializer, KesProver, ProposalVerifier, Updater,
    VerifiableSecretShare,
};
use crate::grease::NewChannelMessage;
use libgrease::amount::MoneroDelta;
use libgrease::channel_metadata::StaticChannelMetadata;
use libgrease::cryptography::keys::{Curve25519PublicKey, Curve25519Secret};
use libgrease::cryptography::zk_objects::{
    Comm0PrivateInputs, GenericPoint, KesProof, PartialEncryptedKey, Proofs0, PublicProof0, PublicUpdateProof,
    UpdateProofs,
};
use libgrease::monero::data_objects::MultisigSplitSecrets;
use libgrease::state_machine::error::InvalidProposal;
use libgrease::XmrScalar;
use log::*;

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
    async fn verify_proposal(&self, data: &NewChannelMessage) -> Result<(), InvalidProposal> {
        info!("DummyDelegate: Verifying proposal. {data:?}");
        Ok(())
    }
}

impl GreaseInitializer for DummyDelegate {
    async fn generate_initial_proofs(
        &self,
        _in: Comm0PrivateInputs,
        metadata: &StaticChannelMetadata,
    ) -> Result<Proofs0, DelegateError> {
        info!("DummyDelegate: Generating initial proofs for {}", metadata.channel_id().name());
        Ok(Proofs0 { public_outputs: 0, private_outputs: 0, proofs: vec![] })
    }

    async fn verify_initial_proofs(
        &self,
        _proof: &PublicProof0,
        metadata: &StaticChannelMetadata,
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
        _kes_pubkey: GenericPoint,
    ) -> Result<KesProof, DelegateError> {
        info!("DummyDelegate: Creating KES proofs for channel {channel_name}");
        Ok(KesProof { proof: format!("KesProof|{channel_name}").into_bytes() })
    }

    async fn verify_kes_proofs(
        &self,
        channel_name: String,
        _c_key: PartialEncryptedKey,
        _m_key: PartialEncryptedKey,
        _kes_pubkey: GenericPoint,
        proofs: KesProof,
    ) -> Result<(), DelegateError> {
        if proofs.proof == format!("KesProof|{channel_name}").into_bytes() {
            info!("DummyDelegate: KES proofs verified successfully");
            Ok(())
        } else {
            Err(DelegateError("Invalid KES proofs".to_string()))
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

impl Updater for DummyDelegate {
    async fn generate_update(
        &self,
        index: u64,
        delta: MoneroDelta,
        _witness: &XmrScalar,
        metadata: &StaticChannelMetadata,
    ) -> Result<UpdateProofs, DelegateError> {
        info!("DummyDelegate: Generating update {index} proof for channel.  {}", delta.amount);
        let proof = format!("UpdateProof|{}|{index}|{}", metadata.channel_id().name(), delta.amount).into_bytes();
        Ok(UpdateProofs { public_outputs: index, private_outputs: index, proof })
    }

    async fn verify_update(
        &self,
        index: u64,
        delta: MoneroDelta,
        proof: &PublicUpdateProof,
        metadata: &StaticChannelMetadata,
    ) -> Result<(), DelegateError> {
        info!("Verifying update {index} proof for {} picoXMR", delta.amount);
        let expected = format!("UpdateProof|{}|{index}|{}", metadata.channel_id().name(), delta.amount);
        if proof.proof == expected.as_bytes() {
            info!(
                "Update proof verified successfully for channel {}",
                metadata.channel_id().name()
            );
            Ok(())
        } else {
            Err(DelegateError("Invalid update proof".to_string()))
        }
    }
}

impl ChannelClosure for DummyDelegate {
    async fn verify_peer_witness(
        &self,
        _w: &XmrScalar,
        _c: &GenericPoint,
        metadata: &StaticChannelMetadata,
    ) -> Result<(), DelegateError> {
        info!(
            "DummyDelegate: Verifying peer witness for channel {} is correct.",
            metadata.channel_id().name()
        );
        Ok(())
    }
}

impl GreaseChannelDelegate for DummyDelegate {}
