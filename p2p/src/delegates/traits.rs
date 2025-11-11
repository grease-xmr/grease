//---------------------------------   Verify Channel Proposals    ------------------------------------------------------

use crate::delegates::error::DelegateError;
use crate::message_types::NewChannelProposal;
use crate::Client;
use libgrease::amount::MoneroDelta;
use libgrease::channel_metadata::ChannelMetadata;
use libgrease::cryptography::keys::{Curve25519PublicKey, Curve25519Secret};
use libgrease::cryptography::zk_objects::{
    Comm0PrivateInputs, GenericPoint, GenericScalar, KesProof, PartialEncryptedKey, Proofs0, PublicProof0,
    PublicUpdateProof, UpdateProofs,
};
use libgrease::monero::data_objects::MultisigSplitSecrets;
use libgrease::state_machine::error::InvalidProposal;
use std::future::Future;
use std::time::Duration;

pub trait ProposalVerifier {
    fn verify_proposal(&self, data: &NewChannelProposal) -> impl Future<Output = Result<(), InvalidProposal>> + Send;
}

//--------------------------------------   KES Shared Secret handling    -----------------------------------------------

pub trait VerifiableSecretShare {
    fn split_secret_share(
        &self,
        secret: &Curve25519Secret,
        kes_pubkey: &GenericPoint,
        peer_pubkey: &Curve25519PublicKey,
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
        inputs: Comm0PrivateInputs,
        metadata: &ChannelMetadata,
    ) -> impl Future<Output = Result<Proofs0, DelegateError>> + Send;

    fn verify_initial_proofs(
        &self,
        proof: &PublicProof0,
        metadata: &ChannelMetadata,
    ) -> impl Future<Output = Result<(), DelegateError>> + Send;
}

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
        kes_public_key: GenericPoint,
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
    ) -> impl Future<Output = Result<UpdateProofs, DelegateError>> + Send;

    fn verify_update(
        &self,
        index: u64,
        delta: MoneroDelta,
        proof: &PublicUpdateProof,
        metadata: &ChannelMetadata,
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
