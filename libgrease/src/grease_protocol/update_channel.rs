use crate::amount::MoneroDelta;
use crate::cryptography::adapter_signature::AdaptedSignature;
use crate::cryptography::dleq::Dleq;
use crate::cryptography::secret_encryption::SecretWithRole;
use crate::grease_protocol::adapter_signature::{AdapterSignatureError, AdapterSignatureHandler};
use crate::grease_protocol::error::DleqError;
use crate::payment_channel::HasRole;
use crate::XmrScalar;
use ciphersuite::Ed25519;
use modular_frost::curve::Curve as FrostCurve;
use rand_core::{CryptoRng, RngCore};
use thiserror::Error;

pub struct GreaseUpdate {
    update_count: u64,
    delta: MoneroDelta,
    omega: XmrScalar,
    peer_shard: SecretWithRole<Ed25519>,
    signature: AdaptedSignature<Ed25519>,
}

pub trait UpdateProtocol<C: FrostCurve>: HasRole + AdapterSignatureHandler {
    fn update_count(&self) -> u64;
    fn prepare_next_update<D: Dleq<C>>(
        &mut self,
        update_count: u64,
        delta: MoneroDelta,
    ) -> Result<(), UpdateProtocolError>;
    fn update_prepared(&self, update_count: u64) -> bool;
    fn delta_for_next_update(&self) -> Option<MoneroDelta>;

    fn update<R: RngCore + CryptoRng>(&mut self, update_count: u64, rng: &mut R) -> Result<(), UpdateProtocolError>;
}

#[derive(Debug, Error)]
pub enum UpdateProtocolError {
    #[error("Update {0} has not been prepared.")]
    NotReady(u64),
    #[error("Received invalid data from peer: {0}")]
    InvalidDataFromPeer(String),
    #[error("Witness error: {0}")]
    WitnessError(#[from] DleqError),
    #[error("Could not provide result because the following information is missing: {0}")]
    MissingInformation(String),
    #[error("Adapter signature error: {0}")]
    SignatureError(#[from] AdapterSignatureError),
}
