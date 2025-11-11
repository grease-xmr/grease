use crate::grease_protocol::adapter_signature::{AdapterSignatureError, AdapterSignatureHandler};
use crate::grease_protocol::error::DleqError;
use crate::payment_channel::HasRole;
use modular_frost::curve::Curve as FrostCurve;
use rand_core::{CryptoRng, RngCore};
use thiserror::Error;
use crate::cryptography::vcof::VerifiableConsecutiveOnewayFunction;

pub trait UpdateProtocol<C: FrostCurve>: HasRole + AdapterSignatureHandler {
    type VCOF: VerifiableConsecutiveOnewayFunction<C>;

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
