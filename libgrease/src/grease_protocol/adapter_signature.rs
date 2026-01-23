use crate::cryptography::adapter_signature::AdaptedSignature;
use crate::cryptography::keys::Curve25519Secret;
use crate::payment_channel::HasRole;
use crate::XmrScalar;
use ciphersuite::Ed25519;
use rand_core::{CryptoRng, RngCore};
use thiserror::Error;

pub trait AdapterSignatureHandler: HasRole {
    /// Assign the initial adapter signature offset.
    fn initialize_signature_offset(&mut self);

    /// Update the adapter signature offset.
    ///
    /// Implementations that need to store the offset should clone it and then
    /// call `zeroize()` on their copy when it's no longer needed.
    fn update_signature_offset(&mut self, offset: &XmrScalar);

    /// Return the current adapter signature offset.
    fn adapter_signature_offset(&self) -> &XmrScalar;

    /// Return the message to be signed for the `update_count`-th adapter signature.
    fn adapter_signature_message(&self, _update_count: u64) -> String {
        todo!("Implement adapter signature message generation")
    }

    /// Generate a new adapter signature using the current secret key and offset.
    fn new_adapter_signature<R: RngCore + CryptoRng>(
        &self,
        secret_key: &Curve25519Secret,
        update_count: u64,
        rng: &mut R,
    ) -> Result<AdaptedSignature<Ed25519>, AdapterSignatureError> {
        let offset = self.adapter_signature_offset();
        let signature = AdaptedSignature::<Ed25519>::sign(
            secret_key.as_scalar(),
            offset,
            self.adapter_signature_message(update_count),
            rng,
        );
        Ok(signature)
    }
}

#[derive(Debug, Error)]
pub enum AdapterSignatureError {
    #[error("Could not provide result because the following information is missing: {0}")]
    MissingInformation(String),
}
