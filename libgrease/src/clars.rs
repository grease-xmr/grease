//! 2P-CLRAS: Two party Consecutive Linkable Ring Adapter Signature
//!
//! This module implements the 2P-CLRAS signature scheme as described in https://eprint.iacr.org/2022/744.pdf.

use crate::cas::{CasError, ConsecutiveAdaptorSignature, PreSignature, Signature, Witness};
use crate::keys::{PublicKey, SecretKey};
use curve25519_dalek::Scalar;
use thiserror::Error;

pub struct PreSignatureInfo {
    pub nonce: PublicKey,
    pub partial_pre_signature: PreSignature,
}

pub trait Clras2P {
    type Cas: ConsecutiveAdaptorSignature;
    fn joint_generate(&mut self, peer: &PublicKey) -> ((SecretKey, PublicKey), PublicKey);

    /// Provides a hash function to map data to a scalar.
    ///
    /// Implementations should consider domain separation.
    fn hash_to_scalar<B: AsRef<[u8]>>(&self, data: B, nonce: &PublicKey, joint_key: &PublicKey) -> Scalar;

    fn pre_signature<B: AsRef<[u8]>>(
        &mut self,
        info: &PreSignatureInfo,
        peer_info: &PreSignatureInfo,
        message: B,
        statement: <<Self::Cas as ConsecutiveAdaptorSignature>::W as Witness>::S,
    ) -> PreSignature;

    fn pre_signature_verify<B: AsRef<[u8]>>(
        &self,
        pre_signature: &PreSignature,
        message: B,
        statement: <<Self::Cas as ConsecutiveAdaptorSignature>::W as Witness>::S,
    ) -> bool;

    fn verify<B: AsRef<[u8]>>(&self, message: B, signature: &Signature) -> bool;

    fn adapt(
        &self,
        pre_signature: &PreSignature,
        witness: &<Self::Cas as ConsecutiveAdaptorSignature>::W,
        cas: &Self::Cas,
    ) -> Signature {
        cas.adapt_pre_signature(pre_signature, witness)
    }

    fn extract_witness(
        &self,
        pre_signature: &PreSignature,
        signature: &Signature,
        statement: &<<Self::Cas as ConsecutiveAdaptorSignature>::W as Witness>::S,
        cas: &Self::Cas,
    ) -> Result<<Self::Cas as ConsecutiveAdaptorSignature>::W, Clras2PError> {
        let w = cas.extract_witness(signature, pre_signature, statement)?;
        Ok(w)
    }
}

/// Error types for 2P-CLRAS operations
#[derive(Error, Debug)]
pub enum Clras2PError {
    #[error("Adapter signature error: {0}")]
    CasError(#[from] CasError),
    #[error("Invalid key material")]
    KeyError,
}
