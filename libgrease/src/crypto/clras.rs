//! 2P-CLRAS: Two party Consecutive Linkable Ring Adapter Signature
//!
//! This module implements the 2P-CLRAS signature scheme as described in https://eprint.iacr.org/2022/744.pdf.

use crate::crypto::cas::{CasError, ConsecutiveAdaptorSignature, PreSignature, Signature, Statement, Witness};
use crate::crypto::keys::{Curve25519PublicKey, Curve25519Secret};
use curve25519_dalek::Scalar;
use thiserror::Error;

pub trait Clras2P {
    type Cas: ConsecutiveAdaptorSignature;

    /// Provides a hash function to map data to a scalar.
    ///
    /// Implementations should consider domain separation.
    fn hash_to_scalar<B: AsRef<[u8]>>(
        &self,
        data: B,
        nonce: &Curve25519PublicKey,
        ring: &[Curve25519PublicKey],
    ) -> Scalar;

    /// Generates a challenge for the signature scheme, given a message, nonce, and ring.
    fn generate_challenge<B: AsRef<[u8]>>(
        &self,
        message: B,
        nonce: &Curve25519PublicKey,
        ring: &[Curve25519PublicKey],
    ) -> Scalar {
        self.hash_to_scalar(message, nonce, ring)
    }

    /// Generates this party's public nonce for the challenge of the signature scheme, given a secret nonce and a ring
    /// of public
    /// keys.
    fn generate_public_nonce(
        &self,
        secret_nonce: &Curve25519Secret,
        ring: &[Curve25519PublicKey],
    ) -> Curve25519PublicKey;

    /// Combined both peers' public nonces and the statement to create a combined public nonce.
    fn calculate_combined_public_nonce(
        &self,
        public_nonce: &Curve25519PublicKey,
        peer_public_nonce: &Curve25519PublicKey,
        statement: &<<Self::Cas as ConsecutiveAdaptorSignature>::W as Witness>::S,
    ) -> Curve25519PublicKey {
        let combined = public_nonce.as_point() + peer_public_nonce.as_point() + statement.as_public_key().as_point();
        Curve25519PublicKey::from(combined)
    }

    /// Sign the adapter signature with the local secret key to create a partial pre/adapter signature.
    fn pre_partial_sign(&self, secret_nonce: &Scalar, challenge: &Scalar, ring: &[Curve25519PublicKey]) -> Signature;

    /// Combine two partial pre-signatures into a full signature. This method also checks that the two partial
    /// pre-signatures are valid and have the same challenge.
    fn combine_partial_pre_signatures<B: AsRef<[u8]>>(
        &self,
        pre_signature: &PreSignature,
        peer_pre_signature: &PreSignature,
        message: B,
        statement: &<<Self::Cas as ConsecutiveAdaptorSignature>::W as Witness>::S,
        ring: &[Curve25519PublicKey],
    ) -> Result<Signature, Clras2PError> {
        if pre_signature.challenge != peer_pre_signature.challenge {
            return Err(Clras2PError::invalid_pre_signature("The signature challenges do not match"));
        }
        if !self.pre_signature_verify(pre_signature, &message, statement, ring) {
            return Err(Clras2PError::invalid_pre_signature("The local pre-signature is invalid"));
        }
        if !self.pre_signature_verify(peer_pre_signature, &message, statement, ring) {
            return Err(Clras2PError::invalid_pre_signature("The peer pre-signature is invalid"));
        }
        let s = pre_signature.s + peer_pre_signature.s;
        Ok(Signature { challenge: pre_signature.challenge, s })
    }

    fn pre_signature_verify<B: AsRef<[u8]>>(
        &self,
        pre_signature: &PreSignature,
        message: B,
        statement: &<<Self::Cas as ConsecutiveAdaptorSignature>::W as Witness>::S,
        ring: &[Curve25519PublicKey],
    ) -> bool;

    /// Verify the full ring signature, signed by the joint secret key.
    fn verify<B: AsRef<[u8]>>(&self, signature: &Signature, message: B, ring: &[Curve25519PublicKey]) -> bool;

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
    #[error("A pre-signature is invalid. {0}")]
    InvalidPreSignature(String),
}

impl Clras2PError {
    pub fn invalid_pre_signature(reason: &str) -> Self {
        Clras2PError::InvalidPreSignature(reason.to_string())
    }
}
