//! # Consecutive Adaptor Signature (CAS)
//!
//! ## Overview
//! Consecutive Adaptor Signature (CAS) extends standard adaptor signatures by enabling a *sequence* of linked
//! pre-signatures. It allows a signer to generate multiple conditional signatures ("pre-signatures") tied to a chain of
//! secrets. Revealing one secret automatically enables adaptation of all subsequent signatures in the chain, creating a
//! verifiable sequence of authorized actions.
//!
//! ## Key Components
//!
//! ### Verifiable Consecutive One-way Function (VCOF)
//!
//! Generates a chain of statement-witness pairs \((Y_0, y_0), (Y_1, y_1), \dots\) where:
//! - Each \((Y_{i+1}, y_{i+1})\) is derived from \((Y_i, y_i)\).
//! - Publicly verifiable: Anyone can confirm the link between consecutive pairs.
//! - One-way: Easy to compute forward, but hard to reverse (derive \(y_i\) from \(Y_{i+1}\)).
//!
//! ### Adaptor Signatures
//! A cryptographic primitive where a pre-signature \(\hat{\sigma}\) is bound to a secret \(y\). Knowledge of \(y\)
//! converts \(\hat{\sigma}\) into a valid signature \(\sigma\).
//!
//! ## CAS Construction
//! CAS combines VCOF with adaptor signatures to create a sequence of interdependent pre-signatures. The workflow
//! includes:
//!
//! ### Setup
//! - Generate initial statement-witness pair \((Y_0, y_0)\) using VCOF.
//!
//! ### Pre-Signature Generation
//! For message \(m_i\) at step \(i\):
//! - Use VCOF to compute \((Y_i, y_i)\) from \((Y_{i-1}, y_{i-1})\).
//! - Create adaptor signature \(\hat{\sigma}_i\) tied to \(Y_i\).
//!
//! ### Verification
//! - Confirm \(\hat{\sigma}_i\) is valid for \(m_i\) under the statement \(Y_i\).
//!
//! ### Adaptation
//! - Release \(y_i\) to convert \(\hat{\sigma}_i\) into a full signature \(\sigma_i\).
//! - \(y_i\) also enables adaptation of all subsequent pre-signatures
//!   \(\hat{\sigma}_{i+1}, \hat{\sigma}_{i+2}, \dots\).
//!
//! ## Properties
//! - **Sequential Dependence**: Each pre-signature \(\hat{\sigma}_i\) depends on its predecessor \
//! (\hat{\sigma}_{i-1}\).
//! - **Forward Security**: Compromising \(y_i\) does not expose earlier secrets \(y_0, \dots, y_{i-1}\).
//! - **Batch Verification**: Multiple pre-signatures can be verified efficiently using VCOF proofs.

use crate::keys::{PublicKey, SecretKey};
use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::Scalar;
use thiserror::Error;

pub trait Statement {
    fn as_public_key(&self) -> &PublicKey;
    fn from_public_key(key: PublicKey) -> Self;
}

pub trait Witness {
    type S: Statement;
    fn generate_statement(&self) -> Self::S;
    fn as_scalar(&self) -> &Scalar;
    fn from_scalar(scalar: Scalar) -> Self;
}

pub struct Signature {
    pub s: Scalar,
    pub challenge: Scalar,
}

pub struct PreSignature {
    pub s: Scalar,
    pub challenge: Scalar,
    pub public_key: PublicKey,
}

pub struct StatementWitnessPair<SW: VCOF + ?Sized> {
    pub witness: <SW as VCOF>::W,
    pub statement: <<SW as VCOF>::W as Witness>::S,
}

pub struct StatementWitnessProof<SW: VCOF + ?Sized> {
    pub pair: StatementWitnessPair<SW>,
    pub proof: <SW as VCOF>::Proof,
}

/// # Verifiable Consecutive One-Way Function (VCOF)
///
/// The **Verifiable Consecutive One-Way Function (VCOF)** is a cryptographic primitive with the following properties:
///
/// 1. **Consecutive Generation**
///    - Generates a new statement-witness pair \((Y_{i+1}, y_{i+1})\) from a previous ("ancestor")
///      pair \((Y_i, y_i)\).
///    - Ensures a strict sequential chain of pairs.
///
/// 2. **Public Verifiability**
///    - The generation of new pairs can be publicly verified, ensuring transparency and auditability.
///
/// 3. **One-Wayness**
///    - Efficient to compute new pairs **forward** (from ancestor to successor).
///    - Computationally hard to invert: deriving ancestor pairs \((Y_i, y_i)\) from successor pairs
///       \((Y_{i+1}, y_{i+1})\) is infeasible.
///
/// 4. **Stateful System Applications**
///    - Ideal for protocols requiring sequential state updates (e.g., bidirectional payment channels).
///    - Enables secure state revocation: reallocating resources (e.g., channel balances) invalidates prior states.
///    - Suitable for schemes demanding ordered interactions and updates.
pub trait VCOF {
    type W: Witness;
    type Proof;

    /// Generate a new random statement and witness pair.
    fn generate(&self) -> (Self::W, <Self::W as Witness>::S);

    /// Generate a new statement-witness pair and proof from the preceding statement-witness pair.
    fn next_statement_witness(
        &self,
        witness: &Self::W,
        statement: &<Self::W as Witness>::S,
    ) -> Result<StatementWitnessProof<Self>, CasError>;

    /// Verify that the `current` statement follows consecutively from the `prev` statement using the supplied proof.
    fn verify_consecutive(
        &self,
        prev: &<Self::W as Witness>::S,
        current: &<Self::W as Witness>::S,
        proof: &Self::Proof,
    ) -> bool;
}

/// Consecutive Adaptor Signature (CAS) implementation
/// Based on Algorithm 1 from "MoNet: A Fast Payment Channel Network for Monero"
/// Core CAS trait defining cryptographic operations
pub trait ConsecutiveAdaptorSignature {
    type W: Witness;

    /// Generates a new random key pair
    fn generate_keypair(&mut self) -> (SecretKey, PublicKey);

    fn hash_to_scalar<B: AsRef<[u8]>>(&self, message: B, nonce: &PublicKey, public_key: &PublicKey) -> Scalar;

    /// Create pre-signature (adapter signature) for message using a secret key and statement
    ///
    /// The default implementation produces a Schnorr signature for the message.
    ///
    /// If `pubkey` is `None`, the public key is derived from the secret key. If `pubkey` is provided, it *must* be
    /// `sk.G` or else the signature will be invalid. This is not checked in the default implementation.
    fn pre_sign<B: AsRef<[u8]>>(
        &mut self,
        sk: &SecretKey,
        pubkey: Option<&PublicKey>,
        message: B,
        statement: &<Self::W as Witness>::S,
    ) -> Result<(SecretKey, PreSignature), CasError> {
        let (r, pub_r) = self.generate_keypair();
        let r_sign = pub_r.as_point() + statement.as_public_key().as_point();
        let r_sign = PublicKey::from(r_sign);
        let public_key = pubkey.cloned().unwrap_or_else(|| PublicKey::from_secret(&sk));
        let challenge = self.hash_to_scalar(message, &r_sign, &public_key);
        // Schnorr signature scheme for partial signature
        let s = r.as_scalar() + challenge * sk.as_scalar();
        let pre_sig = PreSignature { challenge, s, public_key };
        Ok((r, pre_sig))
    }

    /// Verifies pre-signature (adapter signature) validity.
    ///
    /// The pre-signature is not a valid signature for the message, but it will verify the using an adapted public
    /// nonce offset by the statement.
    fn verify_pre_signature<B: AsRef<[u8]>>(
        &self,
        pre_sig: &PreSignature,
        pubkey: &PublicKey,
        message: B,
        statement: &<Self::W as Witness>::S,
    ) -> bool {
        let r_pre = &pre_sig.s * ED25519_BASEPOINT_TABLE - pre_sig.challenge * pubkey.as_point();
        let r_sign = r_pre + statement.as_public_key().as_point();
        let r_sign = PublicKey::from(r_sign);
        let challenge = self.hash_to_scalar(message, &r_sign, &pubkey);
        pre_sig.challenge == challenge
    }

    /// Verifies full signature validity
    fn verify_signature<B: AsRef<[u8]>>(&self, sig: &Signature, pubkey: &PublicKey, message: B) -> bool {
        let public_r = &sig.s * ED25519_BASEPOINT_TABLE - sig.challenge * pubkey.as_point();
        let public_r = PublicKey::from(public_r);
        let challenge = self.hash_to_scalar(message, &public_r, pubkey);
        sig.challenge == challenge
    }

    /// Converts pre-signature to full signature using the given witness/secret
    fn adapt_pre_signature(&self, pre_sig: &PreSignature, witness: &Self::W) -> Signature {
        let s = pre_sig.s + witness.as_scalar();
        let challenge = pre_sig.challenge.clone();
        Signature { s, challenge }
    }

    /// Extracts witness from signature/pre-signature pair
    fn extract_witness(
        &self,
        signature: &Signature,
        pre_sig: &PreSignature,
        statement: &<Self::W as Witness>::S,
    ) -> Result<Self::W, CasError> {
        let diff = signature.s - pre_sig.s;
        let point_check = &diff * ED25519_BASEPOINT_TABLE;
        if point_check != *statement.as_public_key().as_point() {
            return Err(CasError::InvalidTransitionProof);
        }
        let witness = Self::W::from_scalar(diff);
        Ok(witness)
    }
}

/// Error types for CAS operations
#[derive(Error, Debug)]
pub enum CasError {
    #[error("Invalid pre-signature")]
    InvalidPreSignature,
    #[error("Signature verification failed")]
    SignatureVerificationError,
    #[error("Invalid statement transition proof")]
    InvalidTransitionProof,
    #[error("The witness does not correspond to the statement")]
    WitnessStatementMismatch,
    #[error("Invalid key material")]
    KeyError,
}
