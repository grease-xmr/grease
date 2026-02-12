//! Channel Establishment Protocol
//!
//! This module defines types for the channel establishment phase, where both parties
//! exchange cryptographic material to set up the 2-of-2 multisig wallet, generate
//! adapter signatures, and interact with the KES for offset encryption.

use crate::channel_id::ChannelId;
use crate::cryptography::adapter_signature::{AdaptedSignature, SchnorrSignature};
use crate::cryptography::dleq::{Dleq, DleqError, DleqProof};
use crate::cryptography::pok::KesProofError;
use crate::cryptography::secret_encryption::EncryptedSecret;
use crate::error::ReadError;
use crate::grease_protocol::multisig_wallet::MultisigWalletError;
use ciphersuite::group::GroupEncoding;
use ciphersuite::{Ciphersuite, Ed25519};
use modular_frost::curve::Curve as FrostCurve;
use modular_frost::sign::Writable;
use std::time::Duration;
use thiserror::Error;

/// A bundle of cryptographic material exchanged during channel establishment.
///
/// Each party generates this package containing their encrypted offset (chi value),
/// adapted signature, and DLEQ proof. The counterparty uses this to verify that
/// the correct initial offset was provided to the KES.
///
/// The generic parameter `KC` is the curve used by the KES (defaults to Ed25519).
#[derive(Clone, Debug)]
pub struct ChannelInitPackage<KC: FrostCurve>
where
    Ed25519: Dleq<KC>,
{
    pub encrypted_offset: EncryptedSecret<KC>,
    pub adapted_signature: AdaptedSignature<Ed25519>,
    pub dleq_proof: DleqProof<KC, Ed25519>,
    pub payload_signature: SchnorrSignature<KC>,
    /// The signer's nonce public key (`G * nonce`), used to verify `payload_signature`.
    pub nonce_pubkey: KC::G,
}

#[derive(Debug, Error)]
pub enum EstablishError {
    #[error("A commitment is invalid: {0}")]
    InvalidCommitment(String),
    #[error("Received invalid data from peer: {0}")]
    InvalidDataFromPeer(String),
    #[error("AdapterSigOffset error: {0}")]
    AdapterSigOffsetError(#[from] DleqError),
    #[error("DLEQ proof generation failed: {0}")]
    DleqGenerationError(crate::cryptography::dleq::DleqError),
    #[error("The provided KES public key is invalid for the given curve.")]
    InvalidKesPublicKey,
    #[error("Could not provide result because the {0} is missing.")]
    MissingInformation(String),
    #[error("Multisig wallet error: {0}")]
    MultisigWalletError(#[from] MultisigWalletError),
    #[error("Could not deserialize a binary data structure: {0}")]
    ReadError(#[from] ReadError),
    #[error("KES proof verification failed: {0}")]
    KesProofError(#[from] KesProofError),
    #[error("Payload signature verification failed: {0}")]
    InvalidPayloadSignature(String),
    #[error("Expected {expected} role but got {got}")]
    WrongRole { expected: crate::payment_channel::ChannelRole, got: crate::payment_channel::ChannelRole },
}

// Backwards-compatible alias during migration
pub type EstablishProtocolError = EstablishError;

/// Compute the payload signature message that binds a [`ChannelInitPackage`] to the channel parameters.
///
/// The message commits to `(channel_id, encrypted_offset, dispute_window, T0)` where T0 is the
/// KC-curve public point of the initial offset.
pub(crate) fn payload_signature_message<KC: Ciphersuite>(
    channel_id: &ChannelId,
    encrypted_offset: &EncryptedSecret<KC>,
    dispute_window: Duration,
    initial_offset_public: &KC::G,
) -> Vec<u8> {
    use blake2::Blake2b512;
    use flexible_transcript::{DigestTranscript, Transcript};

    let mut transcript = DigestTranscript::<Blake2b512>::new(b"Grease PayloadSig v1");
    transcript.append_message(b"channel_id", channel_id.as_str().as_bytes());
    let chi_bytes = Writable::serialize(encrypted_offset);
    transcript.append_message(b"chi0", &chi_bytes);
    transcript.append_message(b"dw", dispute_window.as_secs().to_le_bytes());
    transcript.append_message(b"T0", initial_offset_public.to_bytes().as_ref());
    transcript.challenge(b"payload_sig_message").to_vec()
}
