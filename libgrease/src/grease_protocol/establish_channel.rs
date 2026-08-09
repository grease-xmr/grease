//! Channel Establishment Protocol
//!
//! Spec: `docs/src/14_establishing_channel.typ` §`initProtocol`, and the sequence diagrams
//! `docs/diagrams/establish_channel_sequence_{a,b}.md`.
//!
//! This module defines the package the two parties exchange to agree the *initial* channel state: an adaptor
//! signature over the counterparty's closing transaction, the fresh offset that locks it verifiably encrypted to
//! the arbiter, and the binding proof tying the two together. The arbiter is not contacted during establishment
//! and holds no state for the channel until a dispute is opened.

use crate::channel_id::ChannelId;
use crate::cryptography::adapter_signature::{AdaptedSignature, SchnorrSignature};
use crate::cryptography::attestation::{G2Point, Statement};
use crate::cryptography::binding_proof::{
    prove_encrypted_offset, verify_encrypted_offset, BindingProof, BindingProofError, BindingProofParams,
};
use crate::cryptography::pvss::SecondBase;
use crate::cryptography::verifiable_encryption::{encrypt_to_statement, EncryptedOffset, VerifiableEncryptionError};
use crate::error::ReadError;
use crate::grease_protocol::adapter_signature::adapter_signature_message;
use crate::grease_protocol::multisig_wallet::{MultisigTxError, MultisigWalletError};
use crate::grease_protocol::update_record::CloseHash;
use crate::state_machine::MultisigSetupError;
use crate::{XmrPoint, XmrScalar};
use ciphersuite::group::ff::{Field, PrimeField};
use ciphersuite::group::GroupEncoding;
use ciphersuite::{Ciphersuite, Ed25519};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, Error)]
pub enum EstablishError {
    #[error("A commitment is invalid: {0}")]
    InvalidCommitment(String),
    #[error("Received invalid data from peer: {0}")]
    InvalidDataFromPeer(String),
    #[error("Could not provide result because the {0} is missing.")]
    MissingInformation(String),
    #[error("Multisig wallet setup error: {0}")]
    MultisigSetupError(#[from] MultisigSetupError),
    #[error("Error initializing wallet: {0}")]
    WalletError(#[from] MultisigWalletError),
    #[error("Error setting up initial transaction: {0}")]
    Tx0Error(#[from] MultisigTxError),
    #[error("Could not deserialize a binary data structure: {0}")]
    ReadError(#[from] ReadError),
    #[error("Payload signature verification failed: {0}")]
    InvalidPayloadSignature(String),
    #[error("Expected {expected} role but got {got}")]
    WrongRole { expected: crate::payment_channel::ChannelRole, got: crate::payment_channel::ChannelRole },
    #[error("Binding proof verification failed: {0}")]
    BindingProof(#[from] BindingProofError),
    #[error("Verifiable encryption failed: {0}")]
    VerifiableEncryption(#[from] VerifiableEncryptionError),
    #[error("The channel id cannot be bound to a funding output: {0}")]
    ChannelIdFinalize(#[from] crate::channel_id::ChannelIdFinalizeError),
    #[error("Update record error: {0}")]
    Record(#[from] crate::grease_protocol::update_record::UpdateRecordError),
}

// Backwards-compatible alias during migration
pub type EstablishProtocolError = EstablishError;

/// The update count of the initial channel state; the statement the initial offsets are sealed to is
/// `m = (channel_id, 0)`.
pub const INITIAL_UPDATE_COUNT: u64 = 0;

/// The initial-state package (`docs/src/14_establishing_channel.typ` §initProtocol, steps 4–5).
///
/// Each party adapter-signs the **counterparty's** closing transaction with a fresh secret offset `ω` and hands
/// over this bundle: the offset verifiably encrypted to the "latest state" statement `m = (channel_id, 0)` under
/// the arbiter's master key, the binding proof establishing that the sealed offset is the discrete logarithm of
/// the adaptor point `Q` in `adapted_signature`, and a payload signature tying the whole bundle to the channel
/// parameters. The counterparty verifies all of it — [`ChannelInitPackage::verify`] — before accepting the
/// initial state.
///
/// `encrypted_offset` is a *direct* ciphertext of `ω` addressed to `m` — the one-shot decryption path on a
/// dispute. It is bound into the payload signature (so it cannot be swapped in transit) but is not independently
/// proven; the proven object is `binding_proof`, whose sealed share ciphertexts always suffice to reconstruct `ω`
/// once the arbiter attests `m`. A counterparty that decrypts a garbage direct ciphertext falls back to share
/// reconstruction, so a dishonest author gains nothing.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ChannelInitPackage {
    /// `EncryptToStatement(ω, m, Z)` — the direct ciphertext of the offset, sealed to `m = (channel_id, 0)`.
    pub encrypted_offset: EncryptedOffset,
    /// The cut-and-choose binding proof tying the sealed offset to the adaptor point `Q` (and `Q^B`).
    pub binding_proof: BindingProof,
    /// The adapted signature over the counterparty's closing transaction, locked by `Q = ω·G`.
    pub adapted_signature: AdaptedSignature<Ed25519>,
    /// Schnorr signature over [`payload_signature_message`], verifying under `nonce_pubkey`.
    pub payload_signature: SchnorrSignature<Ed25519>,
    /// The signer's ephemeral nonce public key (`G · nonce`), used to verify `payload_signature`.
    #[serde(serialize_with = "crate::helpers::serialize_ge", deserialize_with = "crate::helpers::deserialize_ge")]
    pub nonce_pubkey: XmrPoint,
}

/// Compute the payload-signature message binding a [`ChannelInitPackage`] to the channel parameters.
///
/// Commits to `(channel_id, the encrypted-offset bundle, dispute_window, Q)`, where the bundle is the direct
/// ciphertext `(U, c)` together with the canonical encoding of the binding proof, and `Q = ω·G` is the adaptor
/// point of the accompanying adapted signature.
pub(crate) fn payload_signature_message(
    channel_id: &ChannelId,
    encrypted_offset: &EncryptedOffset,
    binding_proof: &BindingProof,
    dispute_window: Duration,
    q: &XmrPoint,
) -> Vec<u8> {
    use blake2::Blake2b512;
    use flexible_transcript::{DigestTranscript, Transcript};

    let mut transcript = DigestTranscript::<Blake2b512>::new(b"Grease PayloadSig v2");
    transcript.append_message(b"channel_id", channel_id.as_str().as_bytes());
    transcript.append_message(b"U", encrypted_offset.u().to_compressed());
    transcript.append_message(b"c", encrypted_offset.c().to_repr());
    transcript.append_message(b"binding_proof", binding_proof.to_bytes());
    transcript.append_message(b"dw", dispute_window.as_secs().to_le_bytes());
    transcript.append_message(b"Q", q.to_bytes());
    transcript.challenge(b"payload_sig_message").to_vec()
}

impl ChannelInitPackage {
    /// Create our half of the initial state: a fresh random offset `ω`, the adapted signature over the
    /// *counterparty's* closing transaction (`peer_close_hash`), the offset sealed to `m = (channel_id, 0)`
    /// under the arbiter's master key `Z`, and the binding proof.
    ///
    /// `ω` is sampled fresh from the RNG — offsets are independent per state and per party, never derived and
    /// never reused. The caller receives it back alongside the package and must keep it secret until the state
    /// it locks is superseded or cooperatively closed.
    pub fn create<R: RngCore + CryptoRng>(
        channel_id: &ChannelId,
        peer_close_hash: &CloseHash,
        dispute_window: Duration,
        signing_key: &XmrScalar,
        arbiter_pk: &G2Point,
        params: BindingProofParams,
        rng: &mut R,
    ) -> Result<(Self, Zeroizing<XmrScalar>), EstablishError> {
        let omega = Zeroizing::new(fresh_offset(rng));
        let statement = initial_statement(channel_id);
        let binding_proof = prove_encrypted_offset(&omega, &statement, arbiter_pk, SecondBase::grease_default(), params)?;
        let encrypted_offset = encrypt_to_statement(&omega, &statement, arbiter_pk, rng)?;
        let msg = adapter_signature_message(channel_id, INITIAL_UPDATE_COUNT, peer_close_hash);
        let adapted_signature = AdaptedSignature::<Ed25519>::sign(signing_key, &omega, msg, rng);
        let q = adapted_signature.adapter_commitment();
        let payload_msg = payload_signature_message(channel_id, &encrypted_offset, &binding_proof, dispute_window, &q);
        let mut nonce = XmrScalar::random(&mut *rng);
        let nonce_pubkey = Ed25519::generator() * nonce;
        let payload_signature = SchnorrSignature::<Ed25519>::sign(&nonce, payload_msg, rng);
        nonce.zeroize();
        let package = ChannelInitPackage { encrypted_offset, binding_proof, adapted_signature, payload_signature, nonce_pubkey };
        Ok((package, omega))
    }

    /// Verify the counterparty's package before accepting the initial state.
    ///
    /// Three checks, each with its own failure mode:
    /// 1. the adapted signature verifies under the peer's signing key over *our* closing transaction
    ///    (`own_close_hash`) at state 0;
    /// 2. `VerifyEncryptedOffset`: the binding proof holds for `m = (channel_id, 0)` under `Z`, and its target
    ///    `Q` is exactly the adaptor point of the adapted signature (`Q^B` is tied to `Q` by the proof's own
    ///    coefficient DLEQs);
    /// 3. the payload signature verifies under `nonce_pubkey`, binding the bundle to the channel parameters.
    pub fn verify(
        &self,
        channel_id: &ChannelId,
        own_close_hash: &CloseHash,
        dispute_window: Duration,
        peer_pubkey: &XmrPoint,
        arbiter_pk: &G2Point,
    ) -> Result<(), EstablishError> {
        let msg = adapter_signature_message(channel_id, INITIAL_UPDATE_COUNT, own_close_hash);
        if !self.adapted_signature.verify(peer_pubkey, msg) {
            return Err(EstablishError::InvalidDataFromPeer(
                "adapted signature over the closing transaction does not verify".into(),
            ));
        }
        let q = self.adapted_signature.adapter_commitment();
        let statement = initial_statement(channel_id);
        let q_b = *self.binding_proof.q_b();
        verify_encrypted_offset(&self.binding_proof, &statement, arbiter_pk, &q, &q_b, SecondBase::grease_default())?;
        let payload_msg = payload_signature_message(channel_id, &self.encrypted_offset, &self.binding_proof, dispute_window, &q);
        self.payload_signature
            .verify(&self.nonce_pubkey, payload_msg)
            .then_some(())
            .ok_or_else(|| EstablishError::InvalidPayloadSignature("v2 init package payload signature does not verify".into()))
    }
}

/// The statement the initial offsets are sealed to: "on this channel, state 0 is the latest".
fn initial_statement(channel_id: &ChannelId) -> Statement {
    Statement::new(channel_id.as_str(), INITIAL_UPDATE_COUNT)
}

/// Sample a fresh, nonzero secret offset.
fn fresh_offset<R: RngCore + CryptoRng>(rng: &mut R) -> XmrScalar {
    std::iter::repeat_with(|| XmrScalar::random(&mut *rng))
        .find(|omega| !bool::from(omega.is_zero()))
        .expect("a uniform scalar is nonzero with overwhelming probability")
}
