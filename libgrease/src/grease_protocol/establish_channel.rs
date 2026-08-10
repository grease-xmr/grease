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
use crate::Ed25519;
use ciphersuite::WrappedGroup;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cryptography::attestation::test_helpers::master_public_key;
    use crate::cryptography::binding_proof::{prove_encrypted_offset, BindingProofParams};
    use crate::cryptography::pvss::SecondBase;
    use crate::XmrScalar;
    use blake2::Digest;
    use ic_bls12_381::{G2Affine, Scalar as BlsScalar};
    use std::str::FromStr;

    /// The frozen channel id from `channel_id.rs`'s own known-answer vector.
    const CHANNEL_ID: &str = "XGC0845ec076e64984475627c8c1a154defceaeea2ce3cd39c55b02823b4f70a4";

    /// `Blake2b512(binding_proof.to_bytes())`, split only to fit the line width. The proof is a compound input to
    /// the transcript, so it is pinned separately: a failure here says the proof encoding moved, and a failure in
    /// the payload vector alone says the transcript did.
    const PROOF_DIGEST: &str = concat!(
        "6235d944f0ed5a961d1a774f320a3b4d78fbfb39d6cba7a2f946f5d09e813f26",
        "968c029bb53947aa43359e7160083f563301b399bcc710b7f398cfc99bb46931",
    );

    /// The frozen `payload_signature_message` output, split only to fit the line width.
    const PAYLOAD_SIG_V2: &str = concat!(
        "b17096996dd5d854bb514b76dc2d04939c29096ffe88c7eaa59c65d875cc23c5",
        "f74e32d1bcaf2144312395b4908dd489807088801c53ebfb3aa09946b6c491f9",
    );

    /// Every input spelled out: `ω = 42`, the master secret `z` a fixed constant, `U = G_2`, `c` a fixed scalar,
    /// an `(8, 4)` proof profile. `prove_encrypted_offset` takes no RNG — every choice in it is PRF-derived — so
    /// the proof is a deterministic function of these five values.
    fn fixed_inputs() -> (ChannelId, EncryptedOffset, BindingProof) {
        let channel_id = ChannelId::from_str(CHANNEL_ID).expect("valid channel id");
        let encrypted_offset = EncryptedOffset::new(
            G2Point::from(G2Affine::generator()),
            XmrScalar::from(0x0123_4567_89ab_cdef_u64),
        )
        .expect("non-identity KEM point");
        let master_pk = master_public_key(&BlsScalar::from(0x1234_5678_90ab_cdef_u64));
        let statement = Statement::new(channel_id.as_str().as_bytes().to_vec(), INITIAL_UPDATE_COUNT);
        let params = BindingProofParams::new(8, 4).expect("valid profile");
        let omega = XmrScalar::from(42u64);
        let binding_proof =
            prove_encrypted_offset(&omega, &statement, &master_pk, SecondBase::grease_default(), params)
                .expect("proof");
        (channel_id, encrypted_offset, binding_proof)
    }

    /// Pins the canonical `BindingProof` encoding that the payload transcript absorbs, so a failure of the vector
    /// below is attributable. Crosses `ic_bls12_381`'s G2 compression and `dalek-ff-group`'s scalar encoding.
    #[test]
    fn binding_proof_encoding_is_frozen() {
        let (_, _, proof) = fixed_inputs();
        assert_eq!(hex::encode(blake2::Blake2b512::digest(proof.to_bytes())), PROOF_DIGEST);
        assert_eq!(hex::encode(proof.q().to_bytes()), "ce1a32994e835c193e2bf33909f44373ae2cf94ddef0fd922035c483670637c2");
    }

    /// Freezes the establish payload transcript under the live `"Grease PayloadSig v2"` domain tag. Crosses
    /// `flexible-transcript`'s `DigestTranscript` and `blake2 0.10`, both replaced by the serai migration; a
    /// drift here means an init package built on the old pin no longer verifies against one built on the new.
    #[test]
    fn payload_signature_message_is_frozen() {
        let (channel_id, encrypted_offset, binding_proof) = fixed_inputs();
        let q = *binding_proof.q();
        let message =
            payload_signature_message(&channel_id, &encrypted_offset, &binding_proof, Duration::from_secs(86_400), &q);
        assert_eq!(hex::encode(&message), PAYLOAD_SIG_V2);
    }

    /// The dispute window is absorbed, so two otherwise identical packages under different windows differ.
    #[test]
    fn payload_signature_message_binds_the_dispute_window() {
        let (channel_id, encrypted_offset, binding_proof) = fixed_inputs();
        let q = *binding_proof.q();
        let day =
            payload_signature_message(&channel_id, &encrypted_offset, &binding_proof, Duration::from_secs(86_400), &q);
        let hour =
            payload_signature_message(&channel_id, &encrypted_offset, &binding_proof, Duration::from_secs(3_600), &q);
        assert_ne!(day, hour);
    }
}
