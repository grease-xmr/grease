//! Channel Establishment Protocol
//!
//! Spec: `docs/src/14_establishing_channel.typ` §`initProtocol`, and the sequence diagrams
//! `docs/diagrams/establish_channel_sequence_{a,b}.md`.
//!
//! This module defines the package the two parties exchange to agree the *initial* channel state: an adaptor
//! signature over the counterparty's closing transaction, and the binding proof that seals the signature's
//! secret offset — verifiably encrypted to the arbiter — to that signature's adaptor point. The arbiter is not
//! contacted during establishment and holds no state for the channel until a dispute is opened.

use crate::arbiter::client::statement_for;
use crate::channel_id::{ChannelId, ProvisionalChannelIdError};
use crate::cryptography::adapter_signature::AdaptedSignature;
use crate::cryptography::attestation::{G2Point, Statement};
use crate::cryptography::binding_proof::{
    prove_encrypted_offset, verify_encrypted_offset, BindingProof, BindingProofError, BindingProofParams,
};
use crate::cryptography::pvss::SecondBase;
use crate::cryptography::verifiable_encryption::VerifiableEncryptionError;
use crate::error::ReadError;
use crate::grease_protocol::adapter_signature::adapter_signature_message;
use crate::grease_protocol::multisig_wallet::{MultisigTxError, MultisigWalletError};
use crate::grease_protocol::update_record::{CloseHash, HalfSignedUpdateRecord, UpdateRecordError};
use crate::payment_channel::ChannelRole;
use crate::state_machine::MultisigSetupError;
use crate::{XmrPoint, XmrScalar};
use ciphersuite::group::ff::Field;
use crate::Ed25519;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

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
    #[error("Expected {expected} role but got {got}")]
    WrongRole { expected: crate::payment_channel::ChannelRole, got: crate::payment_channel::ChannelRole },
    #[error("Binding proof verification failed: {0}")]
    BindingProof(#[from] BindingProofError),
    #[error("Verifiable encryption failed: {0}")]
    VerifiableEncryption(#[from] VerifiableEncryptionError),
    #[error("The channel id cannot be bound to a funding output: {0}")]
    ChannelIdFinalize(#[from] crate::channel_id::ChannelIdFinalizeError),
    #[error(transparent)]
    ProvisionalChannelId(#[from] crate::channel_id::ProvisionalChannelIdError),
    #[error("Update record error: {0}")]
    Record(#[from] crate::grease_protocol::update_record::UpdateRecordError),
    #[error("the peer's record half does not describe state 0 of channel {0}")]
    MismatchedRecordHalf(ChannelId),
    #[error("the {0} committed no initial balance, so it contributes no funding output to declare")]
    NotAFundingParty(ChannelRole),
    #[error("the {0} has already declared its funding output; a channel's funding set is declared once")]
    FundingOutputAlreadyDeclared(ChannelRole),
    #[error("expected {expected} partial linking tags, one per declared funding output, but got {actual}")]
    PartialLinkingTagCount { expected: usize, actual: usize },
}

// Backwards-compatible alias during migration
pub type EstablishProtocolError = EstablishError;

/// The update count of the initial channel state; the statement the initial offsets are sealed to is
/// `m = (channel_id, 0)`.
pub const INITIAL_UPDATE_COUNT: u64 = 0;

/// The initial-state package (`docs/src/14_establishing_channel.typ` §initProtocol, steps 4–5).
///
/// Each party adapter-signs the **counterparty's** closing transaction with a fresh secret offset `ω` and hands
/// over this bundle: the adapted signature, locked by `Q = ω·G`, and the binding proof establishing that the
/// offset verifiably encrypted to the "latest state" statement `m = (channel_id, 0)` under the arbiter's master
/// key is the discrete logarithm of that very `Q`. The counterparty verifies both —
/// [`ChannelInitPackage::verify`] — before accepting the initial state.
///
/// The adaptor signature's message binds the channel id, the update count 0 and the close hash under the
/// sender's wallet signing key; `verify_encrypted_offset` binds the proof to `m`, the arbiter key `Z` and that
/// signature's adaptor point `Q`; and the proof's sealed share ciphertexts *are* the encrypted offset — on a
/// dispute, a single sealed share decrypted under an arbiter attestation completes the interpolation and yields
/// `ω` ([`recover_offset`](crate::cryptography::binding_proof::recover_offset)). A separate direct ciphertext of
/// `ω` would not be covered by the proof and could be filled with anything, so none is sent — the same shape as
/// [`UpdatePackage`](crate::grease_protocol::update_channel::UpdatePackage).
///
/// The record half travels in the same message rather than in an exchange of its own, so that "both packages
/// exchanged" is the same fact as "the cross-signed state-0 record can be assembled", and so that the adaptor
/// signature, its binding proof and the half it goes with are accepted or refused as one unit.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ChannelInitPackage {
    /// The cut-and-choose binding proof tying the sealed offset to the adaptor point `Q` (and `Q^B`).
    pub binding_proof: BindingProof,
    /// The adapted signature over the counterparty's closing transaction, locked by `Q = ω·G`.
    pub adapted_signature: AdaptedSignature<Ed25519>,
    /// Our signature over the canonical [`UpdateRecord`] message for state 0. The counterparty verifies it and
    /// pairs it with its own half to obtain the cross-signed record — the only thing the arbiter adjudicates on.
    ///
    /// [`UpdateRecord`]: crate::grease_protocol::update_record::UpdateRecord
    pub record_half: HalfSignedUpdateRecord,
}

impl ChannelInitPackage {
    /// Create our half of the initial state: a fresh random offset `ω`, the adapted signature over the
    /// *counterparty's* closing transaction (`peer_close_hash`), and the binding proof sealing `ω` to
    /// `m = (channel_id, 0)` under the arbiter's master key `Z`.
    ///
    /// `ω` is sampled fresh from the RNG — offsets are independent per state and per party, never derived and
    /// never reused. The caller receives it back alongside the package and must keep it secret until the state
    /// it locks is superseded or cooperatively closed.
    ///
    /// `record_half` arrives pre-built rather than being signed here, because it is signed with a *different*
    /// key: the adaptor signature adapts the wallet's FROST signing share, while the record half is signed with
    /// the wallet spend key the arbiter registers and the dispute path verifies against. A half that does not
    /// describe `(channel_id, 0)` is refused here, so the mistake is caught locally rather than by the peer.
    pub fn create<R: RngCore + CryptoRng>(
        channel_id: &ChannelId,
        peer_close_hash: &CloseHash,
        signing_key: &XmrScalar,
        record_half: HalfSignedUpdateRecord,
        arbiter_pk: &G2Point,
        params: BindingProofParams,
        rng: &mut R,
    ) -> Result<(Self, Zeroizing<XmrScalar>), EstablishError> {
        if record_half.channel_id() != channel_id || record_half.update_count() != INITIAL_UPDATE_COUNT {
            return Err(EstablishError::MismatchedRecordHalf(channel_id.clone()));
        }
        let omega = Zeroizing::new(fresh_offset(rng));
        let statement = initial_statement(channel_id)?;
        let binding_proof = prove_encrypted_offset(&omega, &statement, arbiter_pk, SecondBase::grease_default(), params)?;
        let msg = adapter_signature_message(channel_id, INITIAL_UPDATE_COUNT, peer_close_hash)?;
        let adapted_signature = AdaptedSignature::<Ed25519>::sign(signing_key, &omega, msg, rng);
        let package = ChannelInitPackage { binding_proof, adapted_signature, record_half };
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
    /// 3. the record half is signed by the opposite role, describes `(channel_id, 0)` over `record_close_hash`,
    ///    and verifies under the peer's key.
    ///
    /// `record_close_hash` is the canonical hash of *both* state-0 exits, not `own_close_hash`: a record carries
    /// one hash per state, and the two per-holder hashes cannot both go in it.
    pub fn verify(
        &self,
        channel_id: &ChannelId,
        own_close_hash: &CloseHash,
        record_close_hash: &CloseHash,
        own_role: ChannelRole,
        peer_pubkey: &XmrPoint,
        arbiter_pk: &G2Point,
    ) -> Result<(), EstablishError> {
        let msg = adapter_signature_message(channel_id, INITIAL_UPDATE_COUNT, own_close_hash)?;
        if !self.adapted_signature.verify(peer_pubkey, msg) {
            return Err(EstablishError::InvalidDataFromPeer(
                "adapted signature over the closing transaction does not verify".into(),
            ));
        }
        let q = self.adapted_signature.adapter_commitment();
        let statement = initial_statement(channel_id)?;
        let q_b = *self.binding_proof.q_b();
        verify_encrypted_offset(&self.binding_proof, &statement, arbiter_pk, &q, &q_b, SecondBase::grease_default())?;
        self.verify_record_half(channel_id, record_close_hash, own_role, peer_pubkey)
    }

    /// The record-half half of [`verify`](Self::verify), in the order
    /// [`verify_record_half`](crate::grease_protocol::update_channel::UpdateProtocolCommon::verify_record_half)
    /// fixes: role, then the signed fields, then the signature itself.
    fn verify_record_half(
        &self,
        channel_id: &ChannelId,
        record_close_hash: &CloseHash,
        own_role: ChannelRole,
        peer_pubkey: &XmrPoint,
    ) -> Result<(), EstablishError> {
        let half = &self.record_half;
        let expected = own_role.other();
        if half.signer_role() != expected {
            return Err(UpdateRecordError::RoleMismatch { expected, actual: half.signer_role() }.into());
        }
        if half.channel_id() != channel_id || half.update_count() != INITIAL_UPDATE_COUNT {
            return Err(EstablishError::MismatchedRecordHalf(channel_id.clone()));
        }
        if half.close_hash() != record_close_hash {
            return Err(EstablishError::MismatchedRecordHalf(channel_id.clone()));
        }
        half.verify(peer_pubkey)?;
        Ok(())
    }
}

/// The statement the initial offsets are sealed to: "on this channel, state 0 is the latest".
///
/// Routed through [`statement_for`] so its refusal of a provisional id — and its canonical encoding of the id —
/// hold here too, ahead of the sealing.
fn initial_statement(channel_id: &ChannelId) -> Result<Statement, ProvisionalChannelIdError> {
    statement_for(channel_id, INITIAL_UPDATE_COUNT)
}

/// Sample a fresh, nonzero secret offset.
fn fresh_offset<R: RngCore + CryptoRng>(rng: &mut R) -> XmrScalar {
    std::iter::repeat_with(|| XmrScalar::random(&mut *rng))
        .find(|omega| !bool::from(omega.is_zero()))
        .expect("a uniform scalar is nonzero with overwhelming probability")
}
