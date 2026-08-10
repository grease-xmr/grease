//! Channel Update Protocol Traits (v2)
//!
//! Spec: `docs/src/15_channel_update.typ` §`updateProtocol` and `docs/diagrams/channel_update_sequence.md`.
//!
//! A v2 update is deliberately cheap: *a handful of Schnorr operations plus one verifiably encrypted offset and
//! its binding proof*. There is no VCOF, no chained witness derivation and no ZK circuit, so nothing in this
//! module is asynchronous — the traits are plain synchronous Rust.
//!
//! # The shape of one update
//!
//! 1. The proposer calls [`UpdateProtocolProposer::initiate_update`] with a balance `delta` and the proposee
//!    mirrors it with [`UpdateProtocolProposee::receive_update_request`]. Either side may refuse.
//! 2. Both sides run the FROST preprocessing round-trip for the new pair of commitment transactions.
//! 3. Each side draws a **fresh, independent** offset `ω`, seals it to the arbiter and builds an
//!    [`UpdatePackage`]. The packages cross.
//! 4. Each side verifies the package it received and, if everything checks out, holds the cross-signed
//!    [`UpdateRecord`] for the new state.
//! 5. Both sides call `finalize_update`, which applies the balance delta and adopts the new `update_count`.
//!
//! # Offsets do not chain
//!
//! Every offset is drawn afresh for every state and every party. `ω_i` is **not** derived from `ω_{i-1}` — that
//! chaining was the whole point of the retired VCOF and it is gone. The spec is blunt about the consequence:
//! "Each state's offset is generated independently at random, so no offset reveals anything about any other …
//! There is therefore no need for the offsets to chain to one another, and no zero-knowledge circuit is
//! evaluated on an update."
//!
//! Offsets are domain-separated per *(channel, state, party)*. The channel and the state are carried by the
//! dispute statement the offset is sealed to — `m = (channel_id, update_count)`, produced by
//! [`statement_for`](crate::arbiter::client::statement_for) — so an offset sealed for state `i` stays sealed
//! under an attestation for any other state. Separation *between the parties* is not in `m`: both parties seal
//! to the same `m_i`, and what keeps their offsets apart is that each is an independent draw bound to its own
//! adaptor point `Q`. One attestation on `m_i` therefore opens both parties' state-`i` ciphertexts, which is
//! exactly right — at dispute time state `i` is the agreed latest and both closes settle it.
//!
//! An offset burned on an update that was then rejected must never be reused when the state is retried.
//!
//! # Which signature covers which transaction
//!
//! The adaptor signature a party *sends* is over the **counterparty's** new commitment transaction, adapted by
//! that party's own fresh `ω`. The signature a party *receives* is therefore the one over its **own** commitment
//! transaction: it can be completed — and the transaction broadcast — only once the counterparty reveals `ω`, at
//! a cooperative close, or once the arbiter attests the state, in a dispute.
//!
//! # Update counts
//!
//! `update_count` is monotonic but not necessarily incremented by one; gaps are legal. Implementations must
//! therefore compare counts with `>` rather than assuming a `+1` step, and the count carried in an
//! [`UpdatePackage`] is checked against the count the local side proposed, not against `current + 1`.

use crate::arbiter::client::statement_for;
use crate::channel_id::ChannelId;
use crate::cryptography::adapter_signature::AdaptedSignature;
use crate::cryptography::attestation::{G2Point, Statement};
use crate::cryptography::binding_proof::{
    prove_encrypted_offset, verify_encrypted_offset, BindingProof, BindingProofError, BindingProofParams,
};
use crate::cryptography::pvss::SecondBase;
use crate::grease_protocol::adapter_signature::{AdapterSignatureError, AdapterSignatureHandler};
use crate::grease_protocol::multisig_wallet::MultisigTransaction;
use crate::grease_protocol::update_record::{CloseHash, HalfSignedUpdateRecord, UpdateRecord, UpdateRecordError};
use crate::payment_channel::{ChannelRole, HasRole};
use crate::{XmrPoint, XmrScalar};
use crate::Ed25519;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Everything one party sends the other for a single channel update.
///
/// The two parties send structurally identical packages; they cross rather than being a request/response pair.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdatePackage {
    /// The state this package speaks about.
    pub update_count: u64,
    /// Our pre-signature over the **counterparty's** new commitment transaction, adapted by our fresh `ω`. Its
    /// adaptor point is `Q = ω·G`, readable with [`AdaptedSignature::adapter_commitment`].
    pub adapted_signature: AdaptedSignature<Ed25519>,
    /// `ω` verifiably encrypted to `m = (channel_id, update_count)` under the arbiter's master key `Z`, together
    /// with the cut-and-choose proof that what is sealed really is the discrete log of `Q`.
    ///
    /// The sealed share ciphertexts *are* the encrypted offset: the opened shares alone sit one short of the
    /// reconstruction threshold, so a single sealed share decrypted under an arbiter attestation completes the
    /// interpolation and yields `ω`. There is no separate, unbound `(U, c)` for `ω` itself — one would not be
    /// covered by [`verify_encrypted_offset`] and could be filled with anything.
    pub binding_proof: BindingProof,
    /// Our signature over the canonical [`UpdateRecord`] message for this state. The counterparty verifies it and
    /// pairs it with its own half to obtain the cross-signed record.
    pub record_half: HalfSignedUpdateRecord,
    /// FROST preprocessing data for the counterparty's new commitment transaction.
    pub preprocess: Vec<u8>,
}

impl UpdatePackage {
    /// Assemble an update package from its constituent parts.
    pub fn new(
        update_count: u64,
        adapted_signature: AdaptedSignature<Ed25519>,
        binding_proof: BindingProof,
        record_half: HalfSignedUpdateRecord,
        preprocess: Vec<u8>,
    ) -> Self {
        Self { update_count, adapted_signature, binding_proof, record_half, preprocess }
    }

    /// The adaptor point `Q = ω·G` the sender committed to for this state.
    pub fn adaptor_point(&self) -> XmrPoint {
        self.adapted_signature.adapter_commitment()
    }
}

/// The message the adaptor signature for `update_count` covers: the commitment transaction *held by* `holder`.
///
/// A free function because the dispute path needs the identical bytes — the claimant completes a pre-signature
/// built here, months after the update that produced it — and two independent copies of this format string would
/// be a silent way to make a dispute close unverifiable.
///
/// Provisional: the transcript-based commitment-transaction encoding is still a stub
/// ([`CommitmentTransaction`](crate::state_machine::CommitmentTransaction)), so this is a domain-separated
/// placeholder over `(channel, state, holder)`. It is separated by holder so the two signatures exchanged in one
/// update are never over the same bytes.
pub fn commitment_message(channel_id: &ChannelId, update_count: u64, holder: ChannelRole) -> Vec<u8> {
    format!("grease-commitment-tx-v2:{}:{update_count:016}:{holder}", channel_id.as_str()).into_bytes()
}

/// Common functionality shared by both update proposer and proposee.
///
/// The cryptographic steps — sealing an offset, checking a peer's sealed offset, checking a peer's record half —
/// have default implementations, because there is exactly one right way to do each and it is spelled out in the
/// spec. Implementations supply the channel facts those steps need.
pub trait UpdateProtocolCommon: HasRole + AdapterSignatureHandler + MultisigTransaction + Send + Sync {
    /// The channel this update belongs to.
    fn channel_id(&self) -> ChannelId;

    /// The `update_count` of the state this party is working with: the latest cross-signed [`UpdateRecord`], or
    /// the state under negotiation while an update is in flight.
    fn update_count(&self) -> u64;

    /// The counterparty's channel public key: the key their adapted signature and their record half verify under.
    fn peer_public_key(&self) -> XmrPoint;

    /// Our own channel signing key, used to sign our half of the record.
    fn signing_key(&self) -> &XmrScalar;

    /// The arbiter committee's stable master public key `Z`.
    fn arbiter_master_public_key(&self) -> G2Point;

    /// The cut-and-choose profile for the binding proof. Production `(104, 53)` unless a test overrides it.
    fn binding_proof_params(&self) -> BindingProofParams {
        BindingProofParams::production()
    }

    /// The second base `B` the binding proof's DLEQs are taken against. Recomputed locally, never read from the
    /// wire.
    fn second_base(&self) -> &'static SecondBase {
        SecondBase::grease_default()
    }

    /// The canonical hash of the pair of commitment transactions for `update_count` — what the
    /// [`UpdateRecord`] commits to.
    fn close_hash(&self, update_count: u64) -> Result<CloseHash, UpdateProtocolError>;

    /// The message the adaptor signature for `update_count` covers: the commitment transaction *held by*
    /// `holder`.
    ///
    /// Provisional: the transcript-based commitment-transaction encoding is still a stub
    /// ([`CommitmentTransaction`](crate::state_machine::CommitmentTransaction)), so the default is a
    /// domain-separated placeholder over `(channel, state, holder)`. It is separated by holder so the two
    /// signatures exchanged in one update are never over the same bytes.
    fn commitment_message(&self, update_count: u64, holder: ChannelRole) -> Vec<u8> {
        commitment_message(&self.channel_id(), update_count, holder)
    }

    /// The dispute statement `m = (channel_id, update_count)` an offset for this state is sealed to.
    fn statement(&self, update_count: u64) -> Statement {
        statement_for(&self.channel_id(), update_count)
    }

    /// Draw a fresh, independent offset `ω` for a new state. Never derived from the previous offset.
    fn fresh_offset<R: RngCore + CryptoRng>(&self, rng: &mut R) -> XmrScalar {
        XmrScalar::random(rng)
    }

    /// Seal `omega` to this channel's statement for `update_count` and prove it is the discrete log of `ω·G`.
    ///
    /// Takes no RNG: the prover is fully PRF-derived, and re-running it on the same inputs reproduces the same
    /// bytes on purpose (two proofs that opened different subsets would jointly leak `ω`).
    fn seal_offset(&self, omega: &XmrScalar, update_count: u64) -> Result<BindingProof, UpdateProtocolError> {
        let proof = prove_encrypted_offset(
            omega,
            &self.statement(update_count),
            &self.arbiter_master_public_key(),
            self.second_base(),
            self.binding_proof_params(),
        )?;
        Ok(proof)
    }

    /// Check a peer's sealed offset against the adaptor point in the pre-signature they sent for the same state.
    ///
    /// The profile is taken from the proof but must match the one we would have used: a peer that quietly drops
    /// to a weaker `(n, t)` would otherwise buy itself a cheap forgery.
    fn verify_sealed_offset(
        &self,
        proof: &BindingProof,
        update_count: u64,
        q: &XmrPoint,
    ) -> Result<(), UpdateProtocolError> {
        let expected = self.binding_proof_params();
        if *proof.params() != expected {
            return Err(UpdateProtocolError::InvalidDataFromPeer(format!(
                "binding proof uses profile (n={}, t={}), expected (n={}, t={})",
                proof.params().shares(),
                proof.params().threshold(),
                expected.shares(),
                expected.threshold()
            )));
        }
        verify_encrypted_offset(
            proof,
            &self.statement(update_count),
            &self.arbiter_master_public_key(),
            q,
            proof.q_b(),
            self.second_base(),
        )?;
        Ok(())
    }

    /// Sign our half of the [`UpdateRecord`] for `update_count`.
    fn sign_record_half<R: RngCore + CryptoRng>(
        &self,
        update_count: u64,
        rng: &mut R,
    ) -> Result<HalfSignedUpdateRecord, UpdateProtocolError> {
        let close_hash = self.close_hash(update_count)?;
        Ok(HalfSignedUpdateRecord::sign(
            self.channel_id(),
            update_count,
            close_hash,
            self.role(),
            self.signing_key(),
            rng,
        ))
    }

    /// Verify a peer's record half: signed by the opposite role, over the fields we expect, under their key.
    fn verify_record_half(
        &self,
        half: &HalfSignedUpdateRecord,
        update_count: u64,
    ) -> Result<(), UpdateProtocolError> {
        let expected_role = self.role().other();
        if half.signer_role() != expected_role {
            return Err(UpdateRecordError::RoleMismatch { expected: expected_role, actual: half.signer_role() }.into());
        }
        if half.channel_id() != &self.channel_id() || half.update_count() != update_count {
            return Err(UpdateProtocolError::InvalidDataFromPeer(
                "record half does not describe the state under negotiation".into(),
            ));
        }
        if half.close_hash() != &self.close_hash(update_count)? {
            return Err(UpdateProtocolError::InvalidDataFromPeer(
                "record half commits to a different closing transaction".into(),
            ));
        }
        half.verify(&self.peer_public_key())?;
        Ok(())
    }

    /// Pair a verified peer half with our own to obtain the cross-signed record for this state.
    ///
    /// Both parties assemble from the same two halves, so both end up holding byte-identical records — which
    /// re-signing with [`UpdateRecord::countersign`] would not guarantee.
    fn countersign_record(
        &self,
        own_half: &HalfSignedUpdateRecord,
        peer_half: &HalfSignedUpdateRecord,
    ) -> Result<UpdateRecord, UpdateProtocolError> {
        self.verify_record_half(peer_half, own_half.update_count())?;
        Ok(UpdateRecord::from_halves(own_half, peer_half)?)
    }

    /// Verify the peer's adapted signature over the commitment transaction it covers.
    fn verify_peer_adapted_signature(
        &self,
        sig: &AdaptedSignature<Ed25519>,
        msg: &[u8],
    ) -> Result<(), UpdateProtocolError> {
        sig.verify(&self.peer_public_key(), msg)
            .then_some(())
            .ok_or_else(|| UpdateProtocolError::SignatureVerificationFailed("peer adapted signature".into()))
    }

    /// The full verification of an incoming [`UpdatePackage`], in the order the sequence diagram fixes: the
    /// sealed offset binds to the adaptor point, the pre-signature is valid over *our* commitment transaction,
    /// and the record half is well-formed and signed. Any failure aborts the whole update.
    fn verify_update_package(&self, package: &UpdatePackage, expected_count: u64) -> Result<(), UpdateProtocolError> {
        if package.update_count != expected_count {
            return Err(UpdateProtocolError::UpdateCountMismatch {
                expected: expected_count,
                actual: package.update_count,
            });
        }
        self.verify_sealed_offset(&package.binding_proof, expected_count, &package.adaptor_point())?;
        let msg = self.commitment_message(expected_count, self.role());
        self.verify_peer_adapted_signature(&package.adapted_signature, &msg)?;
        self.verify_record_half(&package.record_half, expected_count)
    }
}

/// Protocol trait for the update proposer (initiator).
///
/// The proposer initiates a channel update by specifying a balance delta, exchanges preprocessing and packages,
/// and finalizes once it holds the cross-signed record.
pub trait UpdateProtocolProposer: UpdateProtocolCommon {
    /// Initiate a channel update with the given balance delta.
    ///
    /// A positive delta transfers funds from customer to merchant, a negative delta transfers from merchant to
    /// customer.
    fn initiate_update(&mut self, delta: i64) -> Result<(), UpdateProtocolError>;

    /// Generate FROST preprocessing data for the new commitment transactions.
    fn generate_tx_preprocessing<R: RngCore + CryptoRng>(&mut self, rng: &mut R) -> Result<Vec<u8>, UpdateProtocolError>;

    /// Create the update package to send to the peer: a fresh offset, its sealed form, the pre-signature over the
    /// peer's commitment transaction, and our half of the record.
    fn create_update_package<R: RngCore + CryptoRng>(&mut self, rng: &mut R) -> Result<UpdatePackage, UpdateProtocolError>;

    /// Verify the peer's package and hold the resulting cross-signed record.
    fn process_response(&mut self, response: &UpdatePackage) -> Result<(), UpdateProtocolError>;

    /// Finalize the update after a successful exchange. Returns the new update count.
    fn finalize_update(&mut self) -> Result<u64, UpdateProtocolError>;

    /// Abort the update and roll back to the previous state: the pending count and balances are discarded.
    fn abort_update(&mut self) -> Result<(), UpdateProtocolError>;
}

/// Protocol trait for the update proposee (responder).
///
/// The proposee receives update requests, validates them, and responds with its own package.
pub trait UpdateProtocolProposee: UpdateProtocolCommon {
    /// Receive and validate an update request from the proposer.
    fn receive_update_request(&mut self, delta: i64) -> Result<(), UpdateProtocolError>;

    /// Process the proposer's preprocessing data, returning our own to send back.
    fn process_tx_preprocessing(&mut self, preprocess: &[u8]) -> Result<Vec<u8>, UpdateProtocolError>;

    /// Verify the proposer's package and hold the peer half it carries.
    fn process_update_package(&mut self, package: &UpdatePackage) -> Result<(), UpdateProtocolError>;

    /// Create the response package, completing the cross-signed record for this state.
    fn create_response<R: RngCore + CryptoRng>(&mut self, rng: &mut R) -> Result<UpdatePackage, UpdateProtocolError>;

    /// Finalize the update after a successful exchange. Returns the new update count.
    fn finalize_update(&mut self) -> Result<u64, UpdateProtocolError>;

    /// Reject the update with a reason, resetting the pending count and balances to the previous state.
    fn reject_update(&mut self, reason: &str) -> Result<(), UpdateProtocolError>;
}

/// Errors that can occur during the channel update protocol.
#[derive(Debug, Error)]
pub enum UpdateProtocolError {
    #[error("Update {0} has not been prepared")]
    NotReady(u64),

    #[error("Received invalid data from peer: {0}")]
    InvalidDataFromPeer(String),

    #[error("Missing required information: {0}")]
    MissingInformation(String),

    #[error("Adapter signature error: {0}")]
    SignatureError(#[from] AdapterSignatureError),

    #[error("Insufficient balance: {0}")]
    InsufficientBalance(String),

    #[error("Update count mismatch: expected {expected}, got {actual}")]
    UpdateCountMismatch { expected: u64, actual: u64 },

    #[error("Update already in progress")]
    UpdateInProgress,

    #[error("No update in progress")]
    NoUpdateInProgress,

    #[error("Update was rejected: {0}")]
    UpdateRejected(String),

    #[error("Invalid balance delta: {0}")]
    InvalidDelta(String),

    #[error("Preprocessing error: {0}")]
    PreprocessingError(String),

    #[error("Signature verification failed: {0}")]
    SignatureVerificationFailed(String),

    #[error("Encrypted offset error: {0}")]
    EncryptedOffset(#[from] BindingProofError),

    #[error("Update record error: {0}")]
    Record(#[from] UpdateRecordError),
}
