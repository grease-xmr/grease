//! Channel force-close protocol traits (v2 — dispute resolution through the arbiter).
//!
//! Spec: `docs/src/18_channel_dispute.typ`, `docs/src/40_arbiter.typ` §`disputeFlow` and §`icp`, and
//! `docs/diagrams/channel_dispute_sequence.md`.
//!
//! # What changed from v1
//!
//! The v1 design escrowed each party's offset with a Key Escrow Service that *held* it and *released* it to
//! whoever won an adjudication. The v2 arbiter holds nothing. It runs a deterministic state machine over a
//! public log, and at the close of an adjudication window it attests one statement: `m = (channel_id,
//! high_water)`. That attestation `σ_m` **is** the decryption key for every offset sealed to `m` — nothing is
//! handed over, because there was never anything to hand over.
//!
//! The consequences run through this whole module:
//!
//! - There is no force-close *request* and no *claim* request. A party presents the cross-signed
//!   [`UpdateRecord`] it already holds, through [`ArbiterClient::submit_dispute`]; the record's two signatures
//!   are the whole authorization, so nothing is signed at dispute time.
//! - The window **refreshes** whenever a higher record is presented. A claimant that presented state `i` and is
//!   answered with state `n > i` does not lose a contest — its presentation is simply no longer the maximal one,
//!   and the clock restarts at `n`.
//! - **Cheating is frozen, not punished.** There is no penalty, no forfeit, and no offset handover on a
//!   "defendant win". The stale party's ciphertext for `m_i` is never unsealed, so its stale close can never be
//!   completed, and that is the entire sanction. [`DisputeOutcome`] names the three terminal shapes —
//!   superseded, frozen, attested — and there is no variant in which value moves as a result of the dispute.
//! - Claimant and defendant are *symmetric*. Both present records; the only asymmetry is who went first.
//!
//! # The claimant's path
//!
//! [`present_record`](ForceCloseProtocolClaimant::present_record) →
//! [`track_dispute`](ForceCloseProtocolClaimant::track_dispute) until the window elapses →
//! [`collect_attestation`](ForceCloseProtocolClaimant::collect_attestation) (delivered wrapped to a
//! [`TransportKeyPair`], unwrapped through vetKD's `decrypt_and_verify`) →
//! [`recover_offset`](ForceCloseProtocolClaimant::recover_offset) on the peer's retained binding proof →
//! [`complete_closing_signature`](ForceCloseProtocolClaimant::complete_closing_signature) →
//! [`broadcast_closing_tx`](ForceCloseProtocolClaimant::broadcast_closing_tx).
//!
//! # The defendant's path
//!
//! Watch — [`watch_for_dispute`](ForceCloseProtocolDefendant::watch_for_dispute) polls the arbiter's public
//! state, [`dispute_log`](ForceCloseProtocolDefendant::dispute_log) its action log — and if
//! [`has_more_recent_state`](ForceCloseProtocolDefendant::has_more_recent_state) says we hold something later,
//! [`answer_dispute`](ForceCloseProtocolDefendant::answer_dispute) presents it. That advances the high-water
//! mark and restarts the window. A defendant that holds nothing newer has nothing to do: it is already being
//! closed at the true latest state.
//!
//! Watching is a *duty*, and a delegable one (§`disputeFlow`): a watchtower can poll and answer on a party's
//! behalf without ever being able to redirect funds, because a close pays the parties' own addresses.

use std::cmp::Ordering;
use std::time::Duration;

use async_trait::async_trait;
use ciphersuite::Ed25519;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::arbiter::client::{
    statement_for, ActionLogEntry, ArbiterClient, ArbiterError, DisputeStateView, TransportKeyPair,
};
use crate::channel_id::ChannelId;
use crate::cryptography::adapter_signature::{AdaptedSignature, SchnorrSignature};
use crate::cryptography::attestation::{G1Point, G2Point, Statement};
use crate::cryptography::binding_proof::{self, BindingProof, BindingProofError};
use crate::grease_protocol::update_channel::commitment_message;
use crate::grease_protocol::update_record::{UpdateRecord, UpdateRecordError};
use crate::monero::data_objects::TransactionId;
use crate::payment_channel::{ChannelRole, HasRole};
use crate::{XmrPoint, XmrScalar};

//--------------------------------------------------------------------------------------------------------------------
//                                              Status and outcome
//--------------------------------------------------------------------------------------------------------------------

/// Where a party stands in a force close.
///
/// The v1 state graph survives — a party is idle, then pending on an open window, then either able to claim or
/// unable to — but the meaning of each terminal state is the arbiter's, not an escrow's: `Claimable` means an
/// attestation exists for the state *we* hold, and `Frozen` means one exists for a state we do not, so nothing
/// of ours can ever be unsealed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PendingCloseStatus {
    /// No dispute has been opened on this channel.
    Idle,
    /// A record has been presented and the adjudication window is open.
    Pending,
    /// A higher record superseded ours; the mark advanced and the window restarted at that state.
    Superseded,
    /// The window elapsed on the state we hold: `σ_m` exists and the close can be completed.
    Claimable,
    /// The window elapsed on a state we do not hold. No offset of ours is released, and no penalty is applied.
    Frozen,
    /// We completed the close for the attested state and broadcast it.
    ForceClosed,
    /// The dispute was abandoned before it resolved — a cooperative close intervened.
    Abandoned,
}

/// How a dispute stands, read from the arbiter's public state by the party holding update count `held`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DisputeOutcome {
    /// The window is open. `high_water` may sit *below* our own state, which is precisely the case a defendant
    /// answers by presenting its later record.
    Open { high_water: u64, window_expiry: u64 },
    /// A higher record has been presented. The mark advanced and the window restarted, so our presentation is no
    /// longer the one that will be attested.
    Superseded { held: u64, high_water: u64 },
    /// The window closed on the state we hold: the arbiter attested `m = (channel_id, update_count)` and our
    /// close can be completed with it.
    Attested { update_count: u64 },
    /// The window closed on a state we do not hold. Our ciphertexts stay sealed for good — the close we were
    /// pursuing is frozen, not penalized.
    Frozen { held: u64, attested: u64 },
}

impl DisputeOutcome {
    /// The status this outcome puts the party in.
    pub fn status(&self) -> PendingCloseStatus {
        match self {
            DisputeOutcome::Open { .. } => PendingCloseStatus::Pending,
            DisputeOutcome::Superseded { .. } => PendingCloseStatus::Superseded,
            DisputeOutcome::Attested { .. } => PendingCloseStatus::Claimable,
            DisputeOutcome::Frozen { .. } => PendingCloseStatus::Frozen,
        }
    }

    /// Whether the dispute has reached a terminal state — the arbiter has attested and tombstoned the channel.
    pub fn is_resolved(&self) -> bool {
        matches!(self, DisputeOutcome::Attested { .. } | DisputeOutcome::Frozen { .. })
    }
}

//--------------------------------------------------------------------------------------------------------------------
//                                                Shared behaviour
//--------------------------------------------------------------------------------------------------------------------

/// Everything both sides of a dispute need: the channel's facts, the state this party holds, and the reading of
/// the arbiter's public state that follows from the two.
pub trait ForceCloseProtocolCommon: HasRole {
    /// The channel under dispute.
    fn channel_id(&self) -> ChannelId;

    /// Our channel signing key — the key our half of every [`UpdateRecord`] verifies under.
    fn public_key(&self) -> XmrPoint;

    /// The counterparty's channel signing key.
    fn peer_public_key(&self) -> XmrPoint;

    /// The adjudication window this channel agreed on. Informational on the party side: the arbiter's own
    /// configured window is what actually times the dispute.
    fn dispute_window(&self) -> Duration;

    /// The update count of the state we hold.
    fn update_count(&self) -> u64;

    /// The arbiter's master public key `Z`, as pinned by this channel's configuration. Never read from a reply.
    fn arbiter_master_public_key(&self) -> G2Point;

    /// The cross-signed record for the state we hold — what we present to the arbiter.
    fn latest_record(&self) -> Result<&UpdateRecord, ForceCloseProtocolError>;

    /// The counterparty's offset for the state we hold, verifiably encrypted to `m`. Recovering it is what
    /// completes our close.
    fn peer_binding_proof(&self) -> Result<&BindingProof, ForceCloseProtocolError>;

    /// The counterparty's pre-signature over *our* commitment transaction, adapted by the offset above.
    fn peer_presignature(&self) -> Result<&AdaptedSignature<Ed25519>, ForceCloseProtocolError>;

    /// Where this party currently stands.
    fn status(&self) -> PendingCloseStatus;

    /// Record a new status.
    fn set_status(&mut self, status: PendingCloseStatus);

    /// Record the arbiter's public view: its high-water mark and its window expiry. The expiry is the arbiter
    /// platform's *consensus* time in seconds — never a local clock reading, which an attacker could influence.
    fn note_dispute_state(&mut self, view: &DisputeStateView);

    /// The dispute statement for a state: `m = (channel_id, update_count)`.
    fn statement(&self, update_count: u64) -> Statement {
        statement_for(&self.channel_id(), update_count)
    }

    /// The channel's two signing keys in the order [`UpdateRecord::verify`] expects: customer, then merchant.
    fn record_verification_keys(&self) -> (XmrPoint, XmrPoint) {
        match self.role() {
            ChannelRole::Customer => (self.public_key(), self.peer_public_key()),
            ChannelRole::Merchant => (self.peer_public_key(), self.public_key()),
        }
    }

    /// Run the arbiter's own check over a record: well-formedness plus the two Schnorr verifications.
    ///
    /// Worth running before presenting, because a record the arbiter rejects leaves no state at all — the
    /// dispute simply does not open, and a party that assumed otherwise would wait out a window that never
    /// started.
    fn verify_record(&self, record: &UpdateRecord) -> Result<(), ForceCloseProtocolError> {
        let (pubkey_a, pubkey_b) = self.record_verification_keys();
        record.verify(&pubkey_a, &pubkey_b).map_err(ForceCloseProtocolError::from)
    }

    /// Read the arbiter's public dispute state against the state we hold.
    fn classify(&self, view: &DisputeStateView) -> DisputeOutcome {
        let held = self.update_count();
        match (view.resolved, view.high_water.cmp(&held)) {
            (true, Ordering::Equal) => DisputeOutcome::Attested { update_count: held },
            (true, _) => DisputeOutcome::Frozen { held, attested: view.high_water },
            (false, Ordering::Greater) => DisputeOutcome::Superseded { held, high_water: view.high_water },
            (false, _) => DisputeOutcome::Open { high_water: view.high_water, window_expiry: view.window_expiry },
        }
    }

    /// Fold the arbiter's view into our own status and window, returning what it means for us.
    fn absorb(&mut self, view: &DisputeStateView) -> DisputeOutcome {
        let outcome = self.classify(view);
        self.note_dispute_state(view);
        self.set_status(outcome.status());
        outcome
    }
}

//--------------------------------------------------------------------------------------------------------------------
//                                                   Claimant
//--------------------------------------------------------------------------------------------------------------------

/// The party that opens a dispute, and — if its record is the maximal one — completes the close.
///
/// Every step but the broadcast has a default implementation, because the spec fixes exactly one way to perform
/// each and getting any of them subtly wrong is only discovered when value is at stake.
#[async_trait]
pub trait ForceCloseProtocolClaimant: ForceCloseProtocolCommon + Send + Sync {
    /// Present our latest cross-signed record, opening the adjudication window (or refreshing it, if a lower
    /// record was presented first).
    async fn present_record(&mut self, arbiter: &dyn ArbiterClient) -> Result<DisputeOutcome, ForceCloseProtocolError> {
        let record = self.latest_record()?.clone();
        self.verify_record(&record)?;
        arbiter.submit_dispute(&record).await?;
        self.track_dispute(arbiter).await
    }

    /// Poll the arbiter and fold its answer into our status and window.
    async fn track_dispute(&mut self, arbiter: &dyn ArbiterClient) -> Result<DisputeOutcome, ForceCloseProtocolError> {
        let channel_id = self.channel_id();
        let view = arbiter
            .dispute_state(&channel_id)
            .await?
            .ok_or_else(|| ArbiterError::NoDispute(channel_id.clone()))?;
        Ok(self.absorb(&view))
    }

    /// Collect the attestation of the high-water statement once the window has elapsed.
    ///
    /// Refuses on two counts before it spends a request: while the window is open there is no key to collect,
    /// and once the mark has moved past our state there is no key *for us* — the close we hold is frozen and
    /// asking again will not change that.
    async fn collect_attestation(
        &mut self,
        arbiter: &dyn ArbiterClient,
        transport: &TransportKeyPair,
    ) -> Result<G1Point, ForceCloseProtocolError> {
        match self.track_dispute(arbiter).await? {
            DisputeOutcome::Attested { .. } => (),
            DisputeOutcome::Frozen { held, attested } => {
                return Err(ForceCloseProtocolError::StateSuperseded { held, high_water: attested })
            }
            DisputeOutcome::Superseded { held, high_water } => {
                return Err(ForceCloseProtocolError::StateSuperseded { held, high_water })
            }
            DisputeOutcome::Open { .. } => return Err(ForceCloseProtocolError::DisputeWindowActive),
        }
        let wrapped = arbiter.request_attestation(&self.channel_id(), transport.public_key()).await?;
        let expected = self.statement(self.update_count());
        if wrapped.statement() != &expected {
            return Err(ForceCloseProtocolError::StatementMismatch {
                expected: expected.update_count(),
                actual: wrapped.statement().update_count(),
            });
        }
        // Always through `decrypt_and_verify`: it re-runs the pairing, so nothing that is not an attestation of
        // this exact statement under the pinned Z can reach the recovery below.
        let sigma = transport.unwrap_attestation(&wrapped, &self.arbiter_master_public_key())?;
        Ok(sigma)
    }

    /// Recover the counterparty's offset `ω` from its sealed shares, using the attestation as the decryption key.
    ///
    /// `statement` is explicit rather than read off the proof: `H_F` absorbs `m`, so the proof's ciphertexts
    /// cannot be opened without it and it is not recoverable from them.
    ///
    /// The target check is what makes recovery *actionable* rather than merely successful: the proof must seal
    /// the discrete log of the adaptor point in the pre-signature we are about to complete. A proof that opens
    /// to some other `Q` yields a scalar that adapts nothing.
    fn recover_offset(
        &self,
        proof: &BindingProof,
        statement: &Statement,
        sigma: &G1Point,
    ) -> Result<XmrScalar, ForceCloseProtocolError> {
        let target = self.peer_presignature()?.adapter_commitment();
        if *proof.q() != target {
            return Err(ForceCloseProtocolError::OffsetTargetMismatch);
        }
        binding_proof::recover_offset(proof, statement, sigma).map_err(ForceCloseProtocolError::from)
    }

    /// Complete the counterparty half of the closing signature with the recovered offset.
    ///
    /// The pre-signature we hold covers *our own* commitment transaction — that is the asymmetry of the update
    /// exchange — so the message is the one for `holder = our role`. [`AdaptedSignature::adapt`] verifies the
    /// completed signature before returning it, so a wrong offset fails here rather than at broadcast.
    fn complete_closing_signature(
        &self,
        peer_offset: &XmrScalar,
    ) -> Result<SchnorrSignature<Ed25519>, ForceCloseProtocolError> {
        let msg = commitment_message(&self.channel_id(), self.update_count(), self.role());
        self.peer_presignature()?
            .adapt(peer_offset, &self.peer_public_key(), &msg)
            .map_err(|e| ForceCloseProtocolError::SignatureAdaptationFailed(e.to_string()))
    }

    /// The whole claimant close, once the window has elapsed: collect, recover, complete.
    async fn complete_force_close(
        &mut self,
        arbiter: &dyn ArbiterClient,
        transport: &TransportKeyPair,
    ) -> Result<SchnorrSignature<Ed25519>, ForceCloseProtocolError> {
        let sigma = self.collect_attestation(arbiter, transport).await?;
        let statement = self.statement(self.update_count());
        let proof = self.peer_binding_proof()?.clone();
        let omega = self.recover_offset(&proof, &statement, &sigma)?;
        self.complete_closing_signature(&omega)
    }

    /// Broadcast the completed closing transaction to Monero.
    async fn broadcast_closing_tx(
        &mut self,
        signature: &SchnorrSignature<Ed25519>,
    ) -> Result<TransactionId, ForceCloseProtocolError>;
}

//--------------------------------------------------------------------------------------------------------------------
//                                                  Defendant
//--------------------------------------------------------------------------------------------------------------------

/// The party that discovers a dispute rather than starting one.
///
/// Its only move is supersession: if it holds a later state, it presents that record and the window restarts.
/// There is nothing else to do and nothing to win — no penalty accrues to the party that presented the stale
/// record, and no offset changes hands.
#[async_trait]
pub trait ForceCloseProtocolDefendant: ForceCloseProtocolCommon + Send + Sync {
    /// Poll the arbiter for a dispute on this channel. `None` means none has been opened.
    async fn watch_for_dispute(
        &mut self,
        arbiter: &dyn ArbiterClient,
    ) -> Result<Option<DisputeOutcome>, ForceCloseProtocolError> {
        let view = arbiter.dispute_state(&self.channel_id()).await?;
        Ok(view.map(|view| self.absorb(&view)))
    }

    /// The arbiter's public, append-only action log for this channel — the other half of the watching duty.
    async fn dispute_log(&self, arbiter: &dyn ArbiterClient) -> Result<Vec<ActionLogEntry>, ForceCloseProtocolError> {
        arbiter.action_log(&self.channel_id()).await.map_err(ForceCloseProtocolError::from)
    }

    /// Whether we hold a state strictly later than the one presented. Counts may skip, so this is a comparison,
    /// never an increment check.
    fn has_more_recent_state(&self, claimed_count: u64) -> bool {
        self.update_count() > claimed_count
    }

    /// Present our later record, advancing the high-water mark and restarting the window.
    async fn present_newer_record(
        &mut self,
        arbiter: &dyn ArbiterClient,
        claimed_count: u64,
    ) -> Result<DisputeOutcome, ForceCloseProtocolError> {
        if !self.has_more_recent_state(claimed_count) {
            return Err(ForceCloseProtocolError::UpdateCountTooLow {
                claimed: claimed_count,
                actual: self.update_count(),
            });
        }
        let record = self.latest_record()?.clone();
        self.verify_record(&record)?;
        arbiter.submit_dispute(&record).await?;
        let view = arbiter
            .dispute_state(&self.channel_id())
            .await?
            .ok_or_else(|| ArbiterError::NoDispute(self.channel_id()))?;
        Ok(self.absorb(&view))
    }

    /// One step of the watching duty: look, and answer if we can.
    ///
    /// `None` means there is nothing open to answer. Otherwise the returned outcome is where the dispute stands
    /// *after* any supersession we performed — so a defendant that answered sees the window restarted at its own
    /// state, and one that had nothing newer sees the dispute unchanged.
    async fn answer_dispute(
        &mut self,
        arbiter: &dyn ArbiterClient,
    ) -> Result<Option<DisputeOutcome>, ForceCloseProtocolError> {
        let Some(outcome) = self.watch_for_dispute(arbiter).await? else { return Ok(None) };
        match outcome {
            DisputeOutcome::Open { high_water, .. } if self.has_more_recent_state(high_water) => {
                self.present_newer_record(arbiter, high_water).await.map(Some)
            }
            _ => Ok(Some(outcome)),
        }
    }
}

//--------------------------------------------------------------------------------------------------------------------
//                                                    Errors
//--------------------------------------------------------------------------------------------------------------------

/// Errors that can occur during the force close protocol.
#[derive(Debug, Error)]
pub enum ForceCloseProtocolError {
    #[error("Channel not found: {0}")]
    ChannelNotFound(String),

    #[error("Channel not in force-closeable state: {0}")]
    InvalidChannelState(String),

    #[error("Missing required information: {0}")]
    MissingInformation(String),

    #[error("Dispute window has not elapsed")]
    DisputeWindowActive,

    #[error("No pending force close")]
    NoPendingForceClose,

    /// A higher record was presented, so nothing will ever be attested for the state we hold. Terminal: the
    /// close we were pursuing is frozen, and no penalty follows from it.
    #[error("State {held} was superseded by state {high_water}; nothing is released for it")]
    StateSuperseded { held: u64, high_water: u64 },

    /// The arbiter answered with an attestation of a statement we did not ask about.
    #[error("The arbiter attested state {actual}, not the requested {expected}")]
    StatementMismatch { expected: u64, actual: u64 },

    /// The retained binding proof does not seal the offset that opens the pre-signature we hold, so recovering
    /// it would produce a scalar that adapts nothing.
    #[error("The retained binding proof does not target the adaptor point of the pre-signature to complete")]
    OffsetTargetMismatch,

    #[error("Failed to recover the offset: {0}")]
    OffsetRecovery(#[from] BindingProofError),

    #[error("Failed to complete the closing signature: {0}")]
    SignatureAdaptationFailed(String),

    #[error("Transaction creation failed: {0}")]
    TransactionCreationFailed(String),

    #[error("Transaction broadcast failed: {0}")]
    BroadcastFailed(String),

    #[error("Invalid update record: {0}")]
    InvalidUpdateRecord(#[from] UpdateRecordError),

    #[error("Update count too low: claimed {claimed}, actual {actual}")]
    UpdateCountTooLow { claimed: u64, actual: u64 },

    #[error("Arbiter error: {0}")]
    Arbiter(#[from] ArbiterError),

    #[error("Serialization error: {0}")]
    SerializationError(String),
}
