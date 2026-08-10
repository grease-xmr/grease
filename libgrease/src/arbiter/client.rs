//! The client-side view of an arbiter: the [`ArbiterClient`] trait and the objects it exchanges.
//!
//! The trait is deliberately small — everything a disputing party needs and nothing more (see
//! `docs/src/40_arbiter.typ` §stateMachine and §disputeFlow):
//!
//! 1. **Pin the master key.** Offsets are sealed to `Z` at *update* time, long before any dispute, so a party must
//!    fetch `Z` once and compare it against the [`ArbiterConfiguration`] it agreed to. [`ArbiterClient::verify_pinned_master_key`]
//!    is that check.
//! 2. **Present a record.** [`ArbiterClient::submit_dispute`] hands over the latest cross-signed [`UpdateRecord`];
//!    the arbiter validates it, and if its count is above the high-water mark, advances the mark and restarts the
//!    window.
//! 3. **Watch.** Both parties poll [`ArbiterClient::dispute_state`] and [`ArbiterClient::action_log`] — the
//!    watching duty of §disputeFlow. A defendant that sees a presentation below its own latest state answers with
//!    the higher record.
//! 4. **Collect.** After the window elapses, [`ArbiterClient::request_attestation`] returns the attestation of the
//!    high-water statement, wrapped to a caller-supplied transport key (vetKD delivers it blinded so only the
//!    requester learns it). [`TransportKeyPair`] generates that key and unwraps the reply back to `σ_m`.
//!
//! Note what is absent: nothing here creates a channel, holds a secret, or moves value. The production ICP client
//! is an implementation of this trait over `ic-agent`, and is out of scope for the KES→arbiter migration.

use async_trait::async_trait;
use ic_vetkeys::{DerivedPublicKey, EncryptedVetKey, TransportSecretKey};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Formatter};
use thiserror::Error;

use crate::arbiter::config::ArbiterConfiguration;
use crate::channel_id::{ChannelId, ProvisionalChannelIdError};
use crate::cryptography::attestation::{AttestationError, G1Point, G2Point, Statement};
use crate::grease_protocol::update_record::UpdateRecord;

/// The dispute statement for a channel state: `m = (channel_id, update_count)`.
///
/// This is the single place the protocol turns a [`ChannelId`] into the [`Statement`] bytes the arbiter attests
/// and offsets are encrypted to. The channel id is absorbed as its canonical `XGC…` string; both the encryptor and
/// the arbiter must derive `m` this way or dispute-path decryption silently fails.
///
/// A provisional (`XGT…`) id is refused: it commits to no funding output, so a statement over it — and everything
/// sealed to that statement — would not be bound to one channel. The id can reach here from a peer or arbiter
/// message (a presented record, a dispute-state reply), which is why this is a `Result` rather than an assertion.
pub fn statement_for(channel_id: &ChannelId, update_count: u64) -> Result<Statement, ProvisionalChannelIdError> {
    channel_id.require_finalized()?;
    Ok(Statement::new(channel_id.as_str().as_bytes().to_vec(), update_count))
}

//--------------------------------------------------------------------------------------------------------------------
//                                                     Errors
//--------------------------------------------------------------------------------------------------------------------

/// Failures a party can see when talking to an arbiter.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ArbiterError {
    /// The arbiter rejected the record: it is malformed or a signature does not verify.
    #[error("the arbiter rejected the record as invalid: {0}")]
    InvalidRecord(String),
    /// The channel is unknown to the arbiter — it was never registered with it.
    #[error("the arbiter does not know channel {0}")]
    UnknownChannel(ChannelId),
    /// The channel id is already registered. Registration is once-per-channel and never overwrites — an identical
    /// duplicate is refused too, because it is the observable signature of two channels colliding on one id.
    #[error("channel {0} is already registered with the arbiter; registration is once per channel")]
    AlreadyRegistered(ChannelId),
    /// The channel id is provisional (`XGT…`): it commits to no funding output, so nothing registrable exists and
    /// no statement can be formed — let alone attested — over it.
    #[error(transparent)]
    ProvisionalChannelId(#[from] ProvisionalChannelIdError),
    /// The channel is tombstoned: it was already resolved and cannot be disputed again.
    #[error("channel {0} has already been resolved; it cannot be disputed again")]
    AlreadyResolved(ChannelId),
    /// No dispute has been opened on this channel, so there is nothing to poll or collect.
    #[error("no dispute is open on channel {0}")]
    NoDispute(ChannelId),
    /// The adjudication window has not elapsed yet, so no attestation exists.
    #[error("the adjudication window on channel {channel_id} has not elapsed: {remaining_secs}s remaining")]
    WindowNotElapsed { channel_id: ChannelId, remaining_secs: u64 },
    /// The master key the arbiter serves is not the one this channel's configuration pinned.
    #[error("the arbiter's master public key does not match the pinned configuration")]
    MasterKeyMismatch,
    /// A point or attestation the arbiter returned did not decode or verify.
    #[error("attestation error: {0}")]
    Attestation(#[from] AttestationError),
    /// The reply is wrapped to a transport key other than the one this party holds the secret for.
    #[error("the attestation is wrapped to a different transport key than the one it was requested with")]
    TransportKeyMismatch,
    /// The wrapped payload did not decrypt, or what came out was not an attestation of the statement it claims.
    #[error("the wrapped attestation did not unwrap to a valid attestation: {0}")]
    UnwrapFailed(String),
    /// The transport could not reach the arbiter, or the reply was unintelligible.
    #[error("arbiter transport failure: {0}")]
    Transport(String),
}

//--------------------------------------------------------------------------------------------------------------------
//                                              Dispute state and log
//--------------------------------------------------------------------------------------------------------------------

/// The arbiter's public per-channel dispute state, as a watching party sees it.
///
/// Every field is non-secret by construction: the arbiter knows only an opaque id, a count, and a close hash.
/// Timestamps are the arbiter platform's consensus time in whole seconds since the Unix epoch — never a local
/// wall-clock reading.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisputeStateView {
    /// The channel under dispute.
    pub channel_id: ChannelId,
    /// The highest update count anyone has successfully presented. Monotonically increasing.
    pub high_water: u64,
    /// Consensus time at which the current adjudication window closes. Restarted whenever the high-water mark
    /// advances.
    pub window_expiry: u64,
    /// Whether the arbiter has attested and tombstoned this channel.
    pub resolved: bool,
}

impl DisputeStateView {
    /// The statement the arbiter will attest (or has attested): `m = (channel_id, high_water)`.
    ///
    /// The id in this view arrived in an arbiter reply, so a provisional one is refused rather than trusted.
    pub fn high_water_statement(&self) -> Result<Statement, ProvisionalChannelIdError> {
        statement_for(&self.channel_id, self.high_water)
    }

    /// Seconds remaining until the window closes at consensus time `now`; zero once it has elapsed.
    pub fn remaining_secs(&self, now: u64) -> u64 {
        self.window_expiry.saturating_sub(now)
    }
}

/// A kind of entry in the arbiter's public, append-only action log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LogAction {
    /// A record was accepted and advanced the high-water mark to this count.
    RecordPresented(u64),
    /// A record at this count was presented but did not beat the high-water mark, so it was ignored.
    StaleRecordIgnored(u64),
    /// The window elapsed and the arbiter attested the statement at this high-water mark.
    Attested(u64),
}

impl LogAction {
    /// The update count this entry speaks about.
    pub fn update_count(&self) -> u64 {
        match self {
            LogAction::RecordPresented(n) | LogAction::StaleRecordIgnored(n) | LogAction::Attested(n) => *n,
        }
    }
}

/// One entry in the arbiter's public action log, stamped with the consensus time it was appended at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionLogEntry {
    /// What happened.
    pub action: LogAction,
    /// Consensus time (Unix seconds) at which the arbiter appended this entry.
    pub at: u64,
}

impl ActionLogEntry {
    /// Build a log entry.
    pub fn new(action: LogAction, at: u64) -> Self {
        ActionLogEntry { action, at }
    }
}

//--------------------------------------------------------------------------------------------------------------------
//                                            Transport-wrapped delivery
//--------------------------------------------------------------------------------------------------------------------

/// A caller-supplied transport public key. vetKD encrypts the derived key under it so that only the requester
/// learns the attestation, even though the request itself is a public canister call.
///
/// The bytes are opaque here: their format is the vetKD transport-key encoding, and the keypair generation and
/// unwrap helpers arrive with the dispute-rewire work. This module only carries them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportPublicKey(#[serde(with = "hex::serde")] Vec<u8>);

impl TransportPublicKey {
    /// Wrap raw transport-key bytes.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        TransportPublicKey(bytes.into())
    }

    /// The raw transport-key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// An attestation as the arbiter delivers it: encrypted under the transport key it was requested with.
///
/// The payload is a serialized vetKD `EncryptedVetKey`; [`TransportKeyPair::unwrap_attestation`] turns it back
/// into the 48-byte G1 signature `σ_m`. It also records which statement it answers, so a caller can tell a stale
/// reply from a current one before spending a pairing on it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrappedAttestation {
    /// The statement `m = (channel_id, high_water)` this attestation answers.
    statement: Statement,
    /// The transport key the payload is wrapped to.
    transport_public_key: TransportPublicKey,
    /// The wrapped attestation payload.
    #[serde(with = "hex::serde")]
    payload: Vec<u8>,
}

impl WrappedAttestation {
    /// Build a wrapped attestation from its parts.
    pub fn new(statement: Statement, transport_public_key: TransportPublicKey, payload: impl Into<Vec<u8>>) -> Self {
        WrappedAttestation { statement, transport_public_key, payload: payload.into() }
    }

    /// The statement this attestation answers.
    pub fn statement(&self) -> &Statement {
        &self.statement
    }

    /// The transport key the payload is wrapped to.
    pub fn transport_public_key(&self) -> &TransportPublicKey {
        &self.transport_public_key
    }

    /// The wrapped payload.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

/// The transport keypair a party generates for one attestation request, and the only way to unwrap the reply.
///
/// vetKD encrypts the derived key under a caller-supplied G1 transport key precisely because the request is a
/// public canister call: without it, every observer of the arbiter chain would learn `σ_m` and could complete any
/// close sealed to that statement. Generate one per request and keep the secret local — it never leaves the party.
///
/// # Always through `decrypt_and_verify`
///
/// [`unwrap_attestation`](TransportKeyPair::unwrap_attestation) goes through `EncryptedVetKey::decrypt_and_verify`
/// and nothing lower. That call does two things a raw subtraction does not: it checks `c1` and `c2` share a
/// discrete logarithm (so a malformed ciphertext cannot steer the result), and it re-verifies the recovered point
/// as a BLS signature on the statement under `Z`. NCC finding **D7X** is exactly the hazard of skipping that —
/// low-level BLS paths that omit the identity and subgroup checks accept points that are not attestations at all.
/// A `σ_m` that reached [`recover_offset`](crate::cryptography::binding_proof::recover_offset) unverified would
/// silently fail to open the sealed shares, or worse, be an attacker-chosen point.
#[derive(Clone)]
pub struct TransportKeyPair {
    secret: TransportSecretKey,
    public: TransportPublicKey,
}

impl TransportKeyPair {
    /// Generate a fresh transport keypair.
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        TransportKeyPair::from_seed(seed)
    }

    /// Derive a transport keypair from a 32-byte seed. Deterministic, so a party that must survive a restart
    /// mid-dispute can re-derive the key its pending request was wrapped to.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        // The only failure mode `from_seed` documents is a seed that is not 32 bytes, which the type forbids.
        let secret = TransportSecretKey::from_seed(seed.to_vec()).expect("a 32-byte seed is always accepted");
        let public = TransportPublicKey::new(secret.public_key());
        TransportKeyPair { secret, public }
    }

    /// The public half, to hand to [`ArbiterClient::request_attestation`].
    pub fn public_key(&self) -> &TransportPublicKey {
        &self.public
    }

    /// Unwrap a delivered attestation back to `σ_m`, verifying it against the master key on the way out.
    ///
    /// `master_public_key` is the `Z` the channel pinned — not one read from the reply — so a wrapped payload
    /// from an arbiter serving a different key cannot pass.
    pub fn unwrap_attestation(
        &self,
        wrapped: &WrappedAttestation,
        master_public_key: &G2Point,
    ) -> Result<G1Point, ArbiterError> {
        if wrapped.transport_public_key() != &self.public {
            return Err(ArbiterError::TransportKeyMismatch);
        }
        let dpk = DerivedPublicKey::deserialize(&master_public_key.to_compressed())
            .map_err(|e| ArbiterError::UnwrapFailed(format!("master public key is not a vetKD derived key: {e:?}")))?;
        let encrypted = EncryptedVetKey::deserialize(wrapped.payload()).map_err(ArbiterError::UnwrapFailed)?;
        let vetkey = encrypted
            .decrypt_and_verify(&self.secret, &dpk, &wrapped.statement().to_bytes())
            .map_err(ArbiterError::UnwrapFailed)?;
        G1Point::from_compressed(vetkey.signature_bytes()).map_err(ArbiterError::from)
    }
}

impl Debug for TransportKeyPair {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "TransportKeyPair({})", hex::encode(self.public.as_bytes()))
    }
}

//--------------------------------------------------------------------------------------------------------------------
//                                                  The trait
//--------------------------------------------------------------------------------------------------------------------

/// The minimal surface a Grease party needs from an arbiter.
///
/// Implementations are shared across tasks (a watching party polls while a closing party collects), hence the
/// `&self` receivers and the `Send + Sync` bound.
#[async_trait]
pub trait ArbiterClient: Send + Sync {
    /// The configuration this client is pinned to — the one both parties agreed on at proposal time.
    fn configuration(&self) -> &ArbiterConfiguration;

    /// Fetch the master public key `Z` the arbiter is actually serving.
    async fn master_public_key(&self) -> Result<G2Point, ArbiterError>;

    /// Present a cross-signed record. The arbiter validates it (two Schnorr checks plus well-formedness) and, if
    /// its count beats the high-water mark, advances the mark and restarts the adjudication window. A stale record
    /// is accepted but ignored, leaving a `StaleRecordIgnored` entry in the log.
    async fn submit_dispute(&self, record: &UpdateRecord) -> Result<(), ArbiterError>;

    /// The current public dispute state for a channel, or `None` if no dispute has been opened on it.
    async fn dispute_state(&self, channel_id: &ChannelId) -> Result<Option<DisputeStateView>, ArbiterError>;

    /// The channel's public action log, oldest first. Empty if no dispute has been opened.
    async fn action_log(&self, channel_id: &ChannelId) -> Result<Vec<ActionLogEntry>, ArbiterError>;

    /// Request the attestation of the high-water statement, delivered wrapped to `transport_public_key`.
    ///
    /// Fails with [`ArbiterError::WindowNotElapsed`] while the window is still open: the whole point of the window
    /// is that no key exists before it closes.
    async fn request_attestation(
        &self,
        channel_id: &ChannelId,
        transport_public_key: &TransportPublicKey,
    ) -> Result<WrappedAttestation, ArbiterError>;

    /// Check that the arbiter serves the master key this client's configuration pinned.
    ///
    /// Worth doing before sealing the first offset: an offset encrypted to the wrong `Z` is unrecoverable, and the
    /// failure would only surface in a dispute, when it is too late.
    async fn verify_pinned_master_key(&self) -> Result<(), ArbiterError> {
        let served = self.master_public_key().await?;
        match served == *self.configuration().master_public_key() {
            true => Ok(()),
            false => Err(ArbiterError::MasterKeyMismatch),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn channel_id() -> ChannelId {
        ChannelId::from_str("XGC4a7024e7fd6f5c6a2d0131d12fd91ecd17f5da61c2970d603a05053b41a383").unwrap()
    }

    #[test]
    fn statement_binds_the_channel_id_string_and_count() {
        let m = statement_for(&channel_id(), 7).expect("a final id yields a statement");
        assert_eq!(m.channel_id(), channel_id().as_str().as_bytes());
        assert_eq!(m.update_count(), 7);
        assert_ne!(m, statement_for(&channel_id(), 8).unwrap());
    }

    /// F2 of the K-20 review: a provisional id must be refused at the boundary that turns an id into the
    /// statement bytes offsets are sealed to and the arbiter attests.
    #[test]
    fn a_provisional_channel_id_yields_no_statement() {
        let provisional =
            ChannelId::from_str("XGT4a7024e7fd6f5c6a2d0131d12fd91ecd17f5da61c2970d603a05053b41a383").unwrap();
        let err = statement_for(&provisional, 7).expect_err("a provisional id must be refused");
        assert_eq!(err.0, provisional);

        // The same refusal surfaces through a dispute-state view carrying an arbiter-supplied id.
        let view = DisputeStateView { channel_id: provisional, high_water: 7, window_expiry: 1_000, resolved: false };
        assert!(view.high_water_statement().is_err());
    }

    #[test]
    fn dispute_state_view_reports_remaining_time() {
        let view = DisputeStateView { channel_id: channel_id(), high_water: 4, window_expiry: 1_000, resolved: false };
        assert_eq!(view.remaining_secs(400), 600);
        assert_eq!(view.remaining_secs(1_000), 0);
        assert_eq!(view.remaining_secs(5_000), 0);
        assert_eq!(view.high_water_statement().unwrap(), statement_for(&channel_id(), 4).unwrap());
    }

    #[test]
    fn log_actions_expose_their_count() {
        assert_eq!(LogAction::RecordPresented(3).update_count(), 3);
        assert_eq!(LogAction::StaleRecordIgnored(1).update_count(), 1);
        assert_eq!(LogAction::Attested(9).update_count(), 9);
    }

    #[test]
    fn wire_types_round_trip() {
        let view = DisputeStateView { channel_id: channel_id(), high_water: 4, window_expiry: 1_000, resolved: true };
        let json = serde_json::to_string(&view).unwrap();
        assert_eq!(serde_json::from_str::<DisputeStateView>(&json).unwrap(), view);

        let entry = ActionLogEntry::new(LogAction::Attested(4), 1_000);
        let json = serde_json::to_string(&entry).unwrap();
        assert_eq!(serde_json::from_str::<ActionLogEntry>(&json).unwrap(), entry);

        let wrapped = WrappedAttestation::new(
            statement_for(&channel_id(), 4).unwrap(),
            TransportPublicKey::new(vec![1, 2, 3]),
            vec![9u8; 48],
        );
        let json = serde_json::to_string(&wrapped).unwrap();
        assert_eq!(serde_json::from_str::<WrappedAttestation>(&json).unwrap(), wrapped);
    }
}
