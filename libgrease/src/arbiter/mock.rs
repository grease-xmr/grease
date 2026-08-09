//! An in-process arbiter: the dispute state machine of `docs/src/40_arbiter.typ` §stateMachine, minus the
//! consensus platform.
//!
//! [`MockArbiter`] implements [`ArbiterClient`] exactly as the specified algorithms `onPresentRecord` and
//! `onWindowElapsed` describe, so protocol tests exercise real arbiter *semantics* — window restart on
//! supersession, stale records ignored but logged, no key before expiry, a tombstone that forbids re-dispute —
//! without an ICP replica. What it does *not* model is the threshold: it holds the master secret `z` whole and
//! signs `σ_m = z·H_P(m)` itself, where production splits `z` across a committee that never reassembles it. That
//! is the one and only cheat, and it is invisible to callers: the attestation it produces verifies under `Z` and
//! decrypts sealed offsets identically.
//!
//! # The clock is injected, not read
//!
//! The spec anchors window expiry to the platform's *consensus* time precisely because a wall-clock is
//! attacker-influenceable. This mock therefore never calls `SystemTime::now()`: it reads a [`Clock`], and
//! [`ManualClock`] lets a test advance time deterministically. There is no timer thread either — the canister
//! timer of `onWindowElapsed` is modelled by evaluating expiry lazily on every read, which is observationally
//! identical for a polling client.

use async_trait::async_trait;
use ciphersuite::group::ff::Field;
use ic_bls12_381::{G1Affine, G1Projective, G2Affine, Scalar as BlsScalar};
use rand_core::{CryptoRng, OsRng, RngCore};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::arbiter::client::{
    statement_for, ActionLogEntry, ArbiterClient, ArbiterError, DisputeStateView, LogAction, TransportPublicKey,
    WrappedAttestation,
};
use crate::arbiter::config::{ArbiterConfiguration, DEFAULT_DISPUTE_WINDOW};
use crate::channel_id::ChannelId;
use crate::cryptography::attestation::test_helpers::{attest, generate_master_keypair, master_public_key};
use crate::cryptography::attestation::{G1Point, G2Point};
use crate::grease_protocol::update_record::UpdateRecord;
use crate::XmrPoint;

//--------------------------------------------------------------------------------------------------------------------
//                                                     Clock
//--------------------------------------------------------------------------------------------------------------------

/// The arbiter's clock: consensus time in whole seconds since the Unix epoch.
///
/// Injected rather than read from the host, because the window's integrity depends on the clock being one a single
/// operator cannot move.
pub trait Clock: Send + Sync {
    /// The current consensus time, in Unix seconds.
    fn now(&self) -> u64;
}

/// A clock a test drives by hand. Starts at an arbitrary but fixed epoch and only ever moves when told to.
#[derive(Debug)]
pub struct ManualClock(AtomicU64);

impl ManualClock {
    /// A clock reading `start` Unix seconds.
    pub fn new(start: u64) -> Self {
        ManualClock(AtomicU64::new(start))
    }

    /// Move the clock forward by `by`.
    pub fn advance(&self, by: Duration) {
        self.0.fetch_add(by.as_secs(), Ordering::SeqCst);
    }

    /// Jump the clock to an absolute time.
    pub fn set(&self, to: u64) {
        self.0.store(to, Ordering::SeqCst);
    }
}

impl Default for ManualClock {
    fn default() -> Self {
        // An arbitrary non-zero epoch, so a test that forgets to advance cannot pass by accident on a zero clock.
        ManualClock::new(1_700_000_000)
    }
}

impl Clock for ManualClock {
    fn now(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

//--------------------------------------------------------------------------------------------------------------------
//                                                 Internal state
//--------------------------------------------------------------------------------------------------------------------

/// The two signing keys the arbiter checks a record's signatures against. Production registers these when the
/// channel is opened with the arbiter; the mock takes them from [`MockArbiter::register_channel`].
#[derive(Debug, Clone, Copy)]
struct ChannelRegistration {
    pubkey_a: XmrPoint,
    pubkey_b: XmrPoint,
}

/// The arbiter's per-channel dispute state: a high-water mark, a window, a tombstone, and a log. All non-secret.
#[derive(Debug, Clone)]
struct DisputeState {
    high_water: u64,
    window_expiry: u64,
    resolved: bool,
    log: Vec<ActionLogEntry>,
}

impl DisputeState {
    fn view(&self, channel_id: &ChannelId) -> DisputeStateView {
        DisputeStateView {
            channel_id: channel_id.clone(),
            high_water: self.high_water,
            window_expiry: self.window_expiry,
            resolved: self.resolved,
        }
    }
}

//--------------------------------------------------------------------------------------------------------------------
//                                                  MockArbiter
//--------------------------------------------------------------------------------------------------------------------

/// An in-process arbiter holding the master secret whole. Test and development use only.
pub struct MockArbiter {
    config: ArbiterConfiguration,
    master_secret: BlsScalar,
    clock: Arc<dyn Clock>,
    channels: Mutex<HashMap<ChannelId, ChannelRegistration>>,
    disputes: Mutex<HashMap<ChannelId, DisputeState>>,
}

impl MockArbiter {
    /// Build an arbiter around an existing master secret. `config.master_public_key` must be `z·G_2`; use
    /// [`MockArbiter::generate`] to avoid getting that wrong.
    pub fn new(config: ArbiterConfiguration, master_secret: BlsScalar, clock: Arc<dyn Clock>) -> Self {
        MockArbiter {
            config,
            master_secret,
            clock,
            channels: Mutex::new(HashMap::new()),
            disputes: Mutex::new(HashMap::new()),
        }
    }

    /// Generate a fresh master key and build an arbiter with a matching configuration.
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R, dispute_window: Duration, clock: Arc<dyn Clock>) -> Self {
        let (z, big_z) = generate_master_keypair(rng);
        let config = ArbiterConfiguration::new(big_z, "mock-arbiter", dispute_window);
        MockArbiter::new(config, z, clock)
    }

    /// Generate a fresh arbiter with the default 24-hour window and a [`ManualClock`], returning the clock so a
    /// test can drive it.
    pub fn with_manual_clock<R: RngCore + CryptoRng>(rng: &mut R) -> (Self, Arc<ManualClock>) {
        let clock = Arc::new(ManualClock::default());
        let arbiter = MockArbiter::generate(rng, DEFAULT_DISPUTE_WINDOW, clock.clone());
        (arbiter, clock)
    }

    /// Register a channel's two signing keys, so presented records can be verified. In production this happens
    /// when the channel is opened with the arbiter.
    pub fn register_channel(&self, channel_id: ChannelId, pubkey_a: XmrPoint, pubkey_b: XmrPoint) {
        self.channels.lock().unwrap().insert(channel_id, ChannelRegistration { pubkey_a, pubkey_b });
    }

    /// The master secret `z`. Test-only by construction — production `z` exists only as committee shares.
    pub fn master_secret(&self) -> &BlsScalar {
        &self.master_secret
    }

    /// The master public key `Z = z·G_2`, recomputed from the secret.
    pub fn master_public_key(&self) -> G2Point {
        master_public_key(&self.master_secret)
    }

    /// The clock this arbiter reads.
    pub fn clock(&self) -> &Arc<dyn Clock> {
        &self.clock
    }

    /// `onPresentRecord`: validate, then advance-and-restart or log-and-ignore.
    fn on_present_record(&self, record: &UpdateRecord) -> Result<(), ArbiterError> {
        let channel_id = record.channel_id().clone();
        let registration = self
            .channels
            .lock()
            .unwrap()
            .get(&channel_id)
            .copied()
            .ok_or_else(|| ArbiterError::UnknownChannel(channel_id.clone()))?;
        // The arbiter's entire check: well-formedness plus the two Schnorr verifications.
        record
            .verify(&registration.pubkey_a, &registration.pubkey_b)
            .map_err(|e| ArbiterError::InvalidRecord(format!("{e}")))?;

        let now = self.clock.now();
        let mut disputes = self.disputes.lock().unwrap();
        // Created lazily on first presentation: a channel that never disputes costs the arbiter nothing.
        let state = disputes.entry(channel_id.clone()).or_insert_with(|| DisputeState {
            high_water: 0,
            window_expiry: now,
            resolved: false,
            log: Vec::new(),
        });
        if state.resolved {
            return Err(ArbiterError::AlreadyResolved(channel_id));
        }
        let count = record.update_count();
        // Strictly greater, and gaps are legal — the count need not increment by one.
        let supersedes = state.log.is_empty() || count > state.high_water;
        match supersedes {
            true => {
                state.high_water = count;
                state.window_expiry = now + self.config.dispute_window_secs();
                state.log.push(ActionLogEntry::new(LogAction::RecordPresented(count), now));
            }
            false => state.log.push(ActionLogEntry::new(LogAction::StaleRecordIgnored(count), now)),
        }
        Ok(())
    }

    /// `onWindowElapsed`, evaluated lazily: if the window has closed on an unresolved dispute, log the attestation
    /// and set the tombstone. Idempotent, and a no-op while the window is open.
    fn poll_window(&self, channel_id: &ChannelId) {
        let now = self.clock.now();
        let mut disputes = self.disputes.lock().unwrap();
        let Some(state) = disputes.get_mut(channel_id) else { return };
        if state.resolved || now < state.window_expiry {
            return;
        }
        state.log.push(ActionLogEntry::new(LogAction::Attested(state.high_water), now));
        state.resolved = true;
    }

    /// The attestation of a channel's high-water statement, unwrapped — the object the dispute path ultimately
    /// needs. Only available once the window has elapsed.
    pub fn attestation(&self, channel_id: &ChannelId) -> Result<G1Point, ArbiterError> {
        self.poll_window(channel_id);
        let disputes = self.disputes.lock().unwrap();
        let state = disputes.get(channel_id).ok_or_else(|| ArbiterError::NoDispute(channel_id.clone()))?;
        if !state.resolved {
            return Err(ArbiterError::WindowNotElapsed {
                channel_id: channel_id.clone(),
                remaining_secs: state.window_expiry.saturating_sub(self.clock.now()),
            });
        }
        Ok(attest(&self.master_secret, &statement_for(channel_id, state.high_water)))
    }
}

/// Encrypt `sigma` to a caller's transport key in the vetKD `EncryptedVetKey` wire format.
///
/// This is the subnet's side of the blinded delivery, and the mock performs it for real so that the party side
/// exercises `EncryptedVetKey::decrypt_and_verify` rather than a shortcut. The ciphertext is the scheme's own
/// `(c1, c2, c3) = (r·G_1, r·G_2, σ + r·T)` for a fresh `r` and the caller's `T = t·G_1`; the recipient recovers
/// `σ = c3 − t·c1`, and `c2` is what lets it check `c1` was formed honestly.
fn wrap_for_transport(sigma: &G1Point, transport_public_key: &TransportPublicKey) -> Result<Vec<u8>, ArbiterError> {
    let bytes: [u8; 48] = transport_public_key.as_bytes().try_into().map_err(|_| {
        ArbiterError::Transport(format!(
            "transport public key is {} bytes, expected 48",
            transport_public_key.as_bytes().len()
        ))
    })?;
    let t = Option::<G1Affine>::from(G1Affine::from_compressed(&bytes))
        .ok_or_else(|| ArbiterError::Transport("transport public key is not a valid G1 point".into()))?;
    let r = BlsScalar::random(&mut OsRng);
    let c1 = G1Affine::from(G1Affine::generator() * r);
    let c2 = G2Affine::from(G2Affine::generator() * r);
    let c3 = G1Affine::from(G1Projective::from(sigma.as_affine()) + t * r);
    Ok([c1.to_compressed().as_slice(), c2.to_compressed().as_slice(), c3.to_compressed().as_slice()].concat())
}

#[async_trait]
impl ArbiterClient for MockArbiter {
    fn configuration(&self) -> &ArbiterConfiguration {
        &self.config
    }

    async fn master_public_key(&self) -> Result<G2Point, ArbiterError> {
        Ok(MockArbiter::master_public_key(self))
    }

    async fn submit_dispute(&self, record: &UpdateRecord) -> Result<(), ArbiterError> {
        // A window that closed before this call must resolve first, so a late record cannot reopen a dispute.
        self.poll_window(record.channel_id());
        self.on_present_record(record)
    }

    async fn dispute_state(&self, channel_id: &ChannelId) -> Result<Option<DisputeStateView>, ArbiterError> {
        self.poll_window(channel_id);
        Ok(self.disputes.lock().unwrap().get(channel_id).map(|s| s.view(channel_id)))
    }

    async fn action_log(&self, channel_id: &ChannelId) -> Result<Vec<ActionLogEntry>, ArbiterError> {
        self.poll_window(channel_id);
        Ok(self.disputes.lock().unwrap().get(channel_id).map(|s| s.log.clone()).unwrap_or_default())
    }

    async fn request_attestation(
        &self,
        channel_id: &ChannelId,
        transport_public_key: &TransportPublicKey,
    ) -> Result<WrappedAttestation, ArbiterError> {
        let sigma = self.attestation(channel_id)?;
        let high_water = self
            .disputes
            .lock()
            .unwrap()
            .get(channel_id)
            .map(|s| s.high_water)
            .ok_or_else(|| ArbiterError::NoDispute(channel_id.clone()))?;
        let statement = statement_for(channel_id, high_water);
        let payload = wrap_for_transport(&sigma, transport_public_key)?;
        Ok(WrappedAttestation::new(statement, transport_public_key.clone(), payload))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arbiter::client::TransportKeyPair;
    use crate::cryptography::attestation::verify_attestation;
    use crate::grease_protocol::update_record::{CloseHash, HalfSignedUpdateRecord, CLOSE_HASH_LEN};
    use crate::payment_channel::ChannelRole;
    use crate::XmrScalar;
    use ciphersuite::group::ff::Field;
    use ciphersuite::{Ciphersuite, Ed25519};
    use rand_chacha::ChaCha20Rng;
    use rand_core::{OsRng, SeedableRng};
    use std::str::FromStr;

    const DAY: Duration = Duration::from_secs(86_400);

    fn channel_id() -> ChannelId {
        ChannelId::from_str("XGC4a7024e7fd6f5c6a2d0131d12fd91ecd17f5da61c2970d603a05053b41a383").unwrap()
    }

    /// The two channel parties, and a factory for cross-signed records at any update count.
    struct Parties {
        secret_a: XmrScalar,
        pubkey_a: XmrPoint,
        secret_b: XmrScalar,
        pubkey_b: XmrPoint,
    }

    impl Parties {
        fn new() -> Self {
            let secret_a = XmrScalar::random(&mut OsRng);
            let secret_b = XmrScalar::random(&mut OsRng);
            Parties {
                pubkey_a: Ed25519::generator() * secret_a,
                secret_a,
                pubkey_b: Ed25519::generator() * secret_b,
                secret_b,
            }
        }

        fn record(&self, update_count: u64) -> UpdateRecord {
            let half = HalfSignedUpdateRecord::sign(
                channel_id(),
                update_count,
                CloseHash::new([update_count as u8; CLOSE_HASH_LEN]),
                ChannelRole::Customer,
                &self.secret_a,
                &mut OsRng,
            );
            UpdateRecord::countersign(&half, &self.pubkey_a, ChannelRole::Merchant, &self.secret_b, &mut OsRng).unwrap()
        }
    }

    /// A registered arbiter, its clock, and the parties whose records it will accept.
    fn fixture() -> (MockArbiter, Arc<ManualClock>, Parties) {
        let mut rng = ChaCha20Rng::seed_from_u64(99);
        let (arbiter, clock) = MockArbiter::with_manual_clock(&mut rng);
        let parties = Parties::new();
        arbiter.register_channel(channel_id(), parties.pubkey_a, parties.pubkey_b);
        (arbiter, clock, parties)
    }

    fn transport_keypair() -> TransportKeyPair {
        TransportKeyPair::from_seed([0xab; 32])
    }

    fn block_on<F: std::future::Future>(f: F) -> F::Output {
        futures::executor::block_on(f)
    }

    #[test]
    fn configuration_pins_the_served_master_key() {
        let (arbiter, ..) = fixture();
        block_on(arbiter.verify_pinned_master_key()).unwrap();
        // A configuration pinned to a different Z is caught before any offset is sealed to it.
        let mut rng = ChaCha20Rng::seed_from_u64(1234);
        let (_, other_z) = generate_master_keypair(&mut rng);
        let mut config = arbiter.configuration().clone();
        config.master_public_key = other_z;
        let liar = MockArbiter::new(config, *arbiter.master_secret(), arbiter.clock().clone());
        assert_eq!(block_on(liar.verify_pinned_master_key()), Err(ArbiterError::MasterKeyMismatch));
    }

    #[test]
    fn no_dispute_state_until_a_record_is_presented() {
        let (arbiter, ..) = fixture();
        assert!(block_on(arbiter.dispute_state(&channel_id())).unwrap().is_none());
        assert!(block_on(arbiter.action_log(&channel_id())).unwrap().is_empty());
        assert!(matches!(arbiter.attestation(&channel_id()), Err(ArbiterError::NoDispute(_))));
    }

    #[test]
    fn presentation_opens_the_window_at_the_high_water_mark() {
        let (arbiter, clock, parties) = fixture();
        let opened_at = clock.now();
        block_on(arbiter.submit_dispute(&parties.record(5))).unwrap();

        let state = block_on(arbiter.dispute_state(&channel_id())).unwrap().unwrap();
        assert_eq!(state.high_water, 5);
        assert_eq!(state.window_expiry, opened_at + DAY.as_secs());
        assert!(!state.resolved);
        assert_eq!(
            block_on(arbiter.action_log(&channel_id())).unwrap(),
            vec![ActionLogEntry::new(LogAction::RecordPresented(5), opened_at)]
        );
    }

    #[test]
    fn a_zero_count_record_still_opens_a_window() {
        // High-water starts at 0, so state 0 must not be mistaken for "nothing presented yet" and ignored.
        let (arbiter, clock, parties) = fixture();
        block_on(arbiter.submit_dispute(&parties.record(0))).unwrap();
        let state = block_on(arbiter.dispute_state(&channel_id())).unwrap().unwrap();
        assert_eq!(state.high_water, 0);
        assert_eq!(state.window_expiry, clock.now() + DAY.as_secs());
        assert_eq!(block_on(arbiter.action_log(&channel_id())).unwrap().len(), 1);
    }

    #[test]
    fn a_higher_record_advances_the_mark_and_restarts_the_window() {
        let (arbiter, clock, parties) = fixture();
        let opened_at = clock.now();
        block_on(arbiter.submit_dispute(&parties.record(5))).unwrap();

        // Most of the window elapses, then the honest party answers with the true latest state. Gap counts are
        // legal, so 5 -> 200 is a valid supersession.
        clock.advance(Duration::from_secs(80_000));
        let answered_at = clock.now();
        block_on(arbiter.submit_dispute(&parties.record(200))).unwrap();

        let state = block_on(arbiter.dispute_state(&channel_id())).unwrap().unwrap();
        assert_eq!(state.high_water, 200);
        assert_eq!(state.window_expiry, answered_at + DAY.as_secs());
        assert!(state.window_expiry > opened_at + DAY.as_secs(), "the window must restart, not merely persist");

        // Past the *original* expiry, the dispute is still open — the restart is what protects the honest party.
        clock.set(opened_at + DAY.as_secs() + 1);
        let state = block_on(arbiter.dispute_state(&channel_id())).unwrap().unwrap();
        assert!(!state.resolved);
        assert!(matches!(arbiter.attestation(&channel_id()), Err(ArbiterError::WindowNotElapsed { .. })));
    }

    #[test]
    fn a_stale_record_is_ignored_and_logged() {
        let (arbiter, clock, parties) = fixture();
        block_on(arbiter.submit_dispute(&parties.record(9))).unwrap();
        let expiry_before = block_on(arbiter.dispute_state(&channel_id())).unwrap().unwrap().window_expiry;

        clock.advance(Duration::from_secs(600));
        let stale_at = clock.now();
        // Equal counts are stale too: supersession is strictly-greater.
        block_on(arbiter.submit_dispute(&parties.record(9))).unwrap();
        block_on(arbiter.submit_dispute(&parties.record(4))).unwrap();

        let state = block_on(arbiter.dispute_state(&channel_id())).unwrap().unwrap();
        assert_eq!(state.high_water, 9);
        assert_eq!(state.window_expiry, expiry_before, "a stale record must not restart the window");
        let log = block_on(arbiter.action_log(&channel_id())).unwrap();
        assert_eq!(
            log[1..],
            [
                ActionLogEntry::new(LogAction::StaleRecordIgnored(9), stale_at),
                ActionLogEntry::new(LogAction::StaleRecordIgnored(4), stale_at),
            ]
        );
    }

    #[test]
    fn no_attestation_before_the_window_elapses() {
        let (arbiter, clock, parties) = fixture();
        block_on(arbiter.submit_dispute(&parties.record(3))).unwrap();

        clock.advance(DAY - Duration::from_secs(1));
        let err = block_on(arbiter.request_attestation(&channel_id(), transport_keypair().public_key())).unwrap_err();
        assert_eq!(err, ArbiterError::WindowNotElapsed { channel_id: channel_id(), remaining_secs: 1 });
        assert!(!block_on(arbiter.dispute_state(&channel_id())).unwrap().unwrap().resolved);
        // Nothing was logged beyond the presentation: no key exists, so none was released.
        assert_eq!(block_on(arbiter.action_log(&channel_id())).unwrap().len(), 1);
    }

    #[test]
    fn the_attestation_is_released_after_expiry_and_verifies() {
        let (arbiter, clock, parties) = fixture();
        block_on(arbiter.submit_dispute(&parties.record(7))).unwrap();
        clock.advance(DAY);
        let elapsed_at = clock.now();

        let transport = transport_keypair();
        let wrapped = block_on(arbiter.request_attestation(&channel_id(), transport.public_key())).unwrap();
        assert_eq!(wrapped.statement(), &statement_for(&channel_id(), 7));
        assert_eq!(wrapped.transport_public_key(), transport.public_key());

        // The released key is a genuine BLS attestation of the high-water statement under the published Z, and it
        // only comes out through vetKD's `decrypt_and_verify`.
        let z = arbiter.configuration().master_public_key();
        let sigma = transport.unwrap_attestation(&wrapped, z).unwrap();
        verify_attestation(&sigma, &statement_for(&channel_id(), 7), arbiter.configuration().master_public_key()).unwrap();
        // And it attests *only* that statement — a stale close has no key.
        assert!(verify_attestation(&sigma, &statement_for(&channel_id(), 6), arbiter.configuration().master_public_key())
            .is_err());

        let state = block_on(arbiter.dispute_state(&channel_id())).unwrap().unwrap();
        assert!(state.resolved);
        assert_eq!(
            block_on(arbiter.action_log(&channel_id())).unwrap().last().copied(),
            Some(ActionLogEntry::new(LogAction::Attested(7), elapsed_at))
        );
    }

    #[test]
    fn only_the_requesting_transport_key_can_unwrap_the_attestation() {
        // The blinding is the whole reason a public canister call can deliver a secret: an eavesdropper holding
        // the wrapped bytes learns nothing.
        let (arbiter, clock, parties) = fixture();
        block_on(arbiter.submit_dispute(&parties.record(7))).unwrap();
        clock.advance(DAY);

        let transport = transport_keypair();
        let z = arbiter.configuration().master_public_key();
        let wrapped = block_on(arbiter.request_attestation(&channel_id(), transport.public_key())).unwrap();

        let eavesdropper = TransportKeyPair::from_seed([0x11; 32]);
        assert_eq!(
            eavesdropper.unwrap_attestation(&wrapped, z).unwrap_err(),
            ArbiterError::TransportKeyMismatch,
            "a reply wrapped to someone else must be refused before any decryption is attempted"
        );

        // Even re-labelled with the eavesdropper's own transport key, the ciphertext does not open for it.
        let relabelled =
            WrappedAttestation::new(wrapped.statement().clone(), eavesdropper.public_key().clone(), wrapped.payload());
        assert!(matches!(eavesdropper.unwrap_attestation(&relabelled, z), Err(ArbiterError::UnwrapFailed(_))));
    }

    #[test]
    fn an_attestation_for_another_statement_fails_decrypt_and_verify() {
        // `decrypt_and_verify` re-runs the pairing check, so a payload relabelled with a statement it does not
        // attest is rejected at unwrap time rather than surfacing as an unopenable share later.
        let (arbiter, clock, parties) = fixture();
        block_on(arbiter.submit_dispute(&parties.record(7))).unwrap();
        clock.advance(DAY);

        let transport = transport_keypair();
        let z = arbiter.configuration().master_public_key();
        let wrapped = block_on(arbiter.request_attestation(&channel_id(), transport.public_key())).unwrap();
        let mislabelled = WrappedAttestation::new(
            statement_for(&channel_id(), 6),
            transport.public_key().clone(),
            wrapped.payload(),
        );
        assert!(matches!(transport.unwrap_attestation(&mislabelled, z), Err(ArbiterError::UnwrapFailed(_))));

        // And the same payload read against the wrong master key fails too: Z is pinned by the channel, never
        // taken from the reply.
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        let (_, other_z) = generate_master_keypair(&mut rng);
        assert!(matches!(transport.unwrap_attestation(&wrapped, &other_z), Err(ArbiterError::UnwrapFailed(_))));
    }

    #[test]
    fn a_superseded_stale_close_gets_no_key_for_its_own_state() {
        // The whitepaper's "cheating is frozen" scenario, end to end.
        let (arbiter, clock, parties) = fixture();
        block_on(arbiter.submit_dispute(&parties.record(2))).unwrap();
        clock.advance(Duration::from_secs(3_600));
        block_on(arbiter.submit_dispute(&parties.record(11))).unwrap();
        clock.advance(DAY);

        let sigma = arbiter.attestation(&channel_id()).unwrap();
        let z = arbiter.configuration().master_public_key();
        verify_attestation(&sigma, &statement_for(&channel_id(), 11), z).unwrap();
        assert!(verify_attestation(&sigma, &statement_for(&channel_id(), 2), z).is_err());
    }

    #[test]
    fn the_tombstone_prevents_re_dispute() {
        let (arbiter, clock, parties) = fixture();
        block_on(arbiter.submit_dispute(&parties.record(3))).unwrap();
        clock.advance(DAY);
        arbiter.attestation(&channel_id()).unwrap();

        // Even a genuinely higher record cannot reopen a resolved channel.
        let err = block_on(arbiter.submit_dispute(&parties.record(50))).unwrap_err();
        assert_eq!(err, ArbiterError::AlreadyResolved(channel_id()));
        let state = block_on(arbiter.dispute_state(&channel_id())).unwrap().unwrap();
        assert_eq!(state.high_water, 3);
        // Exactly one Attested entry, and the rejected presentation left no trace.
        let log = block_on(arbiter.action_log(&channel_id())).unwrap();
        assert_eq!(log.iter().filter(|e| matches!(e.action, LogAction::Attested(_))).count(), 1);
        assert_eq!(log.len(), 2);
    }

    #[test]
    fn resolution_happens_on_poll_even_without_an_attestation_request() {
        // The canister timer fires on its own; a watching party sees the resolution in the log without asking for
        // the key.
        let (arbiter, clock, parties) = fixture();
        block_on(arbiter.submit_dispute(&parties.record(1))).unwrap();
        clock.advance(DAY);
        let log = block_on(arbiter.action_log(&channel_id())).unwrap();
        assert_eq!(log.last().map(|e| e.action), Some(LogAction::Attested(1)));
    }

    #[test]
    fn a_record_with_an_invalid_signature_is_rejected() {
        let (arbiter, _clock, parties) = fixture();
        let good = parties.record(4);

        // A record whose merchant signature is a forgery under an unrelated key.
        let mallory = XmrScalar::random(&mut OsRng);
        let half = HalfSignedUpdateRecord::sign(
            channel_id(),
            4,
            *good.close_hash(),
            ChannelRole::Customer,
            &parties.secret_a,
            &mut OsRng,
        );
        let forged = UpdateRecord::countersign(&half, &parties.pubkey_a, ChannelRole::Merchant, &mallory, &mut OsRng).unwrap();
        assert!(matches!(block_on(arbiter.submit_dispute(&forged)), Err(ArbiterError::InvalidRecord(_))));

        // And one where a stranger stood in for the customer: the merchant half is genuine, so only the
        // customer-side Schnorr check catches it.
        let mallory_pubkey = Ed25519::generator() * mallory;
        let half = HalfSignedUpdateRecord::sign(
            channel_id(),
            9,
            *good.close_hash(),
            ChannelRole::Customer,
            &mallory,
            &mut OsRng,
        );
        let impostor =
            UpdateRecord::countersign(&half, &mallory_pubkey, ChannelRole::Merchant, &parties.secret_b, &mut OsRng).unwrap();
        assert!(matches!(block_on(arbiter.submit_dispute(&impostor)), Err(ArbiterError::InvalidRecord(_))));

        // Neither rejected record created any state: a dispute opens only on a valid presentation.
        assert!(block_on(arbiter.dispute_state(&channel_id())).unwrap().is_none());
    }

    #[test]
    fn records_for_unregistered_channels_are_rejected() {
        let mut rng = ChaCha20Rng::seed_from_u64(5);
        let (arbiter, _clock) = MockArbiter::with_manual_clock(&mut rng);
        let parties = Parties::new();
        let err = block_on(arbiter.submit_dispute(&parties.record(1))).unwrap_err();
        assert_eq!(err, ArbiterError::UnknownChannel(channel_id()));
    }
}
