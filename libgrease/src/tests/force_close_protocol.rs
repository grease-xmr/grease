//! Tests for the v2 force-close protocol traits (dispute resolution through the arbiter).
//!
//! `grease_protocol::force_close_channel` is a set of traits, so these tests drive it through a minimal
//! in-memory party standing in for the disputing-channel state machine, against a [`MockArbiter`] running the
//! real `onPresentRecord` / `onWindowElapsed` semantics on a [`ManualClock`].
//!
//! The harness is real everywhere the protocol is. Offsets are freshly drawn per state and per party, sealed
//! with [`prove_encrypted_offset`] against the arbiter's master key; records are genuinely cross-signed and the
//! arbiter genuinely verifies both signatures; the attestation comes back vetKD-wrapped and is unwrapped through
//! `EncryptedVetKey::decrypt_and_verify`; and the recovered offset is used to complete an actual adaptor
//! signature, which is then verified. Nothing about the KES survives.
//!
//! The binding proof runs at a cheap `(n, t) = (12, 5)` profile — useless in production, identical code path.

use crate::Ed25519;
use ciphersuite::WrappedGroup;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use crate::arbiter::client::{statement_for, ArbiterClient, ArbiterError, DisputeStateView, TransportKeyPair};
use crate::arbiter::mock::{Clock, ManualClock, MockArbiter};
use crate::channel_id::ChannelId;
use crate::cryptography::adapter_signature::AdaptedSignature;
use crate::cryptography::attestation::{G2Point, Statement};
use crate::cryptography::binding_proof::{prove_encrypted_offset, BindingProof, BindingProofParams};
use crate::cryptography::pvss::SecondBase;
use crate::grease_protocol::force_close_channel::{
    DisputeOutcome, ForceCloseProtocolClaimant, ForceCloseProtocolCommon, ForceCloseProtocolDefendant,
    ForceCloseProtocolError, PendingCloseStatus,
};
use crate::grease_protocol::adapter_signature::adapter_signature_message;
use crate::grease_protocol::update_record::{CloseHash, HalfSignedUpdateRecord, UpdateRecord};
use crate::monero::data_objects::TransactionId;
use crate::payment_channel::{ChannelRole, HasRole};
use crate::wallet::multisig_wallet::{commitment_pair_message, commitment_tx_message};
use crate::{XmrPoint, XmrScalar};

const CHANNEL: &str = "XGC4a7024e7fd6f5c6a2d0131d12fd91ecd17f5da61c2970d603a05053b41a383";
const DAY: Duration = Duration::from_secs(86_400);

fn channel_id() -> ChannelId {
    ChannelId::from_str(CHANNEL).unwrap()
}

fn test_params() -> BindingProofParams {
    BindingProofParams::new(12, 5).unwrap()
}

fn block_on<F: std::future::Future>(f: F) -> F::Output {
    futures::executor::block_on(f)
}

//--------------------------------------------------------------------------------------------------------------------
//                                              The stand-in party
//--------------------------------------------------------------------------------------------------------------------

/// One party's complete local view of a single channel state — exactly the fields the disputing state machine
/// retains, and nothing else.
struct DisputeParty {
    role: ChannelRole,
    channel_id: ChannelId,
    public_key: XmrPoint,
    peer_public_key: XmrPoint,
    master_pk: G2Point,
    record: UpdateRecord,
    /// The channel balances at this state, in piconero. The record's own `close_hash` is the pair message over
    /// these two, which is what lets a dispute recompute the per-holder hash it closes with.
    customer_amount: u64,
    merchant_amount: u64,
    /// The peer's sealed offset for this state — the object a dispute close feeds to `recover_offset`.
    peer_binding_proof: BindingProof,
    /// The peer's pre-signature over *our* commitment transaction.
    peer_presignature: AdaptedSignature<Ed25519>,
    /// The peer's offset in the clear. The party never has this in reality; the tests use it to assert that
    /// recovery produced the right scalar.
    peer_offset: XmrScalar,
    status: PendingCloseStatus,
    high_water: Option<u64>,
    window_expiry: Option<u64>,
}

impl HasRole for DisputeParty {
    fn role(&self) -> ChannelRole {
        self.role
    }
}

impl ForceCloseProtocolCommon for DisputeParty {
    fn channel_id(&self) -> ChannelId {
        self.channel_id.clone()
    }

    fn public_key(&self) -> XmrPoint {
        self.public_key
    }

    fn peer_public_key(&self) -> XmrPoint {
        self.peer_public_key
    }

    fn dispute_window(&self) -> Duration {
        DAY
    }

    fn update_count(&self) -> u64 {
        self.record.update_count()
    }

    fn state_amounts(&self) -> (u64, u64) {
        (self.customer_amount, self.merchant_amount)
    }

    fn arbiter_master_public_key(&self) -> G2Point {
        self.master_pk
    }

    fn latest_record(&self) -> Result<&UpdateRecord, ForceCloseProtocolError> {
        Ok(&self.record)
    }

    fn peer_binding_proof(&self) -> Result<&BindingProof, ForceCloseProtocolError> {
        Ok(&self.peer_binding_proof)
    }

    fn peer_presignature(&self) -> Result<&AdaptedSignature<Ed25519>, ForceCloseProtocolError> {
        match *self.peer_binding_proof.q() == self.peer_presignature.adapter_commitment() {
            true => Ok(&self.peer_presignature),
            false => Err(ForceCloseProtocolError::OffsetTargetMismatch),
        }
    }

    fn status(&self) -> PendingCloseStatus {
        self.status
    }

    fn set_status(&mut self, status: PendingCloseStatus) {
        self.status = status;
    }

    fn note_dispute_state(&mut self, view: &DisputeStateView) {
        self.high_water = Some(view.high_water);
        self.window_expiry = Some(view.window_expiry);
    }
}

#[async_trait::async_trait]
impl ForceCloseProtocolClaimant for DisputeParty {
    async fn broadcast_closing_tx(
        &mut self,
        _signature: &crate::cryptography::adapter_signature::SchnorrSignature<Ed25519>,
    ) -> Result<TransactionId, ForceCloseProtocolError> {
        Ok(TransactionId { id: format!("closed-at-{}", self.update_count()) })
    }
}

impl ForceCloseProtocolDefendant for DisputeParty {}

//--------------------------------------------------------------------------------------------------------------------
//                                                  The channel
//--------------------------------------------------------------------------------------------------------------------

/// A registered channel with two signing keys and a deterministic offset schedule, able to hand out either
/// party's local view of any state.
struct Channel {
    arbiter: MockArbiter,
    clock: Arc<ManualClock>,
    customer_secret: XmrScalar,
    merchant_secret: XmrScalar,
}

impl Channel {
    fn new() -> Self {
        Channel::with_seed(0xf0_7ce_c105e)
    }

    fn with_seed(seed: u64) -> Self {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let (arbiter, clock) = MockArbiter::with_manual_clock(&mut rng);
        let customer_secret = XmrScalar::random(&mut rng);
        let merchant_secret = XmrScalar::random(&mut rng);
        let channel = Channel { arbiter, clock, customer_secret, merchant_secret };
        channel
            .arbiter
            .register_channel(channel_id(), channel.public(ChannelRole::Customer), channel.public(ChannelRole::Merchant))
            .unwrap();
        channel
    }

    fn secret(&self, role: ChannelRole) -> &XmrScalar {
        match role {
            ChannelRole::Customer => &self.customer_secret,
            ChannelRole::Merchant => &self.merchant_secret,
        }
    }

    fn public(&self, role: ChannelRole) -> XmrPoint {
        Ed25519::generator() * self.secret(role)
    }

    fn master_pk(&self) -> G2Point {
        *self.arbiter.configuration().master_public_key()
    }

    /// The offset a party draws for a state. Deterministic so both parties' views of a state agree, and
    /// domain-separated by role so the two offsets in one state are independent draws.
    fn offset(&self, update_count: u64, role: ChannelRole) -> XmrScalar {
        let tag = match role {
            ChannelRole::Customer => 0u64,
            ChannelRole::Merchant => 1,
        };
        XmrScalar::random(&mut ChaCha20Rng::seed_from_u64(0x0ff5e7 ^ (update_count << 4) ^ tag))
    }

    /// The channel balances at a state, in piconero: `(customer, merchant)`. One payment per state, so no two
    /// states share a pair and a close hash belongs to exactly one of them.
    fn amounts(&self, update_count: u64) -> (u64, u64) {
        const TOTAL: u64 = 2_000_000_000_000;
        let merchant = update_count * 1_000_000;
        (TOTAL - merchant, merchant)
    }

    /// The message a state's adaptor signature covers: the commitment transaction *held by* `holder`.
    fn adaptor_message(&self, update_count: u64, holder: ChannelRole) -> Vec<u8> {
        let (customer, merchant) = self.amounts(update_count);
        let msg = commitment_tx_message(&channel_id(), update_count, holder, customer, merchant);
        let close_hash = CloseHash::try_from(msg).expect("the commitment message is a 64-byte challenge");
        adapter_signature_message(&channel_id(), update_count, &close_hash).expect("the fixture id is final")
    }

    /// The pre-signature `signer` sends for a state: over the *counterparty's* commitment transaction, adapted
    /// by the signer's own offset.
    fn presignature(&self, update_count: u64, signer: ChannelRole) -> AdaptedSignature<Ed25519> {
        AdaptedSignature::<Ed25519>::sign(
            self.secret(signer),
            &self.offset(update_count, signer),
            self.adaptor_message(update_count, signer.other()),
            &mut ChaCha20Rng::seed_from_u64(update_count),
        )
    }

    /// The cross-signed record both parties hold for a state, committing to the *pair* of commitment
    /// transactions over the same two amounts a dispute recomputes from.
    fn record(&self, update_count: u64) -> UpdateRecord {
        let (customer, merchant) = self.amounts(update_count);
        let close_hash = CloseHash::try_from(commitment_pair_message(&channel_id(), update_count, customer, merchant))
            .expect("the pair message is a 64-byte challenge");
        let mut rng = ChaCha20Rng::seed_from_u64(0xdec0de ^ update_count);
        let halves = [ChannelRole::Customer, ChannelRole::Merchant].map(|role| {
            HalfSignedUpdateRecord::sign(channel_id(), update_count, close_hash, role, self.secret(role), &mut rng)
                .expect("the fixture id is final")
        });
        UpdateRecord::from_halves(&halves[0], &halves[1]).expect("halves agree by construction")
    }

    /// Seal a party's offset for a state, exactly as the update protocol does.
    fn seal(&self, update_count: u64, owner: ChannelRole) -> BindingProof {
        prove_encrypted_offset(
            &self.offset(update_count, owner),
            &statement_for(&channel_id(), update_count).expect("the fixture id is final"),
            &self.master_pk(),
            SecondBase::grease_default(),
            test_params(),
        )
        .expect("sealing a fresh offset always succeeds")
    }

    /// `role`'s local view of `update_count`.
    fn party(&self, role: ChannelRole, update_count: u64) -> DisputeParty {
        let peer = role.other();
        let (customer_amount, merchant_amount) = self.amounts(update_count);
        DisputeParty {
            role,
            channel_id: channel_id(),
            public_key: self.public(role),
            peer_public_key: self.public(peer),
            master_pk: self.master_pk(),
            record: self.record(update_count),
            customer_amount,
            merchant_amount,
            peer_binding_proof: self.seal(update_count, peer),
            peer_presignature: self.presignature(update_count, peer),
            peer_offset: self.offset(update_count, peer),
            status: PendingCloseStatus::Idle,
            high_water: None,
            window_expiry: None,
        }
    }
}

fn transport() -> TransportKeyPair {
    TransportKeyPair::from_seed([0x2f; 32])
}

//--------------------------------------------------------------------------------------------------------------------
//                                     Outcome classification and plain data
//--------------------------------------------------------------------------------------------------------------------

#[test]
fn an_outcome_maps_to_the_status_it_puts_the_party_in() {
    let cases = [
        (DisputeOutcome::Open { high_water: 3, window_expiry: 99 }, PendingCloseStatus::Pending, false),
        (DisputeOutcome::Superseded { held: 3, high_water: 9 }, PendingCloseStatus::Superseded, false),
        (DisputeOutcome::Attested { update_count: 9 }, PendingCloseStatus::Claimable, true),
        (DisputeOutcome::Frozen { held: 3, attested: 9 }, PendingCloseStatus::Frozen, true),
    ];
    cases.iter().for_each(|(outcome, status, resolved)| {
        assert_eq!(outcome.status(), *status);
        assert_eq!(outcome.is_resolved(), *resolved, "{outcome:?}");
    });
}

#[test]
fn statuses_and_outcomes_round_trip_through_serde() {
    let outcome = DisputeOutcome::Frozen { held: 2, attested: 11 };
    let encoded = ron::to_string(&outcome).expect("should serialize");
    assert_eq!(ron::from_str::<DisputeOutcome>(&encoded).expect("should deserialize"), outcome);

    let status = PendingCloseStatus::Superseded;
    let encoded = ron::to_string(&status).expect("should serialize");
    assert_eq!(ron::from_str::<PendingCloseStatus>(&encoded).expect("should deserialize"), status);
}

#[test]
fn every_force_close_error_displays() {
    let errors: Vec<ForceCloseProtocolError> = vec![
        ForceCloseProtocolError::ChannelNotFound("test".into()),
        ForceCloseProtocolError::InvalidChannelState("not disputing".into()),
        ForceCloseProtocolError::MissingInformation("missing".into()),
        ForceCloseProtocolError::DisputeWindowActive,
        ForceCloseProtocolError::NoPendingForceClose,
        ForceCloseProtocolError::StateSuperseded { held: 2, high_water: 11 },
        ForceCloseProtocolError::StatementMismatch { expected: 5, actual: 4 },
        ForceCloseProtocolError::OffsetTargetMismatch,
        ForceCloseProtocolError::SignatureAdaptationFailed("bad offset".into()),
        ForceCloseProtocolError::CloseHashMismatch { update_count: 7 },
        ForceCloseProtocolError::TransactionCreationFailed("tx error".into()),
        ForceCloseProtocolError::BroadcastFailed("broadcast error".into()),
        ForceCloseProtocolError::UpdateCountTooLow { claimed: 5, actual: 3 },
        ForceCloseProtocolError::Arbiter(ArbiterError::MasterKeyMismatch),
        ForceCloseProtocolError::SerializationError("serial error".into()),
    ];
    errors.iter().for_each(|error| assert!(!format!("{error}").is_empty(), "error display should not be empty"));
}

#[test]
fn classify_reads_the_arbiter_view_against_the_state_we_hold() {
    let channel = Channel::new();
    let party = channel.party(ChannelRole::Customer, 5);
    let view = |high_water, resolved| DisputeStateView {
        channel_id: channel_id(),
        high_water,
        window_expiry: 1_000,
        resolved,
    };

    // Window open at our own state, and at a state below it — both are "open"; the second is what a defendant
    // answers by presenting its later record.
    assert_eq!(party.classify(&view(5, false)), DisputeOutcome::Open { high_water: 5, window_expiry: 1_000 });
    assert_eq!(party.classify(&view(2, false)), DisputeOutcome::Open { high_water: 2, window_expiry: 1_000 });
    // Someone answered above us: our presentation is no longer the maximal one.
    assert_eq!(party.classify(&view(9, false)), DisputeOutcome::Superseded { held: 5, high_water: 9 });
    // Resolved on our state, and on one that is not ours.
    assert_eq!(party.classify(&view(5, true)), DisputeOutcome::Attested { update_count: 5 });
    assert_eq!(party.classify(&view(9, true)), DisputeOutcome::Frozen { held: 5, attested: 9 });
    assert_eq!(party.classify(&view(2, true)), DisputeOutcome::Frozen { held: 5, attested: 2 });
}

#[test]
fn has_more_recent_state_compares_counts_and_never_assumes_an_increment() {
    let channel = Channel::new();
    // Counts may skip, so a party at 200 supersedes a presentation at 5 just as it does one at 199.
    let party = channel.party(ChannelRole::Merchant, 200);
    assert!(party.has_more_recent_state(5));
    assert!(party.has_more_recent_state(199));
    assert!(!party.has_more_recent_state(200), "equal counts do not supersede");
    assert!(!party.has_more_recent_state(201));
    assert!(!party.has_more_recent_state(u64::MAX));

    let genesis = channel.party(ChannelRole::Merchant, 0);
    assert!(!genesis.has_more_recent_state(0));
}

//--------------------------------------------------------------------------------------------------------------------
//                                                Presentation
//--------------------------------------------------------------------------------------------------------------------

#[test]
fn presenting_a_record_opens_the_window_at_our_state() {
    let channel = Channel::new();
    let mut claimant = channel.party(ChannelRole::Merchant, 7);
    let opened_at = channel.clock.now();

    let outcome = block_on(claimant.present_record(&channel.arbiter)).unwrap();
    assert_eq!(outcome, DisputeOutcome::Open { high_water: 7, window_expiry: opened_at + DAY.as_secs() });
    assert_eq!(claimant.status(), PendingCloseStatus::Pending);
    assert_eq!(claimant.high_water, Some(7));
    assert_eq!(claimant.window_expiry, Some(opened_at + DAY.as_secs()));
}

#[test]
fn a_record_the_arbiter_will_not_accept_opens_no_dispute() {
    // The arbiter's rejection leaves no state at all, so a party that assumed otherwise would wait out a window
    // that never started. `present_record` surfaces the rejection instead.
    let mut rng = ChaCha20Rng::seed_from_u64(31);
    let (arbiter, _clock) = MockArbiter::with_manual_clock(&mut rng);
    let channel = Channel::new();
    let mut claimant = channel.party(ChannelRole::Customer, 4);

    let err = block_on(claimant.present_record(&arbiter)).unwrap_err();
    assert!(matches!(err, ForceCloseProtocolError::Arbiter(ArbiterError::UnknownChannel(_))), "{err}");
    assert!(block_on(arbiter.dispute_state(&channel_id())).unwrap().is_none());
    assert_eq!(claimant.status(), PendingCloseStatus::Idle);
}

#[test]
fn a_record_that_fails_its_own_signature_check_is_never_presented() {
    let channel = Channel::new();
    let mut claimant = channel.party(ChannelRole::Customer, 4);
    // Swap in a record cross-signed by two strangers: the local check catches it before the round trip.
    let strangers = Channel::with_seed(0x5747_3e5);
    claimant.record = strangers.record(4);

    let err = block_on(claimant.present_record(&channel.arbiter)).unwrap_err();
    assert!(matches!(err, ForceCloseProtocolError::InvalidUpdateRecord(_)), "{err}");
    assert!(block_on(channel.arbiter.dispute_state(&channel_id())).unwrap().is_none());
}

#[test]
fn no_attestation_is_collected_while_the_window_is_open() {
    let channel = Channel::new();
    let mut claimant = channel.party(ChannelRole::Merchant, 3);
    block_on(claimant.present_record(&channel.arbiter)).unwrap();

    channel.clock.advance(DAY - Duration::from_secs(1));
    let err = block_on(claimant.collect_attestation(&channel.arbiter, &transport())).unwrap_err();
    assert!(matches!(err, ForceCloseProtocolError::DisputeWindowActive), "{err}");
    assert_eq!(claimant.status(), PendingCloseStatus::Pending);
}

//--------------------------------------------------------------------------------------------------------------------
//                                       The full round trip and its inverse
//--------------------------------------------------------------------------------------------------------------------

#[test]
fn an_uncontested_dispute_runs_from_presentation_to_a_completed_closing_signature() {
    // present -> window -> attest -> recover -> complete, with real crypto at every step.
    let channel = Channel::new();
    let mut claimant = channel.party(ChannelRole::Merchant, 12);
    block_on(claimant.present_record(&channel.arbiter)).unwrap();

    channel.clock.advance(DAY);
    assert_eq!(
        block_on(claimant.track_dispute(&channel.arbiter)).unwrap(),
        DisputeOutcome::Attested { update_count: 12 }
    );
    assert_eq!(claimant.status(), PendingCloseStatus::Claimable);

    // The attestation arrives wrapped to our transport key and is unwrapped through `decrypt_and_verify`.
    let sigma = block_on(claimant.collect_attestation(&channel.arbiter, &transport())).unwrap();

    // It unseals the counterparty's offset — the very scalar the counterparty drew.
    let statement = claimant.statement(12).expect("the fixture id is final");
    let proof = claimant.peer_binding_proof().unwrap().clone();
    let omega = claimant.recover_offset(&proof, &statement, &sigma).unwrap();
    assert_eq!(omega, claimant.peer_offset, "recovery must produce the counterparty's actual offset");

    // Which completes the counterparty half of the closing signature over *our* commitment transaction.
    let signature = claimant.complete_closing_signature(&omega).unwrap();
    let msg = channel.adaptor_message(12, ChannelRole::Merchant);
    assert!(signature.verify(&claimant.peer_public_key(), &msg));

    let tx = block_on(claimant.broadcast_closing_tx(&signature)).unwrap();
    assert_eq!(tx.id, "closed-at-12");

    // And the one-call form takes the same path to the same signature.
    let mut again = channel.party(ChannelRole::Merchant, 12);
    let direct = block_on(again.complete_force_close(&channel.arbiter, &transport())).unwrap();
    assert!(direct.verify(&again.peer_public_key(), &msg));
}

#[test]
fn a_stale_presentation_ends_frozen_with_no_offset_released() {
    // The whitepaper's "cheating is frozen" scenario, driven through the protocol traits. The customer presents
    // state 2; the merchant answers with state 11; the window closes on 11.
    let channel = Channel::new();
    let mut cheat = channel.party(ChannelRole::Customer, 2);
    let mut honest = channel.party(ChannelRole::Merchant, 11);

    block_on(cheat.present_record(&channel.arbiter)).unwrap();
    channel.clock.advance(Duration::from_secs(3_600));
    let answered = block_on(honest.answer_dispute(&channel.arbiter)).unwrap().unwrap();
    assert_eq!(answered, DisputeOutcome::Open { high_water: 11, window_expiry: channel.clock.now() + DAY.as_secs() });

    // Before the window even closes, the cheat can see it has been superseded.
    assert_eq!(
        block_on(cheat.track_dispute(&channel.arbiter)).unwrap(),
        DisputeOutcome::Superseded { held: 2, high_water: 11 }
    );
    assert_eq!(cheat.status(), PendingCloseStatus::Superseded);

    channel.clock.advance(DAY);
    assert_eq!(
        block_on(cheat.track_dispute(&channel.arbiter)).unwrap(),
        DisputeOutcome::Frozen { held: 2, attested: 11 }
    );
    assert_eq!(cheat.status(), PendingCloseStatus::Frozen);

    // No key is handed to the cheat, and no penalty is charged either — the close simply cannot complete.
    let err = block_on(cheat.collect_attestation(&channel.arbiter, &transport())).unwrap_err();
    assert!(matches!(err, ForceCloseProtocolError::StateSuperseded { held: 2, high_water: 11 }), "{err}");

    // The honest party's close does complete, on state 11.
    let signature = block_on(honest.complete_force_close(&channel.arbiter, &transport())).unwrap();
    let msg = channel.adaptor_message(11, ChannelRole::Merchant);
    assert!(signature.verify(&honest.peer_public_key(), &msg));

    // And the attestation that exists is useless against the stale state: sigma_11 opens nothing sealed to m_2.
    let sigma = block_on(honest.collect_attestation(&channel.arbiter, &transport())).unwrap();
    let stale_proof = cheat.peer_binding_proof().unwrap().clone();
    assert!(cheat.recover_offset(&stale_proof, &cheat.statement(2).unwrap(), &sigma).is_err());
    assert!(cheat.recover_offset(&stale_proof, &cheat.statement(11).unwrap(), &sigma).is_err());
}

//--------------------------------------------------------------------------------------------------------------------
//                                            Supersession and watching
//--------------------------------------------------------------------------------------------------------------------

#[test]
fn a_supersession_advances_the_mark_and_restarts_the_window() {
    let channel = Channel::new();
    let mut claimant = channel.party(ChannelRole::Customer, 5);
    let mut defendant = channel.party(ChannelRole::Merchant, 200);

    block_on(claimant.present_record(&channel.arbiter)).unwrap();
    let first_expiry = claimant.window_expiry.unwrap();

    // Most of the window elapses before the defendant answers. Gap counts are legal: 5 -> 200 supersedes.
    channel.clock.advance(Duration::from_secs(80_000));
    let outcome = block_on(defendant.present_newer_record(&channel.arbiter, 5)).unwrap();
    let restarted = channel.clock.now() + DAY.as_secs();
    assert_eq!(outcome, DisputeOutcome::Open { high_water: 200, window_expiry: restarted });
    assert!(restarted > first_expiry, "the window must restart, not merely persist");

    // Past the *original* expiry the dispute is still open — the restart is what protects the honest party.
    channel.clock.set(first_expiry + 1);
    assert!(matches!(
        block_on(claimant.track_dispute(&channel.arbiter)).unwrap(),
        DisputeOutcome::Superseded { held: 5, high_water: 200 }
    ));
}

#[test]
fn a_defendant_holding_nothing_newer_leaves_the_dispute_alone() {
    let channel = Channel::new();
    let mut claimant = channel.party(ChannelRole::Customer, 9);
    let mut defendant = channel.party(ChannelRole::Merchant, 9);
    block_on(claimant.present_record(&channel.arbiter)).unwrap();
    let expiry = claimant.window_expiry.unwrap();

    channel.clock.advance(Duration::from_secs(600));
    let outcome = block_on(defendant.answer_dispute(&channel.arbiter)).unwrap().unwrap();
    assert_eq!(outcome, DisputeOutcome::Open { high_water: 9, window_expiry: expiry });

    // Nothing was presented, so the window did not move and the log records only the original presentation.
    let log = block_on(defendant.dispute_log(&channel.arbiter)).unwrap();
    assert_eq!(log.len(), 1);
    assert_eq!(log[0].action.update_count(), 9);

    // Presenting anyway is refused locally rather than wasting a stale submission.
    let err = block_on(defendant.present_newer_record(&channel.arbiter, 9)).unwrap_err();
    assert!(matches!(err, ForceCloseProtocolError::UpdateCountTooLow { claimed: 9, actual: 9 }), "{err}");
}

#[test]
fn watching_a_channel_with_no_dispute_reports_nothing() {
    let channel = Channel::new();
    let mut defendant = channel.party(ChannelRole::Merchant, 4);
    assert_eq!(block_on(defendant.watch_for_dispute(&channel.arbiter)).unwrap(), None);
    assert_eq!(block_on(defendant.answer_dispute(&channel.arbiter)).unwrap(), None);
    assert!(block_on(defendant.dispute_log(&channel.arbiter)).unwrap().is_empty());
    assert_eq!(defendant.status(), PendingCloseStatus::Idle, "watching must not invent a status");
}

#[test]
fn a_defendant_that_wakes_after_the_window_sees_the_resolution_it_missed() {
    let channel = Channel::new();
    let mut claimant = channel.party(ChannelRole::Customer, 6);
    let mut sleeper = channel.party(ChannelRole::Merchant, 30);
    block_on(claimant.present_record(&channel.arbiter)).unwrap();
    channel.clock.advance(DAY);

    // Too late to answer: the channel is tombstoned and the outcome is frozen for the party that slept.
    let outcome = block_on(sleeper.answer_dispute(&channel.arbiter)).unwrap().unwrap();
    assert_eq!(outcome, DisputeOutcome::Frozen { held: 30, attested: 6 });
    let err = block_on(sleeper.present_newer_record(&channel.arbiter, 6)).unwrap_err();
    assert!(matches!(err, ForceCloseProtocolError::Arbiter(ArbiterError::AlreadyResolved(_))), "{err}");
}

//--------------------------------------------------------------------------------------------------------------------
//                                             Recovery and completion
//--------------------------------------------------------------------------------------------------------------------

#[test]
fn a_proof_that_does_not_target_the_presignature_is_refused_before_recovery() {
    // The pairing that makes recovery actionable: the proof must seal the discrete log of the adaptor point in
    // the pre-signature we are about to complete. A proof for someone else's offset opens to a scalar that
    // adapts nothing, so it is rejected outright rather than yielding a useless signature.
    let channel = Channel::new();
    let mut claimant = channel.party(ChannelRole::Merchant, 8);
    block_on(claimant.present_record(&channel.arbiter)).unwrap();
    channel.clock.advance(DAY);
    let sigma = block_on(claimant.collect_attestation(&channel.arbiter, &transport())).unwrap();

    // Our *own* offset for this state is sealed to the same statement and decrypts perfectly — and is exactly
    // the wrong scalar, because it does not open the pre-signature we hold.
    let own = channel.seal(8, ChannelRole::Merchant);
    let err = claimant.recover_offset(&own, &claimant.statement(8).unwrap(), &sigma).unwrap_err();
    assert!(matches!(err, ForceCloseProtocolError::OffsetTargetMismatch), "{err}");

    // Storage that lost the pairing is caught at the same place, before a request is even made.
    claimant.peer_binding_proof = own;
    assert!(matches!(claimant.peer_presignature(), Err(ForceCloseProtocolError::OffsetTargetMismatch)));
}

#[test]
fn recovering_against_the_wrong_statement_fails() {
    // H_F absorbs `m`, so the statement is an input to decryption and cannot be read off the proof. Handing in
    // the wrong one leaves every share unopenable.
    let channel = Channel::new();
    let mut claimant = channel.party(ChannelRole::Customer, 15);
    block_on(claimant.present_record(&channel.arbiter)).unwrap();
    channel.clock.advance(DAY);
    let sigma = block_on(claimant.collect_attestation(&channel.arbiter, &transport())).unwrap();
    let proof = claimant.peer_binding_proof().unwrap().clone();

    assert!(claimant.recover_offset(&proof, &claimant.statement(14).unwrap(), &sigma).is_err());
    assert!(claimant.recover_offset(&proof, &Statement::new(b"XGCsomeotherchannel".to_vec(), 15), &sigma).is_err());
    // The right statement still works, so the failures above are the statement's doing and nothing else.
    assert!(claimant.recover_offset(&proof, &claimant.statement(15).unwrap(), &sigma).is_ok());
}

#[test]
fn completing_with_the_wrong_offset_fails_rather_than_producing_a_bad_signature() {
    let channel = Channel::new();
    let claimant = channel.party(ChannelRole::Customer, 3);
    let wrong = channel.offset(3, ChannelRole::Customer);
    let err = claimant.complete_closing_signature(&wrong).unwrap_err();
    assert!(matches!(err, ForceCloseProtocolError::SignatureAdaptationFailed(_)), "{err}");
    // The right offset completes a signature that verifies under the counterparty's key.
    let signature = claimant.complete_closing_signature(&claimant.peer_offset).unwrap();
    assert!(signature.verify(&claimant.peer_public_key(), channel.adaptor_message(3, ChannelRole::Customer)));
}

#[test]
fn the_completed_signature_is_over_our_own_commitment_transaction() {
    // The asymmetry of the update exchange: the pre-signature we hold covers the transaction *we* would
    // broadcast, so it is the message for `holder = our role` and nothing else.
    let channel = Channel::new();
    let claimant = channel.party(ChannelRole::Merchant, 21);
    let signature = claimant.complete_closing_signature(&claimant.peer_offset).unwrap();
    let peer = claimant.peer_public_key();
    assert!(signature.verify(&peer, channel.adaptor_message(21, ChannelRole::Merchant)));
    assert!(!signature.verify(&peer, channel.adaptor_message(21, ChannelRole::Customer)));
    assert!(!signature.verify(&peer, channel.adaptor_message(20, ChannelRole::Merchant)));
}
