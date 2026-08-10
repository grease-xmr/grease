//! The seam between the update state machine and the dispute path.
//!
//! `tests::force_close_protocol` drives the force-close traits through a stand-in party. These tests drive them
//! through the *real* state objects instead: updates are applied to an [`EstablishedChannelState`], the channel
//! moves to a [`DisputingChannelState`], and the close is completed from whatever that state machine retained —
//! no hand-placed proof anywhere on the path.
//!
//! Two things are pinned here:
//!
//! - the whole seam works end to end: apply updates, reach the stored peer binding proof through the state
//!   machine, feed it to `recover_offset` under a real arbiter attestation, and complete the counterparty half
//!   of the closing signature; and
//! - **which entry** the dispute uses. The channel retains the first update and the last
//!   `proof_history_depth`, and dispute reads the newest one and nothing else — the older entries cannot be
//!   opened by any attestation that will ever exist, which is asserted rather than merely asserted about.
//!
//! The binding proof runs at a cheap `(n, t) = (12, 5)` profile — useless in production, identical code path.

use crate::Ed25519;
use monero::Network;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use crate::amount::{MoneroAmount, MoneroDelta};
use crate::arbiter::client::{statement_for, ArbiterClient, TransportKeyPair};
use crate::arbiter::mock::{ManualClock, MockArbiter};
use crate::balance::Balances;
use crate::channel_id::ChannelIdMetadata;
use crate::channel_metadata::{DynamicChannelMetadata, StaticChannelMetadata};
use crate::cryptography::adapter_signature::AdaptedSignature;
use crate::cryptography::binding_proof::{prove_encrypted_offset, BindingProofParams};
use crate::cryptography::encryption_context::{with_encryption_context, AesGcmEncryption, EncryptionContext};
use crate::cryptography::keys::Curve25519Secret;
use crate::cryptography::pvss::SecondBase;
use crate::grease_protocol::force_close_channel::{
    ForceCloseProtocolClaimant, ForceCloseProtocolCommon, ForceCloseProtocolError, PendingCloseStatus,
};
use crate::grease_protocol::adapter_signature::adapter_signature_message;
use crate::grease_protocol::multisig_wallet::LinkedMultisigWallets;
use crate::grease_protocol::update_record::{CloseHash, HalfSignedUpdateRecord, UpdateRecord};
use crate::monero::data_objects::ClosingAddresses;
use crate::payment_channel::multisig_negotiation::MultisigWalletKeyNegotiation;
use crate::payment_channel::ChannelRole;
use crate::state_machine::{
    AppliedUpdate, DisputeReason, DisputingChannelState, EstablishedChannelState, DEFAULT_PROOF_HISTORY_DEPTH,
};
use crate::wallet::multisig_wallet::{commitment_pair_message, commitment_tx_message, FundingOutputRef, MultisigWallet};
use crate::{XmrPoint, XmrScalar};
use ciphersuite::group::Group;

const ALICE_ADDRESS: &str =
    "43i4pVer2tNFELvfFEEXxmbxpwEAAFkmgN2wdBiaRNcvYcgrzJzVyJmHtnh2PWR42JPeDVjE8SnyK3kPBEjSixMsRz8TncK";
const BOB_ADDRESS: &str =
    "4BH2vFAir1iQCwi2RxgQmsL1qXmnTR9athNhpK31DoMwJgkpFUp2NykFCo4dXJnMhU7w9UZx7uC6qbNGuePkRLYcFo4N7p3";

const DAY: Duration = Duration::from_secs(86_400);

fn block_on<F: std::future::Future>(f: F) -> F::Output {
    futures::executor::block_on(f)
}

fn transport() -> TransportKeyPair {
    TransportKeyPair::from_seed([0x71; 32])
}

fn test_params() -> BindingProofParams {
    BindingProofParams::new(12, 5).expect("a valid cut-and-choose profile")
}

//--------------------------------------------------------------------------------------------------------------------
//                                                  The fixture
//--------------------------------------------------------------------------------------------------------------------

/// A real two-party channel: linked multisig wallets, a registered [`MockArbiter`] on a [`ManualClock`], and the
/// ability to hand either party a genuine [`AppliedUpdate`] for any state.
struct Seam {
    arbiter: MockArbiter,
    clock: Arc<ManualClock>,
    customer_wallet: MultisigWallet,
    merchant_wallet: MultisigWallet,
    metadata: ChannelIdMetadata<Ed25519>,
}

impl Seam {
    fn new() -> Self {
        let mut rng = ChaCha20Rng::seed_from_u64(0x5ea3_1eaf);
        let (arbiter, clock) = MockArbiter::with_manual_clock(&mut rng);
        let (customer_wallet, merchant_wallet) = linked_wallets(&mut rng);
        let mut metadata = ChannelIdMetadata::new(
            merchant_wallet.my_public_key().as_point(),
            customer_wallet.my_public_key().as_point(),
            balances(),
            closing_addresses(),
            arbiter.configuration().clone(),
            100,
            200,
        );
        // Bind the id to a funding output, as establishment does: everything the seam signs or seals —
        // records, statements, commitment messages — is refused over a provisional id, and so is registration.
        let declared = FundingOutputRef::new(XmrPoint::generator() * XmrScalar::from(11u64), 0);
        let output = customer_wallet.derive_funding_output(&declared).expect("the customer derives the output");
        let merchant_partial = merchant_wallet.partial_linking_tag(&output).expect("merchant partial linking tag");
        let tag = customer_wallet.linking_tag(&output, &merchant_partial).expect("linked wallets combine to L_j");
        metadata.finalize(vec![tag]).expect("a provisional id can be finalized");
        let seam = Seam { arbiter, clock, customer_wallet, merchant_wallet, metadata };
        // The arbiter verifies presented records against the channel's two signing keys, customer first.
        seam.arbiter
            .register_channel(
                seam.metadata.name(),
                seam.wallet(ChannelRole::Customer).my_public_key().as_point(),
                seam.wallet(ChannelRole::Merchant).my_public_key().as_point(),
            )
            .unwrap();
        seam
    }

    fn wallet(&self, role: ChannelRole) -> &MultisigWallet {
        match role {
            ChannelRole::Customer => &self.customer_wallet,
            ChannelRole::Merchant => &self.merchant_wallet,
        }
    }

    /// The channel signing key behind a party's `my_public_key` — the key its record half and its pre-signature
    /// verify under.
    fn secret(&self, role: ChannelRole) -> &XmrScalar {
        self.wallet(role).my_spend_key().as_scalar()
    }

    /// The offset a party draws for a state. Deterministic, and domain-separated by role so the two offsets in
    /// one state are independent draws.
    fn offset(&self, update_count: u64, role: ChannelRole) -> XmrScalar {
        let tag = match role {
            ChannelRole::Customer => 0u64,
            ChannelRole::Merchant => 1,
        };
        XmrScalar::random(&mut ChaCha20Rng::seed_from_u64(0xb1_dc0f ^ (update_count << 4) ^ tag))
    }

    /// The channel balances after `update_count` payments, in piconero: `(customer, merchant)`.
    ///
    /// Derived from the same delta [`open_channel`](Seam::open_channel) applies, so the fixture's records and
    /// pre-signatures cannot disagree with the balances the state machine ends up holding.
    fn amounts(&self, update_count: u64) -> (u64, u64) {
        let balances = (0..update_count)
            .fold(balances(), |acc, _| acc.apply_delta(payment()).expect("the channel stays solvent"));
        (balances.customer.to_piconero(), balances.merchant.to_piconero())
    }

    /// The message a state's adaptor signature covers: the commitment transaction *held by* `holder`.
    fn adaptor_message(&self, update_count: u64, holder: ChannelRole) -> Vec<u8> {
        let (customer, merchant) = self.amounts(update_count);
        let msg = commitment_tx_message(&self.metadata.name(), update_count, holder, customer, merchant);
        let close_hash = CloseHash::try_from(msg).expect("the commitment message is a 64-byte challenge");
        adapter_signature_message(&self.metadata.name(), update_count, &close_hash).expect("the seam id is final")
    }

    /// The cross-signed record both parties hold for a state, signed with the real channel keys and committing
    /// to the *pair* of commitment transactions for that state's balances.
    fn record(&self, update_count: u64) -> UpdateRecord {
        let (customer, merchant) = self.amounts(update_count);
        let pair = commitment_pair_message(&self.metadata.name(), update_count, customer, merchant);
        let close_hash = CloseHash::try_from(pair).expect("the pair message is a 64-byte challenge");
        let mut rng = ChaCha20Rng::seed_from_u64(0xc0_1dbeef ^ update_count);
        let halves = [ChannelRole::Customer, ChannelRole::Merchant].map(|role| {
            HalfSignedUpdateRecord::sign(
                self.metadata.name(),
                update_count,
                close_hash,
                role,
                self.secret(role),
                &mut rng,
            )
            .expect("the seam id is final")
        });
        UpdateRecord::from_halves(&halves[0], &halves[1]).expect("halves agree by construction")
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

    /// One party's complete local material for a state, exactly as the update protocol would have left it.
    fn applied_update(&self, update_count: u64, role: ChannelRole) -> AppliedUpdate {
        let peer = role.other();
        let peer_binding_proof = prove_encrypted_offset(
            &self.offset(update_count, peer),
            &statement_for(&self.metadata.name(), update_count).expect("the seam id is final"),
            self.arbiter.configuration().master_public_key(),
            SecondBase::grease_default(),
            test_params(),
        )
        .expect("sealing a fresh offset always succeeds");
        let update = AppliedUpdate {
            record: self.record(update_count),
            my_offset: Curve25519Secret::from(self.offset(update_count, role)),
            my_adapted_signature: self.presignature(update_count, role),
            peer_adapted_signature: self.presignature(update_count, peer),
            peer_binding_proof,
            my_preprocess: vec![],
            peer_preprocess: vec![],
        };
        // The pairing that makes recovery actionable: the retained proof's target Q is the adaptor point of the
        // pre-signature this party will complete.
        assert!(update.proof_matches_presignature(), "state {update_count} was built inconsistently");
        update
    }

    /// An open channel for `role` with `count` updates applied, one per payment.
    fn open_channel(&self, role: ChannelRole, count: u64) -> EstablishedChannelState<Ed25519> {
        let mut state = EstablishedChannelState {
            metadata: StaticChannelMetadata::new(Network::Mainnet, role, self.metadata.clone()),
            dynamic: DynamicChannelMetadata::new(balances(), 0),
            multisig_wallet: self.wallet(role).clone(),
            funding_transactions: HashMap::new(),
            updates: Default::default(),
        };
        (1..=count).for_each(|update_count| {
            let applied = self.applied_update(update_count, role);
            assert_eq!(state.store_update(payment(), applied), update_count);
        });
        state
    }

    /// Move an open channel into dispute, carrying whichever update the state machine says is current.
    fn dispute(&self, state: &EstablishedChannelState<Ed25519>) -> DisputingChannelState<Ed25519> {
        let last_update = state.current_update().expect("the channel has updates").clone();
        DisputingChannelState::from_open_channel(
            state.metadata.clone(),
            state.dynamic.clone(),
            DisputeReason::ForceCloseInitiated,
            state.multisig_wallet.clone(),
            HashMap::new(),
            last_update,
        )
    }
}

fn linked_wallets(rng: &mut ChaCha20Rng) -> (MultisigWallet, MultisigWallet) {
    const RPC: &str = "http://localhost:18082";
    let mut customer = MultisigWalletKeyNegotiation::random(rng, ChannelRole::Customer, Network::Mainnet, RPC);
    let mut merchant = MultisigWalletKeyNegotiation::random(rng, ChannelRole::Merchant, Network::Mainnet, RPC);
    let customer_key = customer.shared_public_key();
    let merchant_key = merchant.shared_public_key();
    customer.set_peer_public_key(merchant_key).expect("roles are compatible");
    merchant.set_peer_public_key(customer_key).expect("roles are compatible");
    (
        MultisigWallet::try_from(customer).expect("a fully negotiated wallet"),
        MultisigWallet::try_from(merchant).expect("a fully negotiated wallet"),
    )
}

fn balances() -> Balances {
    Balances::new(MoneroAmount::from_xmr("1.25").expect("valid"), MoneroAmount::from_xmr("0.75").expect("valid"))
}

/// The one payment every update in this fixture makes. The single source for both the deltas `open_channel`
/// applies and the balances the records and pre-signatures are keyed to.
fn payment() -> MoneroDelta {
    MoneroDelta::from(MoneroAmount::from_xmr("0.01").expect("a valid amount"))
}

fn closing_addresses() -> ClosingAddresses {
    ClosingAddresses::new(ALICE_ADDRESS, BOB_ADDRESS).expect("valid closing addresses")
}

//--------------------------------------------------------------------------------------------------------------------
//                                            The seam, end to end
//--------------------------------------------------------------------------------------------------------------------

#[test]
fn a_dispute_closes_on_the_proof_the_open_channel_retained() {
    // Apply eight updates, so the retained history is genuinely first + last five and the state dispute uses is
    // not the only one available.
    let seam = Seam::new();
    let open = seam.open_channel(ChannelRole::Merchant, 8);
    let mut disputing = seam.dispute(&open);

    block_on(disputing.present_record(&seam.arbiter)).expect("the record verifies under the registered keys");
    seam.clock.advance(DAY);

    // Recovery runs on the proof reached through the state machine, not on one handed to the test.
    let sigma = block_on(disputing.collect_attestation(&seam.arbiter, &transport())).expect("the window elapsed");
    let proof = disputing.peer_binding_proof().expect("retained by the open channel").clone();
    let statement = disputing.statement(8).expect("the seam id is final");
    let omega = disputing.recover_offset(&proof, &statement, &sigma).expect("the attestation opens state 8");
    assert_eq!(omega, seam.offset(8, ChannelRole::Customer), "recovery must produce the counterparty's offset");

    // And that offset completes the counterparty half of the closing signature over *our* commitment tx.
    let signature = disputing.complete_closing_signature(&omega).expect("the offset adapts the pre-signature");
    let msg = seam.adaptor_message(8, ChannelRole::Merchant);
    assert!(signature.verify(&disputing.peer_public_key(), &msg));
    assert_eq!(disputing.status(), PendingCloseStatus::Claimable);
}

#[test]
fn the_one_call_close_takes_the_same_path_from_the_same_stored_state() {
    let seam = Seam::new();
    let open = seam.open_channel(ChannelRole::Customer, 8);
    let mut disputing = seam.dispute(&open);

    block_on(disputing.present_record(&seam.arbiter)).expect("the record verifies");
    seam.clock.advance(DAY);
    let signature =
        block_on(disputing.complete_force_close(&seam.arbiter, &transport())).expect("an uncontested close");
    let msg = seam.adaptor_message(8, ChannelRole::Customer);
    assert!(signature.verify(&disputing.peer_public_key(), &msg));
}

#[test]
fn a_dispute_whose_balances_left_the_record_behind_refuses_to_complete() {
    // `from_open_channel` takes the balances and the record as independent arguments, so nothing structural stops
    // a caller pairing mismatched ones. The record's own close hash is the pair message over the state's two
    // amounts, so recomputing it is what proves the balances are the ones both parties signed — and a state that
    // has drifted is refused outright rather than producing a signature that verifies against nothing.
    let seam = Seam::new();
    let open = seam.open_channel(ChannelRole::Customer, 8);
    let mut disputing = seam.dispute(&open);
    disputing.dynamic.current_balances =
        disputing.dynamic.current_balances.apply_delta(payment()).expect("the channel stays solvent");

    let err = disputing
        .complete_closing_signature(&seam.offset(8, ChannelRole::Merchant))
        .expect_err("drifted balances cannot rebuild the message the pre-signature covers");
    assert!(matches!(err, ForceCloseProtocolError::CloseHashMismatch { update_count: 8 }), "{err}");
}

//--------------------------------------------------------------------------------------------------------------------
//                                   Which entry of the history dispute uses
//--------------------------------------------------------------------------------------------------------------------

#[test]
fn the_history_keeps_the_first_update_and_the_last_five() {
    let seam = Seam::new();
    let open = seam.open_channel(ChannelRole::Merchant, 8);
    let history = open.update_history();
    assert_eq!(history.depth(), DEFAULT_PROOF_HISTORY_DEPTH);
    assert_eq!(history.retained_counts(), vec![1, 4, 5, 6, 7, 8], "first, then the last five");
    assert_eq!(history.first().map(|u| u.record.update_count()), Some(1));
    assert_eq!(history.latest().map(|u| u.record.update_count()), Some(8));
    assert_eq!(history.len(), 6);
}

#[test]
fn dispute_reads_the_newest_entry_and_no_other() {
    // The claim the whole history question turns on: what a dispute closes on is `latest`, whatever else is kept.
    let seam = Seam::new();
    let open = seam.open_channel(ChannelRole::Merchant, 8);
    let disputing = seam.dispute(&open);

    assert_eq!(disputing.update_count(), 8);
    assert_eq!(disputing.last_update().record.update_count(), 8);
    let used = disputing.peer_binding_proof().expect("a retained proof");
    let newest = open.update_history().latest().expect("a retained update");
    assert_eq!(used.q(), newest.peer_binding_proof.q(), "dispute must use the newest retained proof");
    assert_ne!(
        used.q(),
        open.update_history().first().expect("a first update").peer_binding_proof.q(),
        "the first retained proof is a different state's, and is not what dispute reads"
    );
    // The proof/pre-signature pairing is re-checked at dispute time rather than trusted from local storage.
    assert_eq!(disputing.peer_presignature().expect("paired").adapter_commitment(), *used.q());
}

#[test]
fn no_attestation_that_will_ever_exist_opens_an_older_retained_proof() {
    // Why the retained history is audit material and not a second chance at a close: the arbiter attests the
    // high-water statement once and tombstones the channel, so the only attestation for this channel is the one
    // for state 8 — and it opens nothing sealed to any earlier m_i.
    let seam = Seam::new();
    let open = seam.open_channel(ChannelRole::Merchant, 8);
    let mut disputing = seam.dispute(&open);
    block_on(disputing.present_record(&seam.arbiter)).expect("the record verifies");
    seam.clock.advance(DAY);
    let sigma = block_on(disputing.collect_attestation(&seam.arbiter, &transport())).expect("the window elapsed");

    let older = open.update_history().first().expect("a first update").peer_binding_proof.clone();
    // Its own statement is not attested, and relabelling it with the attested one does not help either.
    assert!(disputing.recover_offset(&older, &disputing.statement(1).unwrap(), &sigma).is_err());
    assert!(disputing.recover_offset(&older, &disputing.statement(8).unwrap(), &sigma).is_err());
    // The target check catches it before decryption is even attempted: an older proof seals a different Q.
    assert!(matches!(
        disputing.recover_offset(&older, &disputing.statement(1).unwrap(), &sigma),
        Err(ForceCloseProtocolError::OffsetTargetMismatch)
    ));
}

//--------------------------------------------------------------------------------------------------------------------
//                                          Retention policy mechanics
//--------------------------------------------------------------------------------------------------------------------

#[test]
fn a_shallow_history_still_leaves_dispute_the_state_it_closes_on() {
    let seam = Seam::new();
    let mut open = seam.open_channel(ChannelRole::Merchant, 3);
    open.set_proof_history_depth(1);
    assert_eq!(open.update_history().retained_counts(), vec![1, 3], "the first, and the only recent one");

    let disputing = seam.dispute(&open);
    assert_eq!(disputing.last_update().record.update_count(), 3);
    assert!(disputing.peer_presignature().is_ok(), "the pairing survives a change of retention policy");
}

#[test]
fn a_depth_of_zero_is_raised_to_one_so_a_dispute_always_has_a_state() {
    let seam = Seam::new();
    let mut open = seam.open_channel(ChannelRole::Customer, 4);
    open.set_proof_history_depth(0);
    assert_eq!(open.update_history().depth(), 1);
    assert_eq!(open.update_history().retained_counts(), vec![1, 4]);
    assert!(open.has_updates());
    assert_eq!(open.current_update().map(|u| u.record.update_count()), Some(4));
}

#[test]
fn a_history_shorter_than_its_depth_stores_the_first_update_once() {
    let seam = Seam::new();
    let open = seam.open_channel(ChannelRole::Merchant, 3);
    // Three updates at depth five: the first is still inside the recent window, and must not be duplicated.
    assert_eq!(open.update_history().retained_counts(), vec![1, 2, 3]);
    assert_eq!(open.update_history().len(), 3);
    assert_eq!(open.update_history().first().map(|u| u.record.update_count()), Some(1));
}

#[test]
fn a_retained_history_survives_serde() {
    let seam = Seam::new();
    let open = seam.open_channel(ChannelRole::Merchant, 8);
    // The retained offsets are secrets, so the whole round trip runs inside an encryption context.
    let ctx: Arc<dyn EncryptionContext> = Arc::new(AesGcmEncryption::random());
    let encoded = with_encryption_context(ctx.clone(), || serde_json::to_string(&open).expect("should serialize"));
    let restored: EstablishedChannelState<Ed25519> =
        with_encryption_context(ctx, || serde_json::from_str(&encoded).expect("should deserialize"));
    assert_eq!(restored.update_history().retained_counts(), open.update_history().retained_counts());
    assert_eq!(restored.update_history().depth(), DEFAULT_PROOF_HISTORY_DEPTH);
    assert!(restored.current_update().expect("a latest state").proof_matches_presignature());
}
