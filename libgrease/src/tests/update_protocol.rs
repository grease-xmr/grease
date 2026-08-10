//! Tests for the v2 channel update protocol.
//!
//! `grease_protocol::update_channel` is a set of traits, so these tests drive it through a pair of minimal
//! in-memory parties standing in for the open-channel state machine. The harness is deliberately real where the
//! protocol is: offsets are freshly drawn per state, sealed with [`prove_encrypted_offset`] against a
//! [`MockArbiter`]'s master key, and the receiving side runs the genuine
//! [`verify_encrypted_offset`](crate::cryptography::binding_proof::verify_encrypted_offset), adaptor-signature
//! and record-half checks. Nothing about the VCOF survives.
//!
//! The binding proof runs at a cheap `(n, t) = (12, 5)` profile — ~9 bits of soundness, which is useless in
//! production but exercises exactly the same code paths as `(104, 53)` at a fraction of the cost. The production
//! profile is pinned by `cryptography::binding_proof`'s own tests.

use crate::Ed25519;
use ciphersuite::WrappedGroup;
use rand_core::{CryptoRng, OsRng, RngCore};
use sha2::{Digest, Sha512};
use std::future::Future;
use std::str::FromStr;
use zeroize::Zeroize;

use crate::arbiter::mock::MockArbiter;
use crate::channel_id::ChannelId;
use crate::cryptography::adapter_signature::AdaptedSignature;
use crate::cryptography::attestation::G2Point;
use crate::cryptography::binding_proof::{prove_encrypted_offset, BindingProofParams};
use crate::grease_protocol::adapter_signature::AdapterSignatureHandler;
use crate::grease_protocol::multisig_wallet::{MoneroPayment, MultisigTransaction, MultisigTxError};
use crate::grease_protocol::update_channel::{
    UpdatePackage, UpdateProtocolCommon, UpdateProtocolError, UpdateProtocolProposee, UpdateProtocolProposer,
};
use crate::grease_protocol::update_record::{CloseHash, HalfSignedUpdateRecord, UpdateRecord, CLOSE_HASH_LEN};
use crate::payment_channel::{ChannelRole, HasRole};
use crate::{XmrPoint, XmrScalar};

use crate::io::Writable;
use monero::Address;

const CHANNEL: &str = "XGC4a7024e7fd6f5c6a2d0131d12fd91ecd17f5da61c2970d603a05053b41a383";
const PROPOSER_PREPROCESS: [u8; 3] = [0x01, 0x02, 0x03];
const PROPOSEE_PREPROCESS: [u8; 3] = [0x04, 0x05, 0x06];

fn channel_id() -> ChannelId {
    ChannelId::from_str(CHANNEL).unwrap()
}

/// The cut-and-choose profile these tests run at. See the module docs for why it is not the production one.
fn test_params() -> BindingProofParams {
    BindingProofParams::new(12, 5).unwrap()
}

//--------------------------------------------------------------------------------------------------------------------
//                                       Mocks for the transaction bounds
//--------------------------------------------------------------------------------------------------------------------

/// Minimal mock transaction preprocessing payload used to satisfy the `MultisigTransaction` bound.
struct MockPreprocess(Vec<u8>);

impl Writable for MockPreprocess {
    fn write<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&self.0)
    }
}

/// Minimal mock partial signature used to satisfy the `MultisigTransaction` bound.
struct MockPartialSignature(Vec<u8>);

impl Writable for MockPartialSignature {
    fn write<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&self.0)
    }
}

/// Mock payment type. The update-protocol tests never actually build or sign a transaction, so the
/// accessors are unreachable.
struct MockPayment;

impl MoneroPayment for MockPayment {
    fn new<A: Into<Address>, V: Into<crate::amount::MoneroAmount>>(_recipient: A, _amount: V) -> Self {
        MockPayment
    }

    fn amount(&self) -> crate::amount::MoneroAmount {
        unreachable!("mock payment amount is never queried in the update-protocol tests")
    }

    fn recipient(&self) -> Address {
        unreachable!("mock payment recipient is never queried in the update-protocol tests")
    }
}

//--------------------------------------------------------------------------------------------------------------------
//                                              The stand-in party
//--------------------------------------------------------------------------------------------------------------------

/// The material a party keeps for an update it has started but not yet finalized.
struct PendingUpdate {
    /// The committed `(update_count, balance)` to restore if the update is rejected or aborted.
    previous: (u64, i64),
    /// Our fresh offset for this state, kept once the package is built.
    offset: Option<XmrScalar>,
    /// Our own half of the record, kept so it can be paired with the peer's.
    own_half: Option<HalfSignedUpdateRecord>,
    /// The peer's half, once its package has been verified.
    peer_half: Option<HalfSignedUpdateRecord>,
}

/// Everything both stand-in parties share: keys, the arbiter's master key, balances and the in-flight update.
struct PartyState {
    role: ChannelRole,
    secret: XmrScalar,
    peer_public: XmrPoint,
    master_pk: G2Point,
    update_count: u64,
    balance: i64,
    current_offset: XmrScalar,
    pending: Option<PendingUpdate>,
    record: Option<UpdateRecord>,
    rejected_reason: Option<String>,
}

impl PartyState {
    fn new(role: ChannelRole, secret: XmrScalar, master_pk: G2Point, balance: i64) -> Self {
        PartyState {
            role,
            secret,
            peer_public: Ed25519::generator(),
            master_pk,
            update_count: 0,
            balance,
            current_offset: XmrScalar::default(),
            pending: None,
            record: None,
            rejected_reason: None,
        }
    }

    fn public_key(&self) -> XmrPoint {
        Ed25519::generator() * self.secret
    }

    /// The balance this party would hold after `delta`. Positive deltas move funds customer → merchant.
    fn balance_after(&self, delta: i64) -> i64 {
        match self.role {
            ChannelRole::Customer => self.balance - delta,
            ChannelRole::Merchant => self.balance + delta,
        }
    }

    /// Start an update: apply the delta and step the count optimistically, remembering what to restore.
    ///
    /// The sequence diagram has both parties move their balances *before* any offset material is generated, and
    /// reset them on any rejection — so that is what the harness models.
    fn begin(&mut self, delta: i64) -> Result<(), UpdateProtocolError> {
        if self.pending.is_some() {
            return Err(UpdateProtocolError::UpdateInProgress);
        }
        let new_balance = self.balance_after(delta);
        if new_balance < 0 {
            return Err(UpdateProtocolError::InsufficientBalance(format!(
                "would result in negative balance: {new_balance}"
            )));
        }
        self.pending =
            Some(PendingUpdate { previous: (self.update_count, self.balance), offset: None, own_half: None, peer_half: None });
        self.balance = new_balance;
        self.update_count += 1;
        Ok(())
    }

    fn require_pending(&self) -> Result<&PendingUpdate, UpdateProtocolError> {
        self.pending.as_ref().ok_or(UpdateProtocolError::NoUpdateInProgress)
    }

    /// Roll back to the state before [`begin`](PartyState::begin) — the reset every rejection path performs.
    fn rollback(&mut self) {
        if let Some(pending) = self.pending.take() {
            (self.update_count, self.balance) = pending.previous;
        }
    }

    /// Adopt the pending state permanently, returning the new update count.
    fn commit(&mut self) -> Result<u64, UpdateProtocolError> {
        let pending = self.pending.take().ok_or(UpdateProtocolError::NoUpdateInProgress)?;
        if let Some(offset) = pending.offset {
            self.current_offset.zeroize();
            self.current_offset = offset;
        }
        Ok(self.update_count)
    }
}

macro_rules! impl_party_plumbing {
    ($party:ty) => {
        impl HasRole for $party {
            fn role(&self) -> ChannelRole {
                self.state.role
            }
        }

        impl AdapterSignatureHandler for $party {
            fn initialize_signature_offset(&mut self) {
                self.state.current_offset.zeroize();
                self.state.current_offset = XmrScalar::default();
            }

            fn update_signature_offset(&mut self, offset: &XmrScalar) {
                self.state.current_offset.zeroize();
                self.state.current_offset = *offset;
            }

            fn adapter_signature_offset(&self) -> &XmrScalar {
                &self.state.current_offset
            }
        }

        impl MultisigTransaction for $party {
            type Context = ();
            type Preprocess = MockPreprocess;
            type PartialSignature = MockPartialSignature;
            type Transaction = monero::Transaction;
            type PaymentType = MockPayment;

            fn prepare_transaction<R: Send + Sync + RngCore + CryptoRng>(
                &mut self,
                _payments: &[Self::PaymentType],
                _ctx: &Self::Context,
                _rng: &mut R,
            ) -> impl Future<Output = Result<(), MultisigTxError>> {
                async { Ok(()) }
            }

            fn partial_sign(
                &mut self,
                _preparatory_data: &Self::Preprocess,
                _ctx: &Self::Context,
            ) -> Result<(), MultisigTxError> {
                Ok(())
            }

            fn sign(
                &mut self,
                _peer_sig: Self::PartialSignature,
                _ctx: &Self::Context,
            ) -> Result<Self::Transaction, MultisigTxError> {
                Err(MultisigTxError::NotPrepared)
            }
        }

        impl UpdateProtocolCommon for $party {
            fn channel_id(&self) -> ChannelId {
                channel_id()
            }

            fn update_count(&self) -> u64 {
                self.state.update_count
            }

            fn peer_public_key(&self) -> XmrPoint {
                self.state.peer_public
            }

            fn signing_key(&self) -> &XmrScalar {
                &self.state.secret
            }

            fn arbiter_master_public_key(&self) -> G2Point {
                self.state.master_pk
            }

            fn binding_proof_params(&self) -> BindingProofParams {
                test_params()
            }

            fn close_hash(&self, update_count: u64) -> Result<CloseHash, UpdateProtocolError> {
                Ok(mock_close_hash(update_count))
            }
        }

        impl TestPartyOps for $party {
            fn state(&self) -> &PartyState {
                &self.state
            }

            fn state_mut(&mut self) -> &mut PartyState {
                &mut self.state
            }
        }
    };
}

/// A stand-in close hash: both parties derive the same 64 bytes for a state without building a transaction.
fn mock_close_hash(update_count: u64) -> CloseHash {
    let digest = Sha512::digest(format!("mock-close-hash:{CHANNEL}:{update_count}"));
    let mut bytes = [0u8; CLOSE_HASH_LEN];
    bytes.copy_from_slice(&digest);
    CloseHash::new(bytes)
}

/// The two halves of the exchange that are identical on both sides, expressed once.
trait TestPartyOps: UpdateProtocolCommon + Sized {
    fn state(&self) -> &PartyState;
    fn state_mut(&mut self) -> &mut PartyState;

    /// Draw a fresh offset, seal it, adaptor-sign the *peer's* commitment transaction with it, and sign our half
    /// of the record.
    fn build_package<R: RngCore + CryptoRng>(
        &mut self,
        preprocess: Vec<u8>,
        rng: &mut R,
    ) -> Result<UpdatePackage, UpdateProtocolError> {
        self.state().require_pending()?;
        let count = self.update_count();
        let omega = self.fresh_offset(rng);
        let binding_proof = self.seal_offset(&omega, count)?;
        let msg = self.commitment_message(count, self.role().other());
        let adapted_signature = AdaptedSignature::<Ed25519>::sign(self.signing_key(), &omega, msg, rng);
        let record_half = self.sign_record_half(count, rng)?;
        let pending = self.state_mut().pending.as_mut().expect("checked above");
        pending.offset = Some(omega);
        pending.own_half = Some(record_half.clone());
        self.pair_halves()?;
        Ok(UpdatePackage::new(count, adapted_signature, binding_proof, record_half, preprocess))
    }

    /// Verify a peer's package and keep its record half.
    fn accept_package(&mut self, package: &UpdatePackage) -> Result<(), UpdateProtocolError> {
        self.state().require_pending()?;
        self.verify_update_package(package, self.update_count())?;
        self.state_mut().pending.as_mut().expect("checked above").peer_half = Some(package.record_half.clone());
        self.pair_halves()
    }

    /// Once both halves are in hand, assemble the cross-signed record. Both parties pair the same two halves, so
    /// both end up holding an identical record.
    fn pair_halves(&mut self) -> Result<(), UpdateProtocolError> {
        let pending = self.state().require_pending()?;
        let (own, peer) = match (pending.own_half.clone(), pending.peer_half.clone()) {
            (Some(own), Some(peer)) => (own, peer),
            _ => return Ok(()),
        };
        let record = self.countersign_record(&own, &peer)?;
        self.state_mut().record = Some(record);
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------------------------
//                                                   Proposer
//--------------------------------------------------------------------------------------------------------------------

/// Test implementation of `UpdateProtocolProposer`.
struct TestUpdateProposer {
    state: PartyState,
}

impl TestUpdateProposer {
    fn new(role: ChannelRole, master_pk: G2Point, initial_balance: i64) -> Self {
        TestUpdateProposer { state: PartyState::new(role, XmrScalar::random(&mut OsRng), master_pk, initial_balance) }
    }
}

impl_party_plumbing!(TestUpdateProposer);

impl UpdateProtocolProposer for TestUpdateProposer {
    fn initiate_update(&mut self, delta: i64) -> Result<(), UpdateProtocolError> {
        self.state.begin(delta)
    }

    fn generate_tx_preprocessing<R: RngCore + CryptoRng>(&mut self, _rng: &mut R) -> Result<Vec<u8>, UpdateProtocolError> {
        self.state.require_pending()?;
        Ok(PROPOSER_PREPROCESS.to_vec())
    }

    fn create_update_package<R: RngCore + CryptoRng>(&mut self, rng: &mut R) -> Result<UpdatePackage, UpdateProtocolError> {
        self.build_package(PROPOSER_PREPROCESS.to_vec(), rng)
    }

    fn process_response(&mut self, response: &UpdatePackage) -> Result<(), UpdateProtocolError> {
        self.accept_package(response)
    }

    fn finalize_update(&mut self) -> Result<u64, UpdateProtocolError> {
        self.state.commit()
    }

    fn abort_update(&mut self) -> Result<(), UpdateProtocolError> {
        self.state.rollback();
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------------------------
//                                                   Proposee
//--------------------------------------------------------------------------------------------------------------------

/// Test implementation of `UpdateProtocolProposee`.
struct TestUpdateProposee {
    state: PartyState,
}

impl TestUpdateProposee {
    fn new(role: ChannelRole, master_pk: G2Point, initial_balance: i64) -> Self {
        TestUpdateProposee { state: PartyState::new(role, XmrScalar::random(&mut OsRng), master_pk, initial_balance) }
    }
}

impl_party_plumbing!(TestUpdateProposee);

impl UpdateProtocolProposee for TestUpdateProposee {
    fn receive_update_request(&mut self, delta: i64) -> Result<(), UpdateProtocolError> {
        self.state.begin(delta)
    }

    fn process_tx_preprocessing(&mut self, _preprocess: &[u8]) -> Result<Vec<u8>, UpdateProtocolError> {
        self.state.require_pending()?;
        Ok(PROPOSEE_PREPROCESS.to_vec())
    }

    fn process_update_package(&mut self, package: &UpdatePackage) -> Result<(), UpdateProtocolError> {
        self.accept_package(package)
    }

    fn create_response<R: RngCore + CryptoRng>(&mut self, rng: &mut R) -> Result<UpdatePackage, UpdateProtocolError> {
        self.build_package(PROPOSEE_PREPROCESS.to_vec(), rng)
    }

    fn finalize_update(&mut self) -> Result<u64, UpdateProtocolError> {
        self.state.commit()
    }

    fn reject_update(&mut self, reason: &str) -> Result<(), UpdateProtocolError> {
        self.state.rollback();
        self.state.rejected_reason = Some(reason.to_string());
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------------------------
//                                                   Fixtures
//--------------------------------------------------------------------------------------------------------------------

/// An arbiter master key. Only `Z` matters here: no attestation is requested on the update path.
fn master_public_key() -> G2Point {
    MockArbiter::with_manual_clock(&mut OsRng).0.master_public_key()
}

/// A customer proposer and merchant proposee that know each other's public keys.
fn channel(customer_balance: i64, merchant_balance: i64) -> (TestUpdateProposer, TestUpdateProposee) {
    let master_pk = master_public_key();
    let mut proposer = TestUpdateProposer::new(ChannelRole::Customer, master_pk, customer_balance);
    let mut proposee = TestUpdateProposee::new(ChannelRole::Merchant, master_pk, merchant_balance);
    proposer.state.peer_public = proposee.state.public_key();
    proposee.state.peer_public = proposer.state.public_key();
    (proposer, proposee)
}

/// One complete update for `delta`, driven end to end. Returns the two new update counts.
fn run_update(proposer: &mut TestUpdateProposer, proposee: &mut TestUpdateProposee, delta: i64) -> (u64, u64) {
    let mut rng = OsRng;
    proposer.initiate_update(delta).expect("proposer initiates");
    proposee.receive_update_request(delta).expect("proposee accepts the request");
    let preprocess = proposer.generate_tx_preprocessing(&mut rng).expect("proposer preprocessing");
    let response_preprocess = proposee.process_tx_preprocessing(&preprocess).expect("proposee preprocessing");
    assert_eq!(response_preprocess, PROPOSEE_PREPROCESS.to_vec());

    let package = proposer.create_update_package(&mut rng).expect("proposer builds a package");
    proposee.process_update_package(&package).expect("proposee verifies the package");
    let response = proposee.create_response(&mut rng).expect("proposee responds");
    proposer.process_response(&response).expect("proposer verifies the response");

    let proposer_count = proposer.finalize_update().expect("proposer finalizes");
    let proposee_count = proposee.finalize_update().expect("proposee finalizes");
    (proposer_count, proposee_count)
}

//--------------------------------------------------------------------------------------------------------------------
//                                              Initiation and balances
//--------------------------------------------------------------------------------------------------------------------

#[test]
fn update_initiation_moves_the_state_optimistically() {
    let (mut proposer, _) = channel(1000, 0);

    proposer.initiate_update(100).expect("should initiate update");
    assert!(proposer.state.pending.is_some());
    assert_eq!(proposer.state.balance, 900, "the delta is applied up front");
    assert_eq!(proposer.update_count(), 1);
}

#[test]
fn an_update_beyond_the_balance_is_refused() {
    let (mut proposer, _) = channel(100, 0);

    let result = proposer.initiate_update(200);
    assert!(matches!(result, Err(UpdateProtocolError::InsufficientBalance(_))));
    assert_eq!(proposer.state.balance, 100, "a refused initiation changes nothing");
    assert_eq!(proposer.update_count(), 0);
}

#[test]
fn a_second_update_cannot_start_while_one_is_in_flight() {
    let (mut proposer, _) = channel(1000, 0);

    proposer.initiate_update(100).expect("first update should succeed");
    let result = proposer.initiate_update(50);
    assert!(matches!(result, Err(UpdateProtocolError::UpdateInProgress)));
}

//--------------------------------------------------------------------------------------------------------------------
//                                                  The full flow
//--------------------------------------------------------------------------------------------------------------------

#[test]
fn a_full_update_leaves_both_parties_holding_the_same_record() {
    let (mut proposer, mut proposee) = channel(1000, 0);

    let (proposer_count, proposee_count) = run_update(&mut proposer, &mut proposee, 100);

    assert_eq!((proposer_count, proposee_count), (1, 1));
    assert_eq!(proposer.state.balance, 900, "customer paid 100");
    assert_eq!(proposee.state.balance, 100, "merchant received 100");

    let proposer_record = proposer.state.record.as_ref().expect("proposer holds a record");
    let proposee_record = proposee.state.record.as_ref().expect("proposee holds a record");
    assert_eq!(proposer_record, proposee_record, "both sides assemble the identical cross-signed record");
    assert_eq!(proposer_record.update_count(), 1);
    proposer_record
        .verify(&proposer.state.public_key(), &proposee.state.public_key())
        .expect("the record is genuinely cross-signed by the customer and the merchant");
}

#[test]
fn several_updates_accumulate() {
    let (mut proposer, mut proposee) = channel(1000, 0);

    assert_eq!(run_update(&mut proposer, &mut proposee, 100), (1, 1));
    assert_eq!(run_update(&mut proposer, &mut proposee, 200), (2, 2));

    assert_eq!(proposer.state.balance, 700);
    assert_eq!(proposee.state.balance, 300);
    assert_eq!(proposer.state.record.as_ref().unwrap().update_count(), 2);
}

#[test]
fn offsets_are_independent_across_states() {
    let (mut proposer, mut proposee) = channel(1000, 0);

    run_update(&mut proposer, &mut proposee, 100);
    let first = *proposer.adapter_signature_offset();
    run_update(&mut proposer, &mut proposee, 100);
    let second = *proposer.adapter_signature_offset();

    assert_ne!(first, second, "each state gets a freshly drawn offset — offsets never chain");
}

//--------------------------------------------------------------------------------------------------------------------
//                                              Rejection and rollback
//--------------------------------------------------------------------------------------------------------------------

#[test]
fn aborting_restores_the_previous_state() {
    let (mut proposer, _) = channel(1000, 0);

    proposer.initiate_update(100).expect("should initiate");
    assert_eq!(proposer.state.balance, 900);

    proposer.abort_update().expect("should abort");
    assert!(proposer.state.pending.is_none());
    assert_eq!(proposer.state.balance, 1000, "balance is reset to the previous state");
    assert_eq!(proposer.update_count(), 0, "update count is reset to the previous state");
}

#[test]
fn rejecting_restores_the_previous_state() {
    let (_, mut proposee) = channel(1000, 0);

    proposee.receive_update_request(100).expect("should receive request");
    assert_eq!(proposee.update_count(), 1);

    proposee.reject_update("test rejection").expect("should reject");
    assert!(proposee.state.pending.is_none());
    assert_eq!(proposee.state.rejected_reason.as_deref(), Some("test rejection"));
    assert_eq!(proposee.state.balance, 0);
    assert_eq!(proposee.update_count(), 0);
}

#[test]
fn a_rejected_update_can_be_retried_at_the_same_count() {
    let (mut proposer, mut proposee) = channel(1000, 0);

    proposer.initiate_update(100).unwrap();
    proposer.abort_update().unwrap();

    let (proposer_count, _) = run_update(&mut proposer, &mut proposee, 100);
    assert_eq!(proposer_count, 1, "the aborted attempt did not consume the count");
}

#[test]
fn creating_a_package_before_initiating_fails() {
    let (mut proposer, _) = channel(1000, 0);

    let result = proposer.create_update_package(&mut OsRng);
    assert!(matches!(result, Err(UpdateProtocolError::NoUpdateInProgress)));
}

#[test]
fn finalizing_without_an_update_fails() {
    let (mut proposer, _) = channel(1000, 0);

    let result = proposer.finalize_update();
    assert!(matches!(result, Err(UpdateProtocolError::NoUpdateInProgress)));
}

//--------------------------------------------------------------------------------------------------------------------
//                                              Package verification
//--------------------------------------------------------------------------------------------------------------------

#[test]
fn a_package_for_the_wrong_state_is_rejected() {
    let (mut proposer, mut proposee) = channel(1000, 0);
    let mut rng = OsRng;

    proposee.receive_update_request(100).unwrap();
    let mut package = proposee.create_response(&mut rng).expect("proposee builds a package");
    package.update_count = 5;

    proposer.initiate_update(100).expect("should initiate");
    let result = proposer.process_response(&package);
    assert!(
        matches!(result, Err(UpdateProtocolError::UpdateCountMismatch { expected: 1, actual: 5 })),
        "got {result:?}"
    );
}

#[test]
fn a_sealed_offset_that_does_not_match_the_adaptor_point_is_rejected() {
    let (mut proposer, mut proposee) = channel(1000, 0);
    let mut rng = OsRng;

    proposee.receive_update_request(100).unwrap();
    let mut package = proposee.create_response(&mut rng).expect("proposee builds a package");
    // Seal a different offset. The pre-signature still verifies — only the binding proof's target does not.
    let other = XmrScalar::random(&mut rng);
    package.binding_proof =
        prove_encrypted_offset(&other, &proposee.statement(1), &proposee.arbiter_master_public_key(), proposee.second_base(), test_params())
            .expect("honest prover succeeds");

    proposer.initiate_update(100).unwrap();
    let result = proposer.process_response(&package);
    assert!(matches!(result, Err(UpdateProtocolError::EncryptedOffset(_))), "got {result:?}");
}

#[test]
fn an_offset_sealed_to_another_state_is_rejected() {
    let (mut proposer, mut proposee) = channel(1000, 0);
    let mut rng = OsRng;

    proposee.receive_update_request(100).unwrap();
    let package = proposee.create_response(&mut rng).expect("proposee builds a package");
    let omega = proposee.state.pending.as_ref().and_then(|p| p.offset).expect("offset was kept");

    // The very same offset, sealed to the statement for state 2 instead of state 1.
    let mut tampered = package;
    tampered.binding_proof = prove_encrypted_offset(
        &omega,
        &proposee.statement(2),
        &proposee.arbiter_master_public_key(),
        proposee.second_base(),
        test_params(),
    )
    .expect("honest prover succeeds");

    proposer.initiate_update(100).unwrap();
    let result = proposer.process_response(&tampered);
    assert!(matches!(result, Err(UpdateProtocolError::EncryptedOffset(_))), "got {result:?}");
}

#[test]
fn a_weaker_cut_and_choose_profile_is_rejected() {
    let (mut proposer, mut proposee) = channel(1000, 0);
    let mut rng = OsRng;

    proposee.receive_update_request(100).unwrap();
    let mut package = proposee.create_response(&mut rng).expect("proposee builds a package");
    let omega = proposee.state.pending.as_ref().and_then(|p| p.offset).expect("offset was kept");
    package.binding_proof = prove_encrypted_offset(
        &omega,
        &proposee.statement(1),
        &proposee.arbiter_master_public_key(),
        proposee.second_base(),
        BindingProofParams::new(4, 2).unwrap(),
    )
    .expect("honest prover succeeds");

    proposer.initiate_update(100).unwrap();
    let result = proposer.process_response(&package);
    assert!(matches!(result, Err(UpdateProtocolError::InvalidDataFromPeer(_))), "got {result:?}");
}

#[test]
fn a_pre_signature_over_the_wrong_commitment_transaction_is_rejected() {
    let (mut proposer, mut proposee) = channel(1000, 0);
    let mut rng = OsRng;

    proposee.receive_update_request(100).unwrap();
    let mut package = proposee.create_response(&mut rng).expect("proposee builds a package");
    let omega = proposee.state.pending.as_ref().and_then(|p| p.offset).expect("offset was kept");
    // Sign the proposee's own commitment transaction instead of the proposer's.
    let wrong = proposee.commitment_message(1, ChannelRole::Merchant);
    package.adapted_signature = AdaptedSignature::<Ed25519>::sign(proposee.signing_key(), &omega, wrong, &mut rng);

    proposer.initiate_update(100).unwrap();
    let result = proposer.process_response(&package);
    assert!(matches!(result, Err(UpdateProtocolError::SignatureVerificationFailed(_))), "got {result:?}");
}

#[test]
fn a_record_half_signed_by_a_stranger_is_rejected() {
    let (mut proposer, mut proposee) = channel(1000, 0);
    let mut rng = OsRng;

    proposee.receive_update_request(100).unwrap();
    let mut package = proposee.create_response(&mut rng).expect("proposee builds a package");
    let mallory = XmrScalar::random(&mut rng);
    package.record_half =
        HalfSignedUpdateRecord::sign(channel_id(), 1, mock_close_hash(1), ChannelRole::Merchant, &mallory, &mut rng);

    proposer.initiate_update(100).unwrap();
    let result = proposer.process_response(&package);
    assert!(matches!(result, Err(UpdateProtocolError::Record(_))), "got {result:?}");
}

#[test]
fn a_record_half_committing_to_another_closing_transaction_is_rejected() {
    let (mut proposer, mut proposee) = channel(1000, 0);
    let mut rng = OsRng;

    proposee.receive_update_request(100).unwrap();
    let mut package = proposee.create_response(&mut rng).expect("proposee builds a package");
    package.record_half = HalfSignedUpdateRecord::sign(
        channel_id(),
        1,
        CloseHash::new([0xab; CLOSE_HASH_LEN]),
        ChannelRole::Merchant,
        proposee.signing_key(),
        &mut rng,
    );

    proposer.initiate_update(100).unwrap();
    let result = proposer.process_response(&package);
    assert!(matches!(result, Err(UpdateProtocolError::InvalidDataFromPeer(_))), "got {result:?}");
}

#[test]
fn a_record_half_signed_in_the_wrong_role_is_rejected() {
    let (mut proposer, mut proposee) = channel(1000, 0);
    let mut rng = OsRng;

    proposee.receive_update_request(100).unwrap();
    let mut package = proposee.create_response(&mut rng).expect("proposee builds a package");
    package.record_half = HalfSignedUpdateRecord::sign(
        channel_id(),
        1,
        mock_close_hash(1),
        ChannelRole::Customer,
        proposee.signing_key(),
        &mut rng,
    );

    proposer.initiate_update(100).unwrap();
    let result = proposer.process_response(&package);
    assert!(matches!(result, Err(UpdateProtocolError::Record(_))), "got {result:?}");
}

//--------------------------------------------------------------------------------------------------------------------
//                                                  Wire format
//--------------------------------------------------------------------------------------------------------------------

#[test]
fn an_update_package_round_trips_through_serde() {
    let (_, mut proposee) = channel(1000, 0);

    proposee.receive_update_request(100).unwrap();
    let package = proposee.create_response(&mut OsRng).expect("proposee builds a package");

    let encoded = ron::to_string(&package).expect("package serializes");
    let decoded: UpdatePackage = ron::from_str(&encoded).expect("package deserializes");

    assert_eq!(decoded.update_count, package.update_count);
    assert_eq!(decoded.adaptor_point(), package.adaptor_point());
    assert_eq!(decoded.binding_proof.to_bytes(), package.binding_proof.to_bytes());
    assert_eq!(decoded.record_half, package.record_half);
    assert_eq!(decoded.preprocess, package.preprocess);
}
