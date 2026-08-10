//! Tests for the channel establishment protocol (v2, arbiter design).
//!
//! Spec: `docs/src/14_establishing_channel.typ` §`initProtocol`.
//!
//! These tests cover:
//! - the full happy path: wallet setup → channel-id finalization against `L_F` → initial-state package
//!   exchange → funding → transition to `Open`
//! - channel-id finalization: both parties derive the same `L_F`, the id becomes final, and it cannot be re-bound
//! - wrapper role enforcement (`MerchantEstablishing` / `CustomerEstablishing`)
//! - failure modes on the package exchange: tampering, swapped packages, replay, a package for the wrong state
//! - funding edge cases and `requirements_met` / `next` failures
//!
//! The adversarial cases that belong to the binding proof itself live with the binding proof
//! (`cryptography/binding_proof.rs`); what is tested here is the establishment protocol around it.

use crate::amount::MoneroAmount;
use crate::channel_id::{ChannelId, ChannelIdFinalizeError};
use crate::cryptography::adapter_signature::AdaptedSignature;
use crate::cryptography::binding_proof::BindingProofParams;
use crate::cryptography::linking_tag::{LinkingTagError, PartialLinkingTag};
use crate::grease_protocol::establish_channel::{ChannelInitPackage, EstablishError};
use crate::grease_protocol::multisig_wallet::MultisigWalletError;
use crate::monero::data_objects::{TransactionId, TransactionRecord};
use crate::payment_channel::ChannelRole;
use crate::state_machine::error::LifeCycleError;
use crate::state_machine::{CustomerEstablishing, MerchantEstablishing};
use crate::wallet::errors::WalletError;
use crate::wallet::multisig_wallet::{DerivedFundingOutput, FundingOutputRef, MultisigWallet};
use crate::{XmrPoint, XmrScalar};
use crate::Ed25519;
use ciphersuite::group::{Group, GroupEncoding};
use ciphersuite::WrappedGroup;
use rand_core::OsRng;

use super::propose_channel_tests::{propose_channel, propose_dual_funded_channel};

const URL: &str = "No RPC required";

/// A cheap cut-and-choose profile. Soundness is not what these tests exercise, and the production profile
/// `(104, 53)` would make every one of them an order of magnitude slower.
pub(crate) fn test_params() -> BindingProofParams {
    BindingProofParams::new(12, 5).expect("(12, 5) is a valid profile")
}

// ============================================================================
// Shared test helpers
// ============================================================================

/// Run the proposal exchange and wrap both parties, with the cheap binding-proof profile in place.
pub(crate) fn wrapped_parties() -> (MerchantEstablishing, CustomerEstablishing) {
    let (merchant, customer) = propose_channel();
    let mut merchant = MerchantEstablishing::new(merchant, URL).expect("merchant role");
    let mut customer = CustomerEstablishing::new(customer, URL).expect("customer role");
    merchant.state_mut().set_binding_proof_params(test_params());
    customer.state_mut().set_binding_proof_params(test_params());
    (merchant, customer)
}

pub(crate) fn establish_wallet(merchant: &mut MerchantEstablishing, customer: &mut CustomerEstablishing) {
    // Merchant commits to their shared public key, customer stores the commitment
    let commitment = merchant.wallet_public_key_commitment().expect("merchant commitment should succeed");
    customer.set_merchant_wallet_public_key_commitment(commitment).expect("customer should accept commitment");
    let customer_pubkey = customer.wallet_public_key();

    merchant.set_customer_wallet_public_key(customer_pubkey).expect("merchant should accept customer's public key");
    // Customer then receives the merchant's actual public key - verification happens internally
    let merchant_shared_key = merchant.wallet_public_key();
    customer.set_merchant_wallet_public_key(merchant_shared_key).expect("commitment verification should succeed");
    let customer_address = customer.state().multisig_address().expect("customer should have address");
    assert_eq!(
        customer_address,
        merchant.state().multisig_address().expect("merchant should have an address")
    );
}

/// Inject synthetic signing shares into both parties' wallets.
///
/// The signing share is derived from each wallet's spend key so the adapter
/// signature verifies correctly against the peer's public key.
pub(crate) fn inject_signing_shares(merchant: &mut MerchantEstablishing, customer: &mut CustomerEstablishing) {
    let merchant_share = {
        let wallet = merchant.state().multisig_wallet.as_ref().expect("wallet");
        *wallet.my_spend_key().to_dalek_scalar()
    };
    let customer_share = {
        let wallet = customer.state().multisig_wallet.as_ref().expect("wallet");
        *wallet.my_spend_key().to_dalek_scalar()
    };

    if let Some(wallet) = merchant.state_mut().multisig_wallet.as_mut() {
        wallet.inject_test_signing_share(&merchant_share);
    }
    if let Some(wallet) = customer.state_mut().multisig_wallet.as_mut() {
        wallet.inject_test_signing_share(&customer_share);
    }
}

/// The merchant's shared wallet. Panics unless [`establish_wallet`] has run.
pub(crate) fn wallet_of_merchant(merchant: &MerchantEstablishing) -> &MultisigWallet {
    merchant.state().multisig_wallet.as_ref().expect("merchant wallet")
}

/// The customer's shared wallet. Panics unless [`establish_wallet`] has run.
pub(crate) fn wallet_of_customer(customer: &CustomerEstablishing) -> &MultisigWallet {
    customer.state().multisig_wallet.as_ref().expect("customer wallet")
}

/// Verify a counterparty contribution to `output`'s tag the way `wallet` would, and return the partial.
fn verified_partial_at(
    wallet: &MultisigWallet,
    output: &DerivedFundingOutput,
    partial: &PartialLinkingTag,
) -> XmrPoint {
    let share = wallet.peer_verification_share(output).expect("verification share");
    partial.verified_partial(&share, &wallet.linking_tag_generator(output)).expect("an honest partial verifies")
}

/// The channel's single funding output, as both parties derive it. Panics unless the customer has declared.
fn the_funding_output(state: &crate::state_machine::EstablishingState) -> DerivedFundingOutput {
    let outputs = state.funding_outputs().expect("the funding set is declared");
    assert_eq!(outputs.len(), 1, "the test fixture is a singly-funded channel");
    outputs[0]
}

/// Re-encode a contribution with its partial point replaced, keeping the original proof scalars.
///
/// This is the attacker's real capability: it controls the bytes on the wire, not our Rust types. Nothing in
/// the library hands out a way to mint a `PartialLinkingTag` around an arbitrary point, so a forgery has to be
/// assembled at the encoding boundary — which is exactly where a peer's message enters.
fn forge_partial(honest: &PartialLinkingTag, point: XmrPoint) -> PartialLinkingTag {
    let mut bytes = honest.to_bytes();
    bytes[..32].copy_from_slice(point.to_bytes().as_ref());
    PartialLinkingTag::from_bytes(&bytes).expect("a valid point and the original scalars still decode")
}

/// A funding-output declaration over a fresh transaction public key. The `(R, i)` pair is all a declaration
/// carries, and nothing in this ticket's scope checks that it names a real transaction.
pub(crate) fn a_declaration() -> FundingOutputRef {
    FundingOutputRef::new(Ed25519::generator() * XmrScalar::random(&mut OsRng), 0)
}

/// The customer declares the output it will fund the channel with, and the merchant records it.
///
/// The fixture channel is singly funded — the merchant's initial balance is zero — so this is the whole
/// funding set.
pub(crate) fn declare_funding_outputs(merchant: &mut MerchantEstablishing, customer: &mut CustomerEstablishing) {
    let declared = a_declaration();
    customer.declare_funding_output(declared).expect("the customer funds this channel");
    merchant.receive_customer_funding_output(declared).expect("the merchant records the declaration");
}

/// Exchange partial linking tags and bind both parties' channel ids to the funding outputs.
///
/// Returns the final id, which both sides must agree on.
pub(crate) fn finalize_channel_ids(
    merchant: &mut MerchantEstablishing,
    customer: &mut CustomerEstablishing,
) -> ChannelId {
    let merchant_partials = merchant.partial_linking_tags().expect("merchant partial linking tags");
    let customer_partials = customer.partial_linking_tags().expect("customer partial linking tags");
    let merchant_id = merchant.finalize_channel_id(&customer_partials).expect("merchant finalizes the id");
    let customer_id = customer.finalize_channel_id(&merchant_partials).expect("customer finalizes the id");
    assert_eq!(merchant_id, customer_id, "both parties must derive the same final channel id");
    merchant_id
}

/// Wallet setup and the funding declaration: everything the linking-tag exchange needs.
pub(crate) fn establish_to_declarations() -> (MerchantEstablishing, CustomerEstablishing) {
    let (mut merchant, mut customer) = wrapped_parties();
    establish_wallet(&mut merchant, &mut customer);
    declare_funding_outputs(&mut merchant, &mut customer);
    (merchant, customer)
}

/// Wallet setup, declarations, signing shares, funding-tx watcher and channel-id finalization: everything up
/// to, but not including, the initial-state package exchange.
pub(crate) fn establish_to_final_id() -> (MerchantEstablishing, CustomerEstablishing) {
    let (mut merchant, mut customer) = establish_to_declarations();
    merchant.state_mut().save_funding_tx_pipe(vec![]);
    customer.state_mut().save_funding_tx_pipe(vec![]);
    inject_signing_shares(&mut merchant, &mut customer);
    finalize_channel_ids(&mut merchant, &mut customer);
    (merchant, customer)
}

/// The full establishment protocol short of funding: both initial-state packages generated, exchanged and
/// verified.
pub(crate) fn establish_to_init_packages() -> (MerchantEstablishing, CustomerEstablishing) {
    let mut rng = OsRng;
    let (mut merchant, mut customer) = establish_to_final_id();

    let customer_pkg = customer.generate_init_package(&mut rng).expect("customer init package");
    merchant.receive_customer_init_package(customer_pkg).expect("merchant receives customer package");

    let merchant_pkg = merchant.generate_init_package(&mut rng).expect("merchant init package");
    customer.receive_merchant_init_package(merchant_pkg).expect("customer receives merchant package");

    (merchant, customer)
}

/// Add exact required funding to both parties.
pub(crate) fn fund_both(merchant: &mut MerchantEstablishing, customer: &mut CustomerEstablishing) {
    let required = merchant.state().metadata.initial_balance().total();
    let tx = fake_tx("funding_tx", required);
    merchant.funding_tx_confirmed(tx.clone());
    customer.funding_tx_confirmed(tx);
}

/// Create a `TransactionRecord` with the given id and amount.
pub(crate) fn fake_tx(id: &str, amount: MoneroAmount) -> TransactionRecord {
    TransactionRecord {
        channel_name: "test".into(),
        transaction_id: TransactionId::new(id),
        amount,
        serialized: vec![],
    }
}

// ============================================================================
// Happy path
// ============================================================================

#[test]
fn happy_path() {
    let (mut merchant, mut customer) = establish_to_init_packages();

    fund_both(&mut merchant, &mut customer);

    assert!(merchant.state().requirements_met(), "Merchant requirements not met");
    assert!(customer.state().requirements_met(), "Customer requirements not met");

    // Both parties should be able to transition to established state
    let _merchant = merchant.into_inner().next().expect("merchant to move to established");
    let _customer = customer.into_inner().next().expect("customer to move to established");
}

/// The arbiter is never contacted during establishment: the whole flow above runs against an arbiter
/// configuration that is nothing but a master public key.
#[test]
fn establishment_needs_only_the_arbiters_public_key() {
    let (merchant, customer) = establish_to_init_packages();
    let merchant_z = *merchant.state().metadata.arbiter_configuration().master_public_key();
    let customer_z = *customer.state().metadata.arbiter_configuration().master_public_key();
    assert_eq!(merchant_z, customer_z, "both parties seal their offsets to the same arbiter key");
}

// ============================================================================
// Channel id finalization (§initProtocol step 2)
// ============================================================================

/// Before the shared wallet exists there is no `L_F`, so the id is provisional and carries the `XGT` prefix.
#[test]
fn the_proposed_id_is_provisional() {
    let (merchant, _) = propose_channel();
    let id = merchant.channel_id();
    assert!(!id.is_finalized());
    assert!(id.as_str().starts_with(ChannelId::PREFIX_PROVISIONAL));
}

/// F2 of the K-20 review: `initial_close_hash` is `pub` and reachable without going through
/// `generate_init_package`, so it must refuse a provisional id itself rather than rely on those callers'
/// `require_final_channel_id` guards. A `CloseHash` over an `XGT…` id would commit a closing transaction to no
/// funding output.
#[test]
fn no_close_hash_exists_for_a_provisional_id() {
    let (mut merchant, mut customer) = establish_to_declarations();
    assert!(!merchant.state().channel_id().is_finalized(), "the id must still be provisional here");

    [ChannelRole::Merchant, ChannelRole::Customer].into_iter().for_each(|holder| {
        let err = merchant.state().initial_close_hash(holder).expect_err("a provisional id must be refused");
        assert!(matches!(err, EstablishError::ProvisionalChannelId(_)), "got {err:?}");
    });

    // Binding the id to the funding tags is exactly what lifts the refusal.
    finalize_channel_ids(&mut merchant, &mut customer);
    assert!(merchant.state().initial_close_hash(ChannelRole::Merchant).is_ok());
}

/// Finalizing replaces the provisional id with a 65-character `XGC…` id that commits to the funding tags.
#[test]
fn finalization_binds_the_id_to_the_funding_output() {
    let (mut merchant, mut customer) = establish_to_declarations();
    let provisional = merchant.state().channel_id();

    let final_id = finalize_channel_ids(&mut merchant, &mut customer);

    assert!(final_id.is_finalized());
    assert!(final_id.as_str().starts_with(ChannelId::PREFIX_FINAL));
    assert_eq!(final_id.as_str().len(), ChannelId::LENGTH);
    assert_ne!(final_id, provisional, "binding the tags must change the id");
    assert_eq!(
        merchant.state().channel_id_metadata().linking_tags(),
        customer.state().channel_id_metadata().linking_tags(),
        "both parties must bind the same tags"
    );
    assert_eq!(
        merchant.state().channel_id_metadata().linking_tags().expect("bound").len(),
        1,
        "the fixture channel is funded by the customer alone"
    );
}

/// Neither party can compute a tag alone: the partials differ and neither equals the sum.
#[test]
fn the_linking_tag_needs_both_partials() {
    let (mut merchant, mut customer) = establish_to_declarations();
    let output = the_funding_output(merchant.state());

    let merchant_partial = merchant.partial_linking_tags().expect("merchant partials")[0];
    let customer_partial = customer.partial_linking_tags().expect("customer partials")[0];
    // Each side reads the other's partial only through the verifier, which is the only way to get at it.
    let merchant_point = verified_partial_at(wallet_of_customer(&customer), &output, &merchant_partial);
    let customer_point = verified_partial_at(wallet_of_merchant(&merchant), &output, &customer_partial);
    assert_ne!(merchant_point, customer_point);

    finalize_channel_ids(&mut merchant, &mut customer);
    let tag = merchant.state().channel_id_metadata().linking_tags().expect("the tags are bound")[0];
    assert_eq!(tag, merchant_point + customer_point);
    assert_ne!(tag, merchant_point);
    assert_ne!(tag, customer_point);
}

/// Each side's own partial verifies against the verification share the *counterparty* derives independently,
/// and the two verification shares sum to the funding output's one-time key `K_j` — which is what makes the
/// pair of proofs pin the tag to `(d_j + x)·H_p(K_j)`.
///
/// Before this ticket the shares summed to the wallet's joint spend key `P`; the offset `d_j` is exactly the
/// difference, so `K_j = P + d_j·G` is asserted too, and a lost offset shows up as a sum equal to `P`.
#[test]
fn the_verification_shares_the_proofs_are_checked_against_sum_to_the_one_time_key() {
    let (merchant, customer) = establish_to_declarations();
    let output = the_funding_output(merchant.state());

    let merchant_wallet = wallet_of_merchant(&merchant);
    let customer_wallet = wallet_of_customer(&customer);
    // The customer's view of the merchant's share, and the merchant's view of the customer's.
    let merchant_share =
        customer_wallet.peer_verification_share(&output).expect("customer derives the merchant share");
    let customer_share =
        merchant_wallet.peer_verification_share(&output).expect("merchant derives the customer share");
    let joint_key = merchant_wallet.joint_public_spend_key().as_point();
    assert_eq!(merchant_share + customer_share, output.one_time_key);
    assert_eq!(output.one_time_key, joint_key + Ed25519::generator() * output.derivation);
    assert_ne!(merchant_share + customer_share, joint_key, "the shares must carry the output offset");

    // Both parties agree on the base the tag is taken over, and it is the one-time key's hash, not `P`'s.
    assert_eq!(merchant_wallet.linking_tag_generator(&output), customer_wallet.linking_tag_generator(&output));
}

/// A different shared wallet gives a different tag, and therefore a different channel id.
#[test]
fn a_different_wallet_gives_a_different_id() {
    let (mut merchant_a, mut customer_a) = establish_to_declarations();
    let id_a = finalize_channel_ids(&mut merchant_a, &mut customer_a);

    let (mut merchant_b, mut customer_b) = establish_to_declarations();
    let id_b = finalize_channel_ids(&mut merchant_b, &mut customer_b);

    assert_ne!(id_a, id_b);
}

/// The id is bound to a funding output exactly once.
#[test]
fn a_final_id_cannot_be_rebound() {
    let (mut merchant, mut customer) = establish_to_declarations();
    let customer_partials = customer.partial_linking_tags().expect("customer partials");
    finalize_channel_ids(&mut merchant, &mut customer);

    match merchant.finalize_channel_id(&customer_partials) {
        Err(EstablishError::ChannelIdFinalize(ChannelIdFinalizeError::AlreadyFinalized)) => {}
        other => panic!("expected AlreadyFinalized, got: {other:?}"),
    }
}

// ============================================================================
// Refusing a bad contribution to L_F
//
// `finalize` binds the channel id for the channel's lifetime and refuses to re-bind, so an unverified
// contribution accepted here is unrecoverable. Worse, the exchange is unordered, so whoever sends second can
// answer the first partial with a difference of its choosing and *steer* the tag — and a steered tag collides
// the final channel ids of two channels, hence their arbiter statements. See
// `docs/src/14_establishing_channel.typ` §linkingTagExchange. Every case below must be refused before the
// partials are summed.
// ============================================================================

/// Bytes that do not decode as a contribution are refused at the wire boundary, before any group arithmetic.
#[test]
fn a_malformed_contribution_does_not_decode() {
    assert!(matches!(
        PartialLinkingTag::from_bytes(&[0x11u8; 96]),
        Err(LinkingTagError::MalformedEncoding(_))
    ));
    assert!(matches!(
        PartialLinkingTag::from_bytes(&[0u8; 32]),
        Err(LinkingTagError::MalformedEncoding(_))
    ));
}

/// A well-formed group element carrying junk proof scalars is refused, and the id stays provisional.
#[test]
fn a_garbage_partial_is_refused() {
    let (mut merchant, customer) = establish_to_declarations();

    let honest = customer.partial_linking_tags().expect("customer partials")[0];
    let garbage = vec![forge_partial(&honest, Ed25519::generator() * XmrScalar::random(&mut OsRng))];

    assert_linking_tag_error(merchant.finalize_channel_id(&garbage), LinkingTagError::ProofVerificationFailure);
    assert!(!merchant.state().channel_id().is_finalized(), "a refused partial must not bind the id");
}

/// A contribution that is *internally* valid — a real proof, correctly computed — but taken over a scalar that
/// is not the contributor's MuSig share. This is the case a naive "is it a well-formed proof?" check would wave
/// through: the proof verifies against the prover's own `V`, and fails only because the verifier derives `V`
/// itself from the wallet keys instead of reading it off the message.
#[test]
fn a_partial_from_a_different_scalar_is_refused() {
    let (mut merchant, customer) = establish_to_declarations();
    let output = the_funding_output(merchant.state());

    let base = wallet_of_customer(&customer).linking_tag_generator(&output);
    let wrong_scalar = XmrScalar::random(&mut OsRng);
    let wrong = vec![PartialLinkingTag::prove(&wrong_scalar, &base, &mut OsRng).expect("a proof over any scalar")];
    // The proof is genuinely valid — against the verification share its own scalar implies.
    assert_eq!(
        wrong[0].verified_partial(&(Ed25519::generator() * wrong_scalar), &base),
        Ok(base * wrong_scalar)
    );

    assert_linking_tag_error(merchant.finalize_channel_id(&wrong), LinkingTagError::ProofVerificationFailure);
    assert!(!merchant.state().channel_id().is_finalized());
}

/// The steering attack, in full. A malicious customer opens a second channel whose transcript repeats the
/// first in every other field, waits for the merchant's partial, and answers with `target − merchant_partial`
/// so that the two partials sum to the *first* channel's `L_F`. That is a perfectly well-formed group element,
/// and before the contribution proof it would have been accepted — collapsing two live channels onto one
/// channel id, one arbiter statement, and one attestation that opens the counterparty's offset in both.
#[test]
fn a_steered_partial_is_refused() {
    // Channel 1: an ordinary channel, whose tag is what the attacker steers channel 2 onto.
    let (mut merchant_1, mut customer_1) = establish_to_declarations();
    let id_1 = finalize_channel_ids(&mut merchant_1, &mut customer_1);
    let target = merchant_1.state().channel_id_metadata().linking_tags().expect("channel 1 is bound")[0];

    // Channel 2. The merchant sends its partial first; the attacker answers it.
    let (mut merchant_2, mut customer_2) = establish_to_declarations();
    let output = the_funding_output(merchant_2.state());
    let merchant_partial = merchant_2.partial_linking_tags().expect("merchant partials")[0];
    let merchant_point = verified_partial_at(wallet_of_customer(&customer_2), &output, &merchant_partial);

    let honest = customer_2.partial_linking_tags().expect("customer partials")[0];
    let steered = vec![forge_partial(&honest, target - merchant_point)];

    // The forged partial really does steer the sum — this is the attack, not a straw man.
    let steered_point = XmrPoint::from_bytes(&steered[0].to_bytes()[..32].try_into().unwrap()).unwrap();
    assert_eq!(merchant_point + steered_point, target);

    // And it is refused, so channel 2's id is never bound to channel 1's tag.
    assert_linking_tag_error(merchant_2.finalize_channel_id(&steered), LinkingTagError::ProofVerificationFailure);
    assert!(!merchant_2.state().channel_id().is_finalized());

    // Completing the exchange honestly gives channel 2 an id of its own.
    let id_2 = finalize_channel_ids(&mut merchant_2, &mut customer_2);
    assert_ne!(id_1, id_2, "two channels must never share a final id");
}

/// The degenerate steering target: forcing `L_F` to the identity would let two channels collide without the
/// attacker knowing any secret at all, since the identity is the sum of any partial and its negation.
#[test]
fn a_partial_steering_the_tag_to_the_identity_is_refused() {
    let (mut merchant, customer) = establish_to_declarations();
    let output = the_funding_output(merchant.state());

    let merchant_partial = merchant.partial_linking_tags().expect("merchant partials")[0];
    let merchant_point = verified_partial_at(wallet_of_customer(&customer), &output, &merchant_partial);
    let honest = customer.partial_linking_tags().expect("customer partials")[0];
    let cancelling = vec![forge_partial(&honest, -merchant_point)];

    assert_linking_tag_error(merchant.finalize_channel_id(&cancelling), LinkingTagError::ProofVerificationFailure);
    assert!(!merchant.state().channel_id().is_finalized());
}

/// A contribution of nothing at all. Refused on point hygiene before the proof is even considered.
#[test]
fn an_identity_partial_is_refused() {
    let (mut merchant, customer) = establish_to_declarations();

    let honest = customer.partial_linking_tags().expect("customer partials")[0];
    let empty = vec![forge_partial(&honest, XmrPoint::identity())];

    assert_linking_tag_error(
        merchant.finalize_channel_id(&empty),
        LinkingTagError::IdentityPoint("linking tag partial"),
    );
    assert!(!merchant.state().channel_id().is_finalized());
}

/// A contribution proven for one channel does not carry over to another: the base `H_p(K_j)` and the
/// verification share both change with the funding output and the wallet, and the proof is bound to both.
#[test]
fn a_partial_from_another_channel_is_refused() {
    let (_merchant_1, customer_1) = establish_to_declarations();
    let stolen = customer_1.partial_linking_tags().expect("customer partials");

    let (mut merchant_2, _customer_2) = establish_to_declarations();

    assert_linking_tag_error(merchant_2.finalize_channel_id(&stolen), LinkingTagError::ProofVerificationFailure);
    assert!(!merchant_2.state().channel_id().is_finalized());
}

/// Refusal is recoverable in a way a wrong `L_F` never is: the id stays provisional, so the honest party can
/// simply ask for the exchange again.
#[test]
fn a_refused_partial_leaves_the_exchange_retryable() {
    let (mut merchant, customer) = establish_to_declarations();

    let honest = customer.partial_linking_tags().expect("customer partials");
    let garbage = vec![forge_partial(&honest[0], Ed25519::generator() * XmrScalar::random(&mut OsRng))];
    assert!(merchant.finalize_channel_id(&garbage).is_err());

    let id = merchant.finalize_channel_id(&honest).expect("the honest partial still binds the id");
    assert!(id.is_finalized());
}

// ============================================================================
// The dual-funded channel: one tag per funding output
// ============================================================================

/// A channel both parties fund, with both declarations exchanged. Two funding outputs, two tags.
pub(crate) fn dual_funded_parties() -> (MerchantEstablishing, CustomerEstablishing) {
    let (merchant, customer) = propose_dual_funded_channel();
    let mut merchant = MerchantEstablishing::new(merchant, URL).expect("merchant role");
    let mut customer = CustomerEstablishing::new(customer, URL).expect("customer role");
    merchant.state_mut().set_binding_proof_params(test_params());
    customer.state_mut().set_binding_proof_params(test_params());
    establish_wallet(&mut merchant, &mut customer);

    let (customer_output, merchant_output) = (a_declaration(), a_declaration());
    customer.declare_funding_output(customer_output).expect("the customer funds this channel");
    merchant.receive_customer_funding_output(customer_output).expect("the merchant records it");
    merchant.declare_funding_output(merchant_output).expect("the merchant funds this channel too");
    customer.receive_merchant_funding_output(merchant_output).expect("the customer records it");
    (merchant, customer)
}

/// A channel funded by two outputs commits to two tags, and both parties derive the same pair in the same
/// order without either being told whose output is whose.
#[test]
fn a_dual_funded_channel_binds_one_tag_per_output() {
    let (mut merchant, mut customer) = dual_funded_parties();
    let merchant_view = merchant.state().funding_outputs().expect("two declared outputs");
    let customer_view = customer.state().funding_outputs().expect("two declared outputs");
    assert_eq!(merchant_view.len(), 2);
    assert_eq!(merchant_view, customer_view, "both parties derive the same set in the same order");
    assert!(
        merchant_view[0].one_time_key.to_bytes() < merchant_view[1].one_time_key.to_bytes(),
        "the canonical order is ascending by one-time key"
    );

    finalize_channel_ids(&mut merchant, &mut customer);
    let tags = merchant.state().channel_id_metadata().linking_tags().expect("the tags are bound").to_vec();
    assert_eq!(tags.len(), 2, "one tag per funding output");
    assert_ne!(tags[0], tags[1]);
}

/// The attack surface this ticket opens: with more than one output, a partial is a contribution to *one* of
/// them. A partial proved against `H_p(K_1)` and offered in the slot for `K_2` is genuinely well-formed — it
/// fails only because the verifier checks it against the base and verification share of the output that slot
/// belongs to, both of which it derived itself.
#[test]
fn a_partial_over_another_output_is_refused() {
    let (mut merchant, customer) = dual_funded_parties();
    let mut partials = customer.partial_linking_tags().expect("customer partials");
    assert_eq!(partials.len(), 2, "a dual-funded channel needs two partials");

    // Each partial is honest — for the *other* output.
    partials.swap(0, 1);
    assert_linking_tag_error(merchant.finalize_channel_id(&partials), LinkingTagError::ProofVerificationFailure);
    assert!(!merchant.state().channel_id().is_finalized(), "a mis-slotted partial must not bind the id");

    // Put back in their own slots, the very same partials bind it.
    partials.swap(0, 1);
    assert!(merchant.finalize_channel_id(&partials).is_ok());
}

/// Fewer partials than declared outputs is refused before anything is combined, so the id stays provisional
/// and the exchange can simply be repeated.
#[test]
fn a_short_partial_vector_is_refused() {
    let (mut merchant, customer) = dual_funded_parties();
    let partials = customer.partial_linking_tags().expect("customer partials");
    assert_eq!(partials.len(), 2);

    match merchant.finalize_channel_id(&partials[..1]) {
        Err(EstablishError::PartialLinkingTagCount { expected: 2, actual: 1 }) => {}
        other => panic!("expected PartialLinkingTagCount, got: {other:?}"),
    }
    assert!(!merchant.state().channel_id().is_finalized(), "a short vector must leave the id provisional");
    // An empty vector is the degenerate case of the same refusal.
    assert!(merchant.finalize_channel_id(&[]).is_err());

    assert!(merchant.finalize_channel_id(&partials).is_ok(), "the exchange stays retryable");
}

/// A party that brought no balance contributes no funding output, so it has nothing to declare and cannot
/// slip an extra tag into the channel id.
#[test]
fn a_declaration_from_a_non_funding_party_is_refused() {
    let (mut merchant, mut customer) = wrapped_parties();
    establish_wallet(&mut merchant, &mut customer);
    assert!(!merchant.state().funds_the_channel(ChannelRole::Merchant), "the fixture merchant brings nothing");

    match merchant.declare_funding_output(a_declaration()) {
        Err(EstablishError::NotAFundingParty(ChannelRole::Merchant)) => {}
        other => panic!("expected NotAFundingParty(Merchant), got: {other:?}"),
    }
    match customer.receive_merchant_funding_output(a_declaration()) {
        Err(EstablishError::NotAFundingParty(ChannelRole::Merchant)) => {}
        other => panic!("expected NotAFundingParty(Merchant), got: {other:?}"),
    }
}

/// A funding set is declared once. Replacing a declaration would change a tag — and so the channel id — under
/// a counterparty that has already derived it.
#[test]
fn a_funding_output_cannot_be_redeclared() {
    let (mut merchant, mut customer) = establish_to_declarations();
    match customer.declare_funding_output(a_declaration()) {
        Err(EstablishError::FundingOutputAlreadyDeclared(ChannelRole::Customer)) => {}
        other => panic!("expected FundingOutputAlreadyDeclared(Customer), got: {other:?}"),
    }
    match merchant.receive_customer_funding_output(a_declaration()) {
        Err(EstablishError::FundingOutputAlreadyDeclared(ChannelRole::Customer)) => {}
        other => panic!("expected FundingOutputAlreadyDeclared(Customer), got: {other:?}"),
    }
}

/// No tags exist before the funding set does, and `requirements_met` says so by name.
#[test]
fn no_linking_tags_before_the_funding_outputs_are_declared() {
    let (mut merchant, mut customer) = wrapped_parties();
    establish_wallet(&mut merchant, &mut customer);
    assert!(!merchant.state().every_funding_output_declared());

    match customer.partial_linking_tags() {
        Err(EstablishError::MissingInformation(msg)) => assert!(msg.contains("declaration"), "msg: {msg}"),
        other => panic!("expected MissingInformation about the declaration, got: {other:?}"),
    }
    assert!(!merchant.state().requirements_met());

    declare_funding_outputs(&mut merchant, &mut customer);
    assert!(merchant.state().every_funding_output_declared());
    assert_eq!(customer.partial_linking_tags().expect("the set is declared").len(), 1);
}

/// Assert a channel-id finalization failed on the linking-tag contribution, with the expected reason.
fn assert_linking_tag_error(result: Result<ChannelId, EstablishError>, expected: LinkingTagError) {
    match result {
        Err(EstablishError::WalletError(MultisigWalletError::MoneroWalletError(WalletError::LinkingTagError(
            actual,
        )))) => assert_eq!(actual, expected),
        other => panic!("expected the contribution to be refused with {expected:?}, got: {other:?}"),
    }
}

/// The linking tag cannot be derived before the shared wallet exists.
#[test]
fn no_linking_tag_without_a_wallet() {
    let (merchant, _) = wrapped_parties();
    match merchant.partial_linking_tags() {
        Err(EstablishError::MissingInformation(msg)) => assert!(msg.contains("wallet"), "msg: {msg}"),
        other => panic!("expected MissingInformation about the wallet, got: {other:?}"),
    }
}

/// Every signature in an init package commits to the channel id, so no package may be built against the
/// provisional one.
#[test]
fn no_init_package_before_the_id_is_final() {
    let (mut merchant, mut customer) = establish_to_declarations();
    inject_signing_shares(&mut merchant, &mut customer);

    match customer.generate_init_package(&mut OsRng) {
        Err(EstablishError::MissingInformation(msg)) => {
            assert!(msg.contains("Final channel id"), "msg: {msg}");
        }
        other => panic!("expected MissingInformation about the final channel id, got: {other:?}"),
    }
}

// ============================================================================
// Wrapper role enforcement
// ============================================================================

#[test]
fn merchant_wrapper_rejects_customer() {
    let (_, customer) = propose_channel();
    match MerchantEstablishing::new(customer, "") {
        Err(EstablishError::WrongRole { expected: ChannelRole::Merchant, got: ChannelRole::Customer }) => {}
        Err(e) => panic!("expected WrongRole, got: {e:?}"),
        Ok(_) => panic!("expected Err, got Ok"),
    }
}

#[test]
fn customer_wrapper_rejects_merchant() {
    let (merchant, _) = propose_channel();
    match CustomerEstablishing::new(merchant, "") {
        Err(EstablishError::WrongRole { expected: ChannelRole::Customer, got: ChannelRole::Merchant }) => {}
        Err(e) => panic!("expected WrongRole, got: {e:?}"),
        Ok(_) => panic!("expected Err, got Ok"),
    }
}

/// Merchant rejects a wallet public key with Merchant role (should be Customer).
#[test]
fn merchant_rejects_merchant_role_wallet_key() {
    let (mut merchant, _customer) = wrapped_parties();
    let _ = merchant.wallet_public_key_commitment().expect("merchant commitment should succeed");
    let merchant_key = merchant.wallet_public_key();

    match merchant.set_customer_wallet_public_key(merchant_key) {
        Err(EstablishError::WrongRole { expected: ChannelRole::Customer, got: ChannelRole::Merchant }) => {}
        Err(e) => panic!("expected WrongRole, got: {e:?}"),
        Ok(_) => panic!("should reject Merchant role key as customer key"),
    }
}

/// Customer rejects a wallet public key with Customer role (should be Merchant).
#[test]
fn customer_rejects_customer_role_wallet_key() {
    let (_merchant, mut customer) = wrapped_parties();
    let customer_key = customer.wallet_public_key();

    match customer.set_merchant_wallet_public_key(customer_key) {
        Err(EstablishError::WrongRole { expected: ChannelRole::Merchant, got: ChannelRole::Customer }) => {}
        Err(e) => panic!("expected WrongRole, got: {e:?}"),
        Ok(_) => panic!("should reject Customer role key as merchant key"),
    }
}

// ============================================================================
// requirements_met() / next() failures
// ============================================================================

/// A fresh EstablishingState (right after proposal exchange) has nothing set.
#[test]
fn fresh_state_requirements_not_met() {
    let (merchant, _) = propose_channel();
    assert!(!merchant.requirements_met(), "Fresh state should not have requirements met");
}

/// next() on an incomplete state returns Err with InvalidStateTransition.
#[test]
fn next_fails_without_requirements() {
    let (merchant, _) = propose_channel();
    match merchant.next() {
        Err((_, LifeCycleError::InvalidStateTransition)) => {}
        Err((_, e)) => panic!("expected InvalidStateTransition, got: {e:?}"),
        Ok(_) => panic!("expected Err, got Ok"),
    }
}

/// Packages exchanged but no funding transaction: requirements not met, next() fails.
#[test]
fn next_fails_without_funding() {
    let (merchant, _customer) = establish_to_init_packages();
    assert!(!merchant.state().requirements_met(), "Should not be met without funding");
    match merchant.into_inner().next() {
        Err((_, LifeCycleError::InvalidStateTransition)) => {}
        other => panic!("expected InvalidStateTransition, got: {other:?}"),
    }
}

/// Funded, but the counterparty's initial-state package was never accepted.
#[test]
fn next_fails_without_the_peer_package() {
    let (mut merchant, mut customer) = establish_to_final_id();
    let _ = merchant.generate_init_package(&mut OsRng).expect("merchant init package");
    fund_both(&mut merchant, &mut customer);

    assert!(
        !merchant.state().requirements_met(),
        "Should not be met without the counterparty's package"
    );
}

/// Clearing funding_tx_pipe after full setup causes requirements_met to fail.
#[test]
fn next_fails_without_funding_tx_pipe() {
    let (mut merchant, mut customer) = establish_to_init_packages();
    fund_both(&mut merchant, &mut customer);
    merchant.state_mut().funding_tx_pipe = None;

    assert!(
        !merchant.state().requirements_met(),
        "Should not be met without funding_tx_pipe"
    );
}

/// Funding with half the required amount is insufficient.
#[test]
fn partial_funding_insufficient() {
    let (mut merchant, _customer) = establish_to_init_packages();
    let required = merchant.state().metadata.initial_balance().total();
    let half = MoneroAmount::from_piconero(required.to_piconero() / 2);
    merchant.funding_tx_confirmed(fake_tx("half_tx", half));

    assert!(
        !merchant.state().requirements_met(),
        "Half funding should not satisfy requirements"
    );
}

/// Overfunding (more than required) still satisfies requirements.
#[test]
fn overfunding_satisfies_requirements() {
    let (mut merchant, mut customer) = establish_to_init_packages();
    let required = merchant.state().metadata.initial_balance().total();
    let overfund = MoneroAmount::from_piconero(required.to_piconero() * 2);
    merchant.funding_tx_confirmed(fake_tx("big_tx", overfund));
    customer.funding_tx_confirmed(fake_tx("big_tx", overfund));

    assert!(merchant.state().requirements_met(), "Overfunding should satisfy requirements");
    assert!(customer.state().requirements_met(), "Overfunding should satisfy requirements");

    merchant.into_inner().next().expect("merchant should transition with overfunding");
    customer.into_inner().next().expect("customer should transition with overfunding");
}

// ============================================================================
// Initial-state package exchange: what the counterparty must reject
// ============================================================================

/// The customer's package, built honestly, ready to be tampered with.
fn customer_package() -> (MerchantEstablishing, CustomerEstablishing, ChannelInitPackage) {
    let (merchant, mut customer) = establish_to_final_id();
    let package = customer.generate_init_package(&mut OsRng).expect("customer init package");
    (merchant, customer, package)
}

/// A package with no binding proof at all cannot be built — the proof is not optional — so the closest an
/// attacker gets is a proof for some other offset, which no longer targets the adaptor point `Q`.
#[test]
fn a_binding_proof_for_a_different_offset_is_rejected() {
    let (mut merchant, mut customer, mut package) = customer_package();
    // A second, independent package from the same party: an honest proof, but for a different ω.
    let other = customer.generate_init_package(&mut OsRng).expect("a second customer package");
    package.binding_proof = other.binding_proof;

    match merchant.receive_customer_init_package(package) {
        Err(EstablishError::BindingProof(_)) => {}
        other => panic!("expected the swapped binding proof to be rejected, got: {other:?}"),
    }
}

/// An adaptor signature forged under a key that is not the counterparty's wallet key fails verification.
#[test]
fn a_forged_adaptor_signature_is_rejected() {
    let (mut merchant, _customer, mut package) = customer_package();
    let random_secret = XmrScalar::random(&mut OsRng);
    let random_offset = XmrScalar::random(&mut OsRng);
    package.adapted_signature =
        AdaptedSignature::<Ed25519>::sign(&random_secret, &random_offset, b"fake", &mut OsRng);

    match merchant.receive_customer_init_package(package) {
        Err(EstablishError::InvalidDataFromPeer(_)) => {}
        other => panic!("expected InvalidDataFromPeer, got: {other:?}"),
    }
}

/// The merchant's own package handed back to it as if it came from the customer: the adaptor signature was made
/// with the merchant's wallet key over the *customer's* closing transaction, so it cannot verify in that
/// direction.
#[test]
fn a_replayed_merchant_package_is_rejected() {
    let (mut merchant, _customer) = establish_to_final_id();
    let merchant_pkg = merchant.generate_init_package(&mut OsRng).expect("merchant init package");

    match merchant.receive_customer_init_package(merchant_pkg) {
        Err(EstablishError::InvalidDataFromPeer(_)) => {}
        other => panic!("expected InvalidDataFromPeer, got: {other:?}"),
    }
}

/// A package from an entirely different channel does not verify: the adaptor-signature message commits to the
/// channel id, and the signing keys differ.
#[test]
fn a_package_from_another_channel_is_rejected() {
    let (mut merchant, _customer) = establish_to_final_id();
    let (_, mut other_customer) = establish_to_final_id();
    let foreign = other_customer.generate_init_package(&mut OsRng).expect("another channel's package");

    match merchant.receive_customer_init_package(foreign) {
        Err(EstablishError::InvalidDataFromPeer(_)) => {}
        other => panic!("expected InvalidDataFromPeer, got: {other:?}"),
    }
}

/// Each party adapter-signs the *counterparty's* closing transaction, so the customer's own package must not
/// verify when presented to the customer.
#[test]
fn packages_do_not_verify_in_the_sender_s_own_direction() {
    let (_merchant, mut customer, package) = customer_package();

    match customer.receive_merchant_init_package(package) {
        Err(EstablishError::InvalidDataFromPeer(_)) => {}
        other => panic!("expected InvalidDataFromPeer, got: {other:?}"),
    }
}

/// A rejected package leaves the state untouched: nothing half-accepted is stored, and with no peer half there
/// is nothing to pair our own with — so no state-0 record comes into existence either.
#[test]
fn a_rejected_package_leaves_no_state_0_record() {
    let (mut merchant, _customer, mut package) = customer_package();
    let random_secret = XmrScalar::random(&mut OsRng);
    let random_offset = XmrScalar::random(&mut OsRng);
    package.adapted_signature = AdaptedSignature::<Ed25519>::sign(&random_secret, &random_offset, b"fake", &mut OsRng);
    assert!(merchant.receive_customer_init_package(package).is_err());
    assert!(merchant.state().peer_init_package().is_none());
    assert!(merchant.state().initial_record().is_err());
    assert!(!merchant.state().requirements_met());
}

/// An accepted package is stored, and our own package is kept alongside it.
#[test]
fn accepted_packages_are_stored() {
    let (merchant, customer) = establish_to_init_packages();
    assert!(merchant.state().my_init_package().is_some());
    assert!(merchant.state().peer_init_package().is_some());
    assert_eq!(
        merchant.state().my_init_package(),
        customer.state().peer_init_package(),
        "the customer holds exactly the package the merchant sent"
    );
    assert_eq!(customer.state().my_init_package(), merchant.state().peer_init_package());
}

/// Offsets are drawn fresh per party and per package: never derived from anything, never reused.
#[test]
fn offsets_are_independent() {
    let (merchant, customer) = establish_to_init_packages();
    let merchant_q = merchant.state().my_init_package().expect("merchant package").adapted_signature.adapter_commitment();
    let customer_q = customer.state().my_init_package().expect("customer package").adapted_signature.adapter_commitment();
    assert_ne!(merchant_q, customer_q);

    let (mut again, _) = establish_to_final_id();
    let repeat = again.generate_init_package(&mut OsRng).expect("a fresh package");
    assert_ne!(repeat.adapted_signature.adapter_commitment(), merchant_q);
}

/// The binding proof's target is exactly the adaptor point of the signature it accompanies.
#[test]
fn the_binding_proof_targets_the_adaptor_point() {
    let (_merchant, _customer, package) = customer_package();
    assert_eq!(package.adapted_signature.adapter_commitment(), *package.binding_proof.q());
}

/// Revealing `ω` completes the closing signature the counterparty holds.
#[test]
fn revealing_the_offset_completes_the_closing_signature() {
    use crate::grease_protocol::adapter_signature::adapter_signature_message;
    use crate::grease_protocol::establish_channel::INITIAL_UPDATE_COUNT;

    let (merchant, customer) = establish_to_init_packages();
    let omega = customer.state().initial_offset.as_ref().expect("customer keeps its offset");
    let customer_wallet_key = {
        let wallet = customer.state().multisig_wallet.as_ref().expect("wallet");
        Ed25519::generator() * *wallet.my_spend_key().to_dalek_scalar()
    };
    let package = merchant.state().peer_init_package().expect("merchant holds the customer's package");
    let msg = adapter_signature_message(
        &merchant.state().channel_id(),
        INITIAL_UPDATE_COUNT,
        &merchant.state().initial_close_hash(ChannelRole::Merchant).expect("merchant close hash"),
    )
    .expect("the channel id is final");
    let completed = package
        .adapted_signature
        .adapt(omega, &customer_wallet_key, &msg)
        .expect("the revealed offset completes the signature");
    assert!(completed.verify(&customer_wallet_key, &msg));
}

// ============================================================================
// The state-0 record
// ============================================================================

/// Open the channel for `role`, running the whole establishment flow and funding it.
fn open_channel(role: ChannelRole) -> crate::state_machine::EstablishedChannelState {
    let (mut merchant, mut customer) = establish_to_init_packages();
    fund_both(&mut merchant, &mut customer);
    match role {
        ChannelRole::Merchant => merchant.into_inner().next().expect("merchant opens the channel"),
        ChannelRole::Customer => customer.into_inner().next().expect("customer opens the channel"),
    }
}

/// Both halves travel in the two packages, so once they have been exchanged both parties assemble the same
/// cross-signed record — byte-identical, not merely agreeing on its fields — and it verifies under the two
/// wallet keys the arbiter would be registered with.
#[test]
fn both_parties_hold_the_same_cross_signed_state_0_record() {
    let (merchant, customer) = establish_to_init_packages();
    let from_merchant = merchant.state().initial_record().expect("the merchant assembles the record");
    let from_customer = customer.state().initial_record().expect("the customer assembles the record");
    assert_eq!(from_merchant, from_customer);
    assert_eq!(from_merchant.update_count(), 0);
    assert_eq!(from_merchant.channel_id(), &merchant.state().channel_id());

    let customer_key = wallet_of_customer(&customer).my_public_key().as_point();
    let merchant_key = wallet_of_merchant(&merchant).my_public_key().as_point();
    from_merchant.verify(&customer_key, &merchant_key).expect("the record verifies under the wallet keys");
    // The record commits to the pair hash, not to either party's own exit.
    assert_eq!(
        from_merchant.close_hash(),
        &merchant.state().initial_record_close_hash().expect("the id is final")
    );
    assert_ne!(
        from_merchant.close_hash(),
        &merchant.state().initial_close_hash(ChannelRole::Merchant).expect("the id is final")
    );
}

/// The channel is disputable from the instant it opens: `Open` carries a state-0 [`AppliedUpdate`], not an empty
/// history that only the first payment fills in.
#[test]
fn an_open_channel_has_a_state_0_record_from_the_moment_it_opens() {
    let open = open_channel(ChannelRole::Merchant);
    assert!(open.has_updates());
    assert_eq!(open.current_record().expect("a state-0 record").update_count(), 0);
    assert!(
        open.current_update().expect("a state-0 update").proof_matches_presignature(),
        "the retained proof must open the pre-signature it is stored with"
    );
    assert_eq!(open.update_history().retained_counts(), vec![0]);
}

/// `get_close_record` reads the current witness, which used to panic on a channel with no updates, and `close`
/// used to refuse outright. A cooperative close at state 0 is now possible — which is what makes an abandoned
/// establishment recoverable without the arbiter.
#[test]
fn a_freshly_opened_channel_can_be_closed_cooperatively() {
    let open = open_channel(ChannelRole::Customer);
    let close_record = open.get_close_record();
    assert_eq!(close_record.update_count, 0);
    assert_eq!(close_record.final_balance, open.dynamic.current_balances);
    open.close(close_record).map_err(|(_, e)| e).expect("a state-0 channel closes cooperatively");
}

/// The broadcast gate of §preSigning step 5: a funding party must hold the counterparty's package before it
/// parts with its money. Sending our own half is not enough — it leaves us with no exit we can complete and no
/// record we can present.
#[test]
fn funding_is_refused_until_the_peer_package_arrives() {
    let (mut merchant, mut customer) = establish_to_declarations();
    assert!(!customer.state().ready_to_fund(), "a provisional id is not fundable");

    merchant.state_mut().save_funding_tx_pipe(vec![]);
    customer.state_mut().save_funding_tx_pipe(vec![]);
    inject_signing_shares(&mut merchant, &mut customer);
    finalize_channel_ids(&mut merchant, &mut customer);
    assert!(!customer.state().ready_to_fund(), "a final id alone is not enough");

    let customer_pkg = customer.generate_init_package(&mut OsRng).expect("customer init package");
    assert!(!customer.state().ready_to_fund(), "sending our own package does not make us safe");
    assert!(!merchant.state().ready_to_fund());

    merchant.receive_customer_init_package(customer_pkg).expect("merchant receives customer package");
    assert!(merchant.state().ready_to_fund(), "the merchant holds the customer's exit and record half");
    assert!(!customer.state().ready_to_fund(), "the customer still holds nothing of the merchant's");

    let merchant_pkg = merchant.generate_init_package(&mut OsRng).expect("merchant init package");
    customer.receive_merchant_init_package(merchant_pkg).expect("customer receives merchant package");
    assert!(customer.state().ready_to_fund());
}

// ============================================================================
// Other missing-information errors
// ============================================================================

/// preprepare_data() when empty returns MissingInformation.
#[test]
fn preprepare_data_before_preparation() {
    let (merchant, _) = propose_channel();
    match merchant.preprepare_data() {
        Err(EstablishError::MissingInformation(msg)) => {
            assert!(msg.contains("Preprepare"), "error should mention preprepare: {msg}");
        }
        other => panic!("expected MissingInformation, got: {other:?}"),
    }
}

/// The adaptor signature adapts the FROST partial signature, so it needs one.
#[test]
fn no_init_package_without_a_signing_share() {
    let (mut merchant, mut customer) = establish_to_declarations();
    finalize_channel_ids(&mut merchant, &mut customer);

    match customer.generate_init_package(&mut OsRng) {
        Err(EstablishError::MissingInformation(msg)) => {
            assert!(msg.contains("signing share"), "msg: {msg}");
        }
        other => panic!("expected MissingInformation about the signing share, got: {other:?}"),
    }
}

// ============================================================================
// Funding edge cases
// ============================================================================

/// No transactions → funding_total is 0.
#[test]
fn funding_total_empty() {
    let (merchant, _) = propose_channel();
    assert_eq!(merchant.funding_total(), MoneroAmount::from_piconero(0));
}

/// Multiple transactions sum correctly.
#[test]
fn funding_total_accumulates() {
    let (mut merchant, _) = propose_channel();
    merchant.funding_tx_confirmed(fake_tx("tx1", MoneroAmount::from_piconero(100)));
    merchant.funding_tx_confirmed(fake_tx("tx2", MoneroAmount::from_piconero(200)));
    merchant.funding_tx_confirmed(fake_tx("tx3", MoneroAmount::from_piconero(300)));
    assert_eq!(merchant.funding_total(), MoneroAmount::from_piconero(600));
}

/// Same tx_id inserted twice → HashMap last-write-wins.
#[test]
fn duplicate_tx_id_overwrites() {
    let (mut merchant, _) = propose_channel();
    merchant.funding_tx_confirmed(fake_tx("same_tx", MoneroAmount::from_piconero(100)));
    merchant.funding_tx_confirmed(fake_tx("same_tx", MoneroAmount::from_piconero(500)));
    // HashMap overwrites: only the last value for "same_tx" is stored
    assert_eq!(merchant.funding_total(), MoneroAmount::from_piconero(500));
}

// ============================================================================
// The package in isolation: tampering, replay, swapped roles
// ============================================================================

mod package {
    use super::*;
    use crate::channel_id::ChannelId;
    use crate::cryptography::attestation::test_helpers::generate_master_keypair;
    use crate::cryptography::attestation::{G2Point, Statement};
    use crate::cryptography::binding_proof::{prove_encrypted_offset, BindingProofError};
    use crate::cryptography::pvss::SecondBase;
    use crate::grease_protocol::adapter_signature::adapter_signature_message;
    use crate::grease_protocol::establish_channel::INITIAL_UPDATE_COUNT;
    use crate::grease_protocol::update_record::{CloseHash, HalfSignedUpdateRecord, UpdateRecordError};
    use crate::wallet::multisig_wallet::{commitment_pair_message, commitment_tx_message};
    use std::str::FromStr;
    use zeroize::Zeroizing;

    fn channel_id() -> ChannelId {
        ChannelId::from_str("XGC4a7024e7fd6f5c6a2d0131d12fd91ecd17f5da61c2970d603a05053b41a383").unwrap()
    }

    struct Party {
        secret: XmrScalar,
        pubkey: XmrPoint,
        /// The canonical hash of the closing transaction *this* party holds — the one the counterparty
        /// adapter-signs.
        close_hash: CloseHash,
    }

    fn party(close_hash: CloseHash) -> Party {
        let secret = XmrScalar::random(&mut OsRng);
        let pubkey = Ed25519::generator() * secret;
        Party { secret, pubkey, close_hash }
    }

    struct Channel {
        id: ChannelId,
        arbiter_pk: G2Point,
        customer: Party,
        merchant: Party,
        /// The canonical hash of the *pair* of state-0 exits — the one hash the record commits to.
        record_close_hash: CloseHash,
    }

    fn channel() -> Channel {
        let (_, arbiter_pk) = generate_master_keypair(&mut OsRng);
        let id = channel_id();
        // Each party holds its own closing transaction at state 0, separated by the holder tag, so the two
        // close hashes differ and the swapped-role tests below are meaningful.
        let customer_close = CloseHash::try_from(commitment_tx_message(&id, 0, ChannelRole::Customer, 700, 300)).unwrap();
        let merchant_close = CloseHash::try_from(commitment_tx_message(&id, 0, ChannelRole::Merchant, 700, 300)).unwrap();
        assert_ne!(customer_close, merchant_close);
        let record_close_hash = CloseHash::try_from(commitment_pair_message(&id, 0, 700, 300)).unwrap();
        Channel {
            id,
            arbiter_pk,
            customer: party(customer_close),
            merchant: party(merchant_close),
            record_close_hash,
        }
    }

    /// A party's half of the state-0 record: over the pair hash, under its own key.
    fn record_half(ch: &Channel, signer: ChannelRole) -> HalfSignedUpdateRecord {
        let secret = match signer {
            ChannelRole::Customer => &ch.customer.secret,
            ChannelRole::Merchant => &ch.merchant.secret,
        };
        HalfSignedUpdateRecord::sign(
            ch.id.clone(),
            INITIAL_UPDATE_COUNT,
            ch.record_close_hash,
            signer,
            secret,
            &mut OsRng,
        )
        .expect("the fixture id is final")
    }

    /// Both parties create their packages: each adapter-signs the *counterparty's* closing transaction.
    fn create_packages(ch: &Channel) -> (ChannelInitPackage, Zeroizing<XmrScalar>, ChannelInitPackage, Zeroizing<XmrScalar>) {
        let mut rng = OsRng;
        let (customer_pkg, customer_omega) = ChannelInitPackage::create(
            &ch.id,
            &ch.merchant.close_hash,
            &ch.customer.secret,
            record_half(ch, ChannelRole::Customer),
            &ch.arbiter_pk,
            test_params(),
            &mut rng,
        )
        .expect("customer package");
        let (merchant_pkg, merchant_omega) = ChannelInitPackage::create(
            &ch.id,
            &ch.customer.close_hash,
            &ch.merchant.secret,
            record_half(ch, ChannelRole::Merchant),
            &ch.arbiter_pk,
            test_params(),
            &mut rng,
        )
        .expect("merchant package");
        (customer_pkg, customer_omega, merchant_pkg, merchant_omega)
    }

    /// The merchant verifies a package that claims to come from the customer.
    fn verify_as_merchant(ch: &Channel, pkg: &ChannelInitPackage) -> Result<(), EstablishError> {
        pkg.verify(
            &ch.id,
            &ch.merchant.close_hash,
            &ch.record_close_hash,
            ChannelRole::Merchant,
            &ch.customer.pubkey,
            &ch.arbiter_pk,
        )
    }

    /// The customer verifies a package that claims to come from the merchant.
    fn verify_as_customer(ch: &Channel, pkg: &ChannelInitPackage) -> Result<(), EstablishError> {
        pkg.verify(
            &ch.id,
            &ch.customer.close_hash,
            &ch.record_close_hash,
            ChannelRole::Customer,
            &ch.merchant.pubkey,
            &ch.arbiter_pk,
        )
    }

    #[test]
    fn round_trip() {
        let ch = channel();
        let (customer_pkg, customer_omega, merchant_pkg, _) = create_packages(&ch);
        verify_as_merchant(&ch, &customer_pkg).expect("customer package should verify");
        verify_as_customer(&ch, &merchant_pkg).expect("merchant package should verify");
        // The binding proof's target is exactly the adaptor point of the adapted signature
        assert_eq!(customer_pkg.adapted_signature.adapter_commitment(), *customer_pkg.binding_proof.q());
        // Revealing ω completes the closing signature the customer adapter-signed for the merchant
        let msg = adapter_signature_message(&ch.id, INITIAL_UPDATE_COUNT, &ch.merchant.close_hash).unwrap();
        let completed = customer_pkg
            .adapted_signature
            .adapt(&customer_omega, &ch.customer.pubkey, &msg)
            .expect("revealed offset should complete the signature");
        assert!(completed.verify(&ch.customer.pubkey, &msg));
    }

    /// A package survives the serialization round trip it makes over the wire.
    #[test]
    fn serde_round_trip() {
        let ch = channel();
        let (customer_pkg, ..) = create_packages(&ch);
        let encoded = ron::to_string(&customer_pkg).expect("serialize");
        let decoded: ChannelInitPackage = ron::from_str(&encoded).expect("deserialize");
        assert_eq!(decoded, customer_pkg);
        verify_as_merchant(&ch, &decoded).expect("a round-tripped package still verifies");
        // The record half is a signature over a wire message; it must survive the trip as a signature, not
        // merely as equal bytes.
        decoded.record_half.verify(&ch.customer.pubkey).expect("the decoded half still verifies");
    }

    /// Offsets are fresh per party and per package: never derived, never reused.
    #[test]
    fn offsets_are_independent() {
        let ch = channel();
        let (customer_pkg, _, merchant_pkg, _) = create_packages(&ch);
        let (customer_pkg2, ..) = create_packages(&ch);
        let q_customer = customer_pkg.adapted_signature.adapter_commitment();
        assert_ne!(q_customer, merchant_pkg.adapted_signature.adapter_commitment());
        assert_ne!(q_customer, customer_pkg2.adapted_signature.adapter_commitment());
    }

    /// An adapted signature forged with random keys fails the adaptor-sig check.
    #[test]
    fn tampered_adapted_signature() {
        let ch = channel();
        let (mut customer_pkg, ..) = create_packages(&ch);
        let random_secret = XmrScalar::random(&mut OsRng);
        let random_payload = XmrScalar::random(&mut OsRng);
        customer_pkg.adapted_signature = AdaptedSignature::<Ed25519>::sign(&random_secret, &random_payload, b"fake", &mut OsRng);
        match verify_as_merchant(&ch, &customer_pkg) {
            Err(EstablishError::InvalidDataFromPeer(_)) => {}
            other => panic!("expected InvalidDataFromPeer, got: {other:?}"),
        }
    }

    /// An honest binding proof for a *different* offset no longer targets the adaptor point Q.
    #[test]
    fn tampered_binding_proof() {
        let ch = channel();
        let (mut customer_pkg, ..) = create_packages(&ch);
        let other_omega = XmrScalar::random(&mut OsRng);
        let statement = Statement::new(ch.id.as_str(), INITIAL_UPDATE_COUNT);
        customer_pkg.binding_proof =
            prove_encrypted_offset(&other_omega, &statement, &ch.arbiter_pk, SecondBase::grease_default(), test_params())
                .expect("honest proof for a different offset");
        match verify_as_merchant(&ch, &customer_pkg) {
            Err(EstablishError::BindingProof(BindingProofError::TargetMismatch)) => {}
            other => panic!("expected BindingProof(TargetMismatch), got: {other:?}"),
        }
    }

    /// The merchant's own package replayed back as if it were the customer's: the adapted signature was made
    /// with the merchant's key over the *customer's* closing transaction, so both bindings fail.
    #[test]
    fn replayed_merchant_package_as_customer() {
        let ch = channel();
        let (_, _, merchant_pkg, _) = create_packages(&ch);
        match verify_as_merchant(&ch, &merchant_pkg) {
            Err(EstablishError::InvalidDataFromPeer(_)) => {}
            other => panic!("expected InvalidDataFromPeer, got: {other:?}"),
        }
    }

    /// Swapped-role presentation: the customer's package offered to the customer as if from the merchant.
    #[test]
    fn swapped_role_packages() {
        let ch = channel();
        let (customer_pkg, _, merchant_pkg, _) = create_packages(&ch);
        match verify_as_customer(&ch, &customer_pkg) {
            Err(EstablishError::InvalidDataFromPeer(_)) => {}
            other => panic!("expected InvalidDataFromPeer, got: {other:?}"),
        }
        match verify_as_merchant(&ch, &merchant_pkg) {
            Err(EstablishError::InvalidDataFromPeer(_)) => {}
            other => panic!("expected InvalidDataFromPeer, got: {other:?}"),
        }
    }

    /// The adapter-signature message binds the channel id, so a package presented for a different channel fails
    /// at the adaptor-sig check.
    #[test]
    fn wrong_channel_id() {
        let ch = channel();
        let (customer_pkg, ..) = create_packages(&ch);
        let other_id = ChannelId::from_str("XGC4a7024e7fd6f5c6a2d0131d12fd91ecd17f5da61c2970d603a05053b41a384").unwrap();
        match customer_pkg.verify(
            &other_id,
            &ch.merchant.close_hash,
            &ch.record_close_hash,
            ChannelRole::Merchant,
            &ch.customer.pubkey,
            &ch.arbiter_pk,
        ) {
            Err(EstablishError::InvalidDataFromPeer(_)) => {}
            other => panic!("expected InvalidDataFromPeer, got: {other:?}"),
        }
    }

    // ------------------------------------------------------------------------
    // The record half: what a counterparty must refuse
    // ------------------------------------------------------------------------

    /// A half signed under the receiver's own role is not a counterparty signature at all, and pairing it with
    /// our own would yield two halves of the same role rather than a cross-signed record.
    #[test]
    fn a_record_half_signed_by_the_wrong_role_is_rejected() {
        let ch = channel();
        let (mut customer_pkg, ..) = create_packages(&ch);
        customer_pkg.record_half = record_half(&ch, ChannelRole::Merchant);
        match verify_as_merchant(&ch, &customer_pkg) {
            Err(EstablishError::Record(UpdateRecordError::RoleMismatch {
                expected: ChannelRole::Customer,
                actual: ChannelRole::Merchant,
            })) => {}
            other => panic!("expected Record(RoleMismatch), got: {other:?}"),
        }
    }

    /// The state a record speaks about is signed, so a half for state 1 is not a half of state 0's record. It is
    /// refused twice over: `create` will not build a package around it, and `verify` will not accept one.
    #[test]
    fn a_record_half_for_another_state_is_rejected() {
        let ch = channel();
        let wrong_state = HalfSignedUpdateRecord::sign(
            ch.id.clone(),
            INITIAL_UPDATE_COUNT + 1,
            ch.record_close_hash,
            ChannelRole::Customer,
            &ch.customer.secret,
            &mut OsRng,
        )
        .expect("the fixture id is final");

        let refused = ChannelInitPackage::create(
            &ch.id,
            &ch.merchant.close_hash,
            &ch.customer.secret,
            wrong_state.clone(),
            &ch.arbiter_pk,
            test_params(),
            &mut OsRng,
        );
        assert!(matches!(refused, Err(EstablishError::MismatchedRecordHalf(_))), "create must refuse it locally");

        let (mut customer_pkg, ..) = create_packages(&ch);
        customer_pkg.record_half = wrong_state;
        match verify_as_merchant(&ch, &customer_pkg) {
            Err(EstablishError::MismatchedRecordHalf(id)) => assert_eq!(id, ch.id),
            other => panic!("expected MismatchedRecordHalf, got: {other:?}"),
        }
    }

    /// The pair-hash decision, pinned. A half over one holder's own exit hash — the obvious wrong answer, since
    /// that is what the adaptor signatures sign — is not a half of this state's record.
    #[test]
    fn a_record_half_over_a_different_close_hash_is_rejected() {
        let ch = channel();
        let (mut customer_pkg, ..) = create_packages(&ch);
        customer_pkg.record_half = HalfSignedUpdateRecord::sign(
            ch.id.clone(),
            INITIAL_UPDATE_COUNT,
            ch.customer.close_hash,
            ChannelRole::Customer,
            &ch.customer.secret,
            &mut OsRng,
        )
        .expect("the fixture id is final");
        match verify_as_merchant(&ch, &customer_pkg) {
            Err(EstablishError::MismatchedRecordHalf(id)) => assert_eq!(id, ch.id),
            other => panic!("expected MismatchedRecordHalf, got: {other:?}"),
        }
    }

    /// Well-formed fields under a key that is not the counterparty's: only the Schnorr check catches it.
    #[test]
    fn a_record_half_signed_by_a_stranger_is_rejected() {
        let ch = channel();
        let (mut customer_pkg, ..) = create_packages(&ch);
        let stranger = XmrScalar::random(&mut OsRng);
        customer_pkg.record_half = HalfSignedUpdateRecord::sign(
            ch.id.clone(),
            INITIAL_UPDATE_COUNT,
            ch.record_close_hash,
            ChannelRole::Customer,
            &stranger,
            &mut OsRng,
        )
        .expect("the fixture id is final");
        match verify_as_merchant(&ch, &customer_pkg) {
            Err(EstablishError::Record(UpdateRecordError::InvalidSignature(ChannelRole::Customer))) => {}
            other => panic!("expected Record(InvalidSignature(Customer)), got: {other:?}"),
        }
    }
}

// ============================================================================
// The abandonment claim, end to end
//
// §preSigning promises that a funding party which broadcasts and is then abandoned "closes at state 0 and
// recovers its deposit". That claim rests entirely on there being a cross-signed state-0 record to present, so
// it is worth running against a real arbiter rather than asserting about.
// ============================================================================

mod state_zero_dispute {
    use super::*;
    use crate::arbiter::client::TransportKeyPair;
    use crate::arbiter::mock::{ManualClock, MockArbiter};
    use crate::grease_protocol::adapter_signature::adapter_signature_message;
    use crate::grease_protocol::establish_channel::INITIAL_UPDATE_COUNT;
    use crate::grease_protocol::force_close_channel::{ForceCloseProtocolClaimant, ForceCloseProtocolCommon};
    use crate::state_machine::{DisputeReason, DisputingChannelState};
    use crate::tests::propose_channel_tests::default_arbiter_master_keypair;
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::Duration;

    const DAY: Duration = Duration::from_secs(86_400);

    fn block_on<F: std::future::Future>(f: F) -> F::Output {
        futures::executor::block_on(f)
    }

    /// The customer funds, the merchant stops answering, and the customer closes on state 0 alone.
    ///
    /// Everything on the path comes out of the real establishment flow: the record is the one the two packages
    /// cross-signed, the proof and pre-signature are the ones the open channel retained, and the arbiter holds
    /// the master key the channel pinned during negotiation.
    #[test]
    fn an_abandoned_funder_can_force_close_at_state_0() {
        let (mut merchant, mut customer) = establish_to_init_packages();
        fund_both(&mut merchant, &mut customer);

        // Captured before the transition consumes the establishing states.
        let own_close_hash =
            customer.state().initial_close_hash(ChannelRole::Customer).expect("the id is final");
        let customer_pubkey = wallet_of_customer(&customer).my_public_key().as_point();
        let merchant_pubkey = wallet_of_merchant(&merchant).my_public_key().as_point();
        let merchant_omega: XmrScalar = **merchant.state().initial_offset.as_ref().expect("the merchant's ω");

        let open = customer.into_inner().next().expect("the customer opens the channel");
        let channel_id = open.metadata.channel_id().name();

        // An arbiter holding the very key the channel sealed its offsets to.
        let (z, big_z) = default_arbiter_master_keypair();
        let config = open.metadata.arbiter_configuration().clone();
        assert_eq!(&big_z, config.master_public_key(), "the mock must be the arbiter the channel agreed on");
        let clock = Arc::new(ManualClock::default());
        let arbiter = MockArbiter::new(config, z, clock.clone());
        arbiter
            .register_channel(channel_id.clone(), customer_pubkey, merchant_pubkey)
            .expect("a finalized id registers once");

        let dispute_state = || {
            DisputingChannelState::from_open_channel(
                open.metadata.clone(),
                open.dynamic.clone(),
                DisputeReason::ForceCloseInitiated,
                open.multisig_wallet.clone(),
                HashMap::new(),
                open.current_update().expect("the open channel holds state 0").clone(),
            )
        };
        let mut disputing = dispute_state();

        block_on(disputing.present_record(&arbiter)).expect("the state-0 record opens an adjudication window");
        clock.advance(DAY);

        let transport = TransportKeyPair::from_seed([0x43; 32]);
        let sigma = block_on(disputing.collect_attestation(&arbiter, &transport)).expect("the window elapsed");
        let proof = disputing.peer_binding_proof().expect("retained by the open channel").clone();
        let statement = disputing.statement(INITIAL_UPDATE_COUNT).expect("the id is final");
        let omega = disputing.recover_offset(&proof, &statement, &sigma).expect("the attestation opens state 0");
        assert_eq!(omega, merchant_omega, "recovery must produce the abandoning party's offset");

        // The one-call close, on a second state object built from the same open channel. The pre-signature it
        // completes came out of a real `generate_init_package` → `ChannelInitPackage::create`, so this is what
        // pins the dispute path and establishment onto the same adaptor message.
        let mut again = dispute_state();
        let signature = block_on(again.complete_force_close(&arbiter, &transport))
            .expect("the recovered offset completes the pre-signature the merchant sent");
        let msg =
            adapter_signature_message(&channel_id, INITIAL_UPDATE_COUNT, &own_close_hash).expect("the id is final");
        assert!(signature.verify(&merchant_pubkey, &msg));
    }
}
