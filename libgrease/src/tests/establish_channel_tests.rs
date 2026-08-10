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
use crate::grease_protocol::establish_channel::{ChannelInitPackage, EstablishError};
use crate::monero::data_objects::{TransactionId, TransactionRecord};
use crate::payment_channel::ChannelRole;
use crate::state_machine::error::LifeCycleError;
use crate::state_machine::{CustomerEstablishing, MerchantEstablishing};
use crate::{XmrPoint, XmrScalar};
use crate::Ed25519;
use ciphersuite::WrappedGroup;
use rand_core::OsRng;

use super::propose_channel_tests::propose_channel;

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

/// Exchange partial linking tags and bind both parties' channel ids to the funding output.
///
/// Returns the final id, which both sides must agree on.
pub(crate) fn finalize_channel_ids(
    merchant: &mut MerchantEstablishing,
    customer: &mut CustomerEstablishing,
) -> ChannelId {
    let merchant_partial = merchant.partial_linking_tag().expect("merchant partial linking tag");
    let customer_partial = customer.partial_linking_tag().expect("customer partial linking tag");
    let merchant_id = merchant.finalize_channel_id(&customer_partial).expect("merchant finalizes the id");
    let customer_id = customer.finalize_channel_id(&merchant_partial).expect("customer finalizes the id");
    assert_eq!(merchant_id, customer_id, "both parties must derive the same final channel id");
    merchant_id
}

/// Wallet setup, signing shares, funding-tx watcher and channel-id finalization: everything up to, but not
/// including, the initial-state package exchange.
pub(crate) fn establish_to_final_id() -> (MerchantEstablishing, CustomerEstablishing) {
    let (mut merchant, mut customer) = wrapped_parties();
    establish_wallet(&mut merchant, &mut customer);
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

/// Finalizing replaces the provisional id with a 65-character `XGC…` id that commits to `L_F`.
#[test]
fn finalization_binds_the_id_to_the_funding_output() {
    let (mut merchant, mut customer) = wrapped_parties();
    establish_wallet(&mut merchant, &mut customer);
    let provisional = merchant.state().channel_id();

    let final_id = finalize_channel_ids(&mut merchant, &mut customer);

    assert!(final_id.is_finalized());
    assert!(final_id.as_str().starts_with(ChannelId::PREFIX_FINAL));
    assert_eq!(final_id.as_str().len(), ChannelId::LENGTH);
    assert_ne!(final_id, provisional, "binding L_F must change the id");
    assert_eq!(
        merchant.state().channel_id_metadata().linking_tag(),
        customer.state().channel_id_metadata().linking_tag(),
        "both parties must bind the same L_F"
    );
}

/// Neither party can compute `L_F` alone: the partials differ and neither equals the sum.
#[test]
fn the_linking_tag_needs_both_partials() {
    let (mut merchant, mut customer) = wrapped_parties();
    establish_wallet(&mut merchant, &mut customer);

    let merchant_partial = merchant.partial_linking_tag().expect("merchant partial");
    let customer_partial = customer.partial_linking_tag().expect("customer partial");
    assert_ne!(merchant_partial, customer_partial);

    finalize_channel_ids(&mut merchant, &mut customer);
    let l_f = *merchant.state().channel_id_metadata().linking_tag().expect("L_F is bound");
    assert_eq!(l_f, merchant_partial + customer_partial);
    assert_ne!(l_f, merchant_partial);
    assert_ne!(l_f, customer_partial);
}

/// A different shared wallet gives a different `L_F`, and therefore a different channel id.
#[test]
fn a_different_wallet_gives_a_different_id() {
    let (mut merchant_a, mut customer_a) = wrapped_parties();
    establish_wallet(&mut merchant_a, &mut customer_a);
    let id_a = finalize_channel_ids(&mut merchant_a, &mut customer_a);

    let (mut merchant_b, mut customer_b) = wrapped_parties();
    establish_wallet(&mut merchant_b, &mut customer_b);
    let id_b = finalize_channel_ids(&mut merchant_b, &mut customer_b);

    assert_ne!(id_a, id_b);
}

/// The id is bound to a funding output exactly once.
#[test]
fn a_final_id_cannot_be_rebound() {
    let (mut merchant, mut customer) = wrapped_parties();
    establish_wallet(&mut merchant, &mut customer);
    let customer_partial = customer.partial_linking_tag().expect("customer partial");
    finalize_channel_ids(&mut merchant, &mut customer);

    match merchant.finalize_channel_id(&customer_partial) {
        Err(EstablishError::ChannelIdFinalize(ChannelIdFinalizeError::AlreadyFinalized)) => {}
        other => panic!("expected AlreadyFinalized, got: {other:?}"),
    }
}

/// The linking tag cannot be derived before the shared wallet exists.
#[test]
fn no_linking_tag_without_a_wallet() {
    let (merchant, _) = wrapped_parties();
    match merchant.partial_linking_tag() {
        Err(EstablishError::MissingInformation(msg)) => assert!(msg.contains("wallet"), "msg: {msg}"),
        other => panic!("expected MissingInformation about the wallet, got: {other:?}"),
    }
}

/// Every signature in an init package commits to the channel id, so no package may be built against the
/// provisional one.
#[test]
fn no_init_package_before_the_id_is_final() {
    let (mut merchant, mut customer) = wrapped_parties();
    establish_wallet(&mut merchant, &mut customer);
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
        // The payload signature commits to the binding proof, so the swap is caught there first.
        Err(EstablishError::InvalidPayloadSignature(_)) | Err(EstablishError::BindingProof(_)) => {}
        other => panic!("expected the swapped binding proof to be rejected, got: {other:?}"),
    }
}

/// The payload signature binds the sealed offset: swapping it for another party's is detected.
#[test]
fn a_swapped_encrypted_offset_is_rejected() {
    let (mut merchant, _customer, mut package) = customer_package();
    let (_, mut other_customer) = establish_to_final_id();
    let other = other_customer.generate_init_package(&mut OsRng).expect("another party's package");
    package.encrypted_offset = other.encrypted_offset;

    match merchant.receive_customer_init_package(package) {
        Err(EstablishError::InvalidPayloadSignature(_)) => {}
        other => panic!("expected InvalidPayloadSignature, got: {other:?}"),
    }
}

/// Swapping the nonce_pubkey for a random point invalidates the payload signature.
#[test]
fn a_tampered_nonce_pubkey_is_rejected() {
    let (mut merchant, _customer, mut package) = customer_package();
    package.nonce_pubkey = Ed25519::generator() * XmrScalar::random(&mut OsRng);

    match merchant.receive_customer_init_package(package) {
        Err(EstablishError::InvalidPayloadSignature(_)) => {}
        other => panic!("expected InvalidPayloadSignature, got: {other:?}"),
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

/// A rejected package leaves the state untouched: nothing half-accepted is stored.
#[test]
fn a_rejected_package_is_not_stored() {
    let (mut merchant, _customer, mut package) = customer_package();
    package.nonce_pubkey = Ed25519::generator() * XmrScalar::random(&mut OsRng);
    assert!(merchant.receive_customer_init_package(package).is_err());
    assert!(merchant.state().peer_init_package().is_none());
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
    );
    let completed = package
        .adapted_signature
        .adapt(omega, &customer_wallet_key, &msg)
        .expect("the revealed offset completes the signature");
    assert!(completed.verify(&customer_wallet_key, &msg));
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
    let (mut merchant, mut customer) = wrapped_parties();
    establish_wallet(&mut merchant, &mut customer);
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
    use crate::grease_protocol::update_record::CloseHash;
    use crate::wallet::multisig_wallet::commitment_tx_message;
    use std::str::FromStr;
    use std::time::Duration;
    use zeroize::Zeroizing;

    const DISPUTE_WINDOW: Duration = Duration::from_secs(86_400);

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
    }

    fn channel() -> Channel {
        let (_, arbiter_pk) = generate_master_keypair(&mut OsRng);
        let id = channel_id();
        // Each party holds its own closing transaction at state 0, separated by the holder tag, so the two
        // close hashes differ and the swapped-role tests below are meaningful.
        let customer_close = CloseHash::try_from(commitment_tx_message(&id, 0, ChannelRole::Customer, 700, 300)).unwrap();
        let merchant_close = CloseHash::try_from(commitment_tx_message(&id, 0, ChannelRole::Merchant, 700, 300)).unwrap();
        assert_ne!(customer_close, merchant_close);
        Channel { id, arbiter_pk, customer: party(customer_close), merchant: party(merchant_close) }
    }

    /// Both parties create their packages: each adapter-signs the *counterparty's* closing transaction.
    fn create_packages(ch: &Channel) -> (ChannelInitPackage, Zeroizing<XmrScalar>, ChannelInitPackage, Zeroizing<XmrScalar>) {
        let mut rng = OsRng;
        let (customer_pkg, customer_omega) = ChannelInitPackage::create(
            &ch.id,
            &ch.merchant.close_hash,
            DISPUTE_WINDOW,
            &ch.customer.secret,
            &ch.arbiter_pk,
            test_params(),
            &mut rng,
        )
        .expect("customer package");
        let (merchant_pkg, merchant_omega) = ChannelInitPackage::create(
            &ch.id,
            &ch.customer.close_hash,
            DISPUTE_WINDOW,
            &ch.merchant.secret,
            &ch.arbiter_pk,
            test_params(),
            &mut rng,
        )
        .expect("merchant package");
        (customer_pkg, customer_omega, merchant_pkg, merchant_omega)
    }

    /// The merchant verifies a package that claims to come from the customer.
    fn verify_as_merchant(ch: &Channel, pkg: &ChannelInitPackage) -> Result<(), EstablishError> {
        pkg.verify(&ch.id, &ch.merchant.close_hash, DISPUTE_WINDOW, &ch.customer.pubkey, &ch.arbiter_pk)
    }

    /// The customer verifies a package that claims to come from the merchant.
    fn verify_as_customer(ch: &Channel, pkg: &ChannelInitPackage) -> Result<(), EstablishError> {
        pkg.verify(&ch.id, &ch.customer.close_hash, DISPUTE_WINDOW, &ch.merchant.pubkey, &ch.arbiter_pk)
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
        let msg = adapter_signature_message(&ch.id, INITIAL_UPDATE_COUNT, &ch.merchant.close_hash);
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

    /// Swapping the nonce_pubkey for a random point invalidates the payload signature.
    #[test]
    fn tampered_nonce_pubkey() {
        let ch = channel();
        let (mut customer_pkg, ..) = create_packages(&ch);
        customer_pkg.nonce_pubkey = Ed25519::generator() * XmrScalar::random(&mut OsRng);
        match verify_as_merchant(&ch, &customer_pkg) {
            Err(EstablishError::InvalidPayloadSignature(_)) => {}
            other => panic!("expected InvalidPayloadSignature, got: {other:?}"),
        }
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

    /// The payload signature binds the direct ciphertext: swapping it for the counterparty's is detected.
    #[test]
    fn tampered_encrypted_offset() {
        let ch = channel();
        let (mut customer_pkg, _, merchant_pkg, _) = create_packages(&ch);
        customer_pkg.encrypted_offset = merchant_pkg.encrypted_offset;
        match verify_as_merchant(&ch, &customer_pkg) {
            Err(EstablishError::InvalidPayloadSignature(_)) => {}
            other => panic!("expected InvalidPayloadSignature, got: {other:?}"),
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

    /// The payload signature binds the dispute window.
    #[test]
    fn wrong_dispute_window() {
        let ch = channel();
        let (customer_pkg, ..) = create_packages(&ch);
        let doubled = DISPUTE_WINDOW * 2;
        match customer_pkg.verify(&ch.id, &ch.merchant.close_hash, doubled, &ch.customer.pubkey, &ch.arbiter_pk) {
            Err(EstablishError::InvalidPayloadSignature(_)) => {}
            other => panic!("expected InvalidPayloadSignature, got: {other:?}"),
        }
    }

    /// The adapter-signature message binds the channel id, so a package presented for a different channel fails
    /// at the adaptor-sig check.
    #[test]
    fn wrong_channel_id() {
        let ch = channel();
        let (customer_pkg, ..) = create_packages(&ch);
        let other_id = ChannelId::from_str("XGC4a7024e7fd6f5c6a2d0131d12fd91ecd17f5da61c2970d603a05053b41a384").unwrap();
        match customer_pkg.verify(&other_id, &ch.merchant.close_hash, DISPUTE_WINDOW, &ch.customer.pubkey, &ch.arbiter_pk) {
            Err(EstablishError::InvalidDataFromPeer(_)) => {}
            other => panic!("expected InvalidDataFromPeer, got: {other:?}"),
        }
    }
}
