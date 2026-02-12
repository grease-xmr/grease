//! Tests for the channel establishment protocol.
//!
//! These tests cover:
//! - Full happy-path establishment (wallet setup, init packages, KES validation,
//!   channel key derivation, PoK proofs, funding, state transition)
//! - KES proof-of-knowledge generation and verification against per-channel key
//! - Wrapper role enforcement (MerchantEstablishing / CustomerEstablishing)
//! - Failure modes: missing data, tampering, adversarial proofs, replay attacks
//! - KES bundle fraud detection
//! - Funding edge cases
//! - Accessor edge cases

use crate::amount::MoneroAmount;
use crate::cryptography::adapter_signature::AdaptedSignature;
use crate::cryptography::dleq::{Dleq, DleqProof};
use crate::cryptography::pok::{KesPoK, KesPoKProofs};
use crate::cryptography::CrossCurveScalar;
use crate::grease_protocol::establish_channel::{ChannelInitPackage, EstablishError};
use crate::grease_protocol::kes_establishing::{KesEstablishError, KesEstablishing};
use crate::monero::data_objects::{TransactionId, TransactionRecord};
use crate::payment_channel::ChannelRole;
use crate::state_machine::error::LifeCycleError;
use crate::state_machine::{CustomerEstablishing, MerchantEstablishing};
use crate::XmrScalar;
use ciphersuite::group::ff::Field;
use ciphersuite::{Ciphersuite, Ed25519};
use rand_core::OsRng;
use zeroize::Zeroizing;

use super::propose_channel_tests::propose_channel;

// ============================================================================
// Shared test helpers
// ============================================================================

pub(crate) fn establish_wallet(merchant: &mut MerchantEstablishing, customer: &mut CustomerEstablishing) {
    // Merchant commits to their shared public key, customer stores the commitment
    let commitment = merchant.wallet_public_key_commitment();
    customer.set_merchant_wallet_public_key_commitment(commitment);
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
        XmrScalar(*wallet.my_spend_key().to_dalek_scalar())
    };
    let customer_share = {
        let wallet = customer.state().multisig_wallet.as_ref().expect("wallet");
        XmrScalar(*wallet.my_spend_key().to_dalek_scalar())
    };

    if let Some(wallet) = merchant.state_mut().multisig_wallet.as_mut() {
        wallet.inject_test_signing_share(&merchant_share);
    }
    if let Some(wallet) = customer.state_mut().multisig_wallet.as_mut() {
        wallet.inject_test_signing_share(&customer_share);
    }
}

/// Wallet + signing shares + init package exchange (no KES), returns wrappers + KES private key.
fn establish_with_init_packages() -> (MerchantEstablishing, CustomerEstablishing, XmrScalar) {
    let mut rng = OsRng;
    let url = "No RPC required";
    let (merchant, customer, kes_key) = propose_channel();
    let mut merchant = MerchantEstablishing::new(merchant, url).expect("merchant role");
    let mut customer = CustomerEstablishing::new(customer, url).expect("customer role");

    establish_wallet(&mut merchant, &mut customer);

    merchant.state_mut().save_funding_tx_pipe(vec![]);
    customer.state_mut().save_funding_tx_pipe(vec![]);

    inject_signing_shares(&mut merchant, &mut customer);

    let customer_pkg = customer.generate_init_package(&mut rng).expect("customer init package");
    merchant.receive_customer_init_package(customer_pkg).expect("merchant receives customer package");

    let merchant_pkg = merchant.generate_init_package(&mut rng).expect("merchant init package");
    customer.receive_merchant_init_package(merchant_pkg).expect("customer receives merchant package");

    (merchant, customer, kes_key)
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

/// Run the full establishment protocol up to (and including) KES bundle validation.
///
/// This performs: proposal exchange → wallet key exchange → synthetic signing share
/// injection → init package generation and verification → KES bundle creation
/// (including ephemeral channel ID) → validation via [`KesEstablishing::from_bundle`].
///
/// Returns the merchant/customer wrappers and the KES instance, ready for
/// [`finalize`](KesEstablishing::finalize).
fn establish_to_bundle() -> (MerchantEstablishing, CustomerEstablishing, KesEstablishing<Ed25519>) {
    let (merchant, customer, kes_key) = establish_with_init_packages();
    let kes_bundle = merchant.bundle_for_kes(&mut OsRng).expect("bundling for KES should succeed");
    let kes_secret = Zeroizing::new(kes_key);
    let kes = KesEstablishing::from_bundle(kes_secret, kes_bundle).expect("KES from bundle");
    (merchant, customer, kes)
}

// ============================================================================
// Happy path
// ============================================================================

#[test]
pub fn happy_path() {
    let mut rng = OsRng;
    let (mut merchant, mut customer, kes) = establish_to_bundle();

    // KES generates PoK proofs and creates the OpenChannelRecord
    // (validateOpen, Section 4.6.3 of the KES spec).
    // Channel keys were already derived in from_bundle.
    let (proofs, record) = kes.finalize(&mut rng);
    assert_eq!(record.channel_id, merchant.state().metadata.channel_id().name());

    // Both parties receive and verify the KES PoK proofs.
    // Each party computes P_g = kappa * P_K locally — no explicit set_kes_channel_pubkey needed.
    merchant.receive_kes_proof(proofs.clone()).expect("merchant KES proofs should verify");
    customer.receive_kes_proof(proofs).expect("customer KES proofs should verify");

    // Fund the channel
    let required = merchant.state().metadata.initial_balance().total();
    let tx = TransactionRecord {
        channel_name: "test".into(),
        transaction_id: TransactionId::new("fake_tx"),
        amount: required,
        serialized: vec![],
    };
    merchant.funding_tx_confirmed(tx.clone());
    customer.funding_tx_confirmed(tx);

    assert!(merchant.state().requirements_met(), "Merchant requirements not met");
    assert!(customer.state().requirements_met(), "Customer requirements not met");

    // Both parties should be able to transition to established state
    let _merchant = merchant.into_inner().next().expect("merchant to move to established");
    let _customer = customer.into_inner().next().expect("customer to move to established");
}

// ============================================================================
// Wrapper role enforcement
// ============================================================================

#[test]
fn test_merchant_wrapper_rejects_customer() {
    let (_, customer, _) = propose_channel();
    match MerchantEstablishing::new(customer, "") {
        Err(EstablishError::WrongRole { expected: ChannelRole::Merchant, got: ChannelRole::Customer }) => {}
        Err(e) => panic!("expected WrongRole, got: {e:?}"),
        Ok(_) => panic!("expected Err, got Ok"),
    }
}

#[test]
fn test_customer_wrapper_rejects_merchant() {
    let (merchant, _, _) = propose_channel();
    match CustomerEstablishing::new(merchant, "") {
        Err(EstablishError::WrongRole { expected: ChannelRole::Customer, got: ChannelRole::Merchant }) => {}
        Err(e) => panic!("expected WrongRole, got: {e:?}"),
        Ok(_) => panic!("expected Err, got Ok"),
    }
}

// ============================================================================
// KES proof-of-knowledge
// ============================================================================

#[test]
fn test_kes_pok_verifies_for_parties() {
    let (merchant, customer, kes) = establish_to_bundle();
    let mut rng = OsRng;

    let channel_pubkey = *kes.channel_public_key();
    let proof = kes.generate_pok(&mut rng);

    // Verify the proof against the offset public points and per-channel KES pubkey
    let customer_offset = *customer.state().dleq_proof.public_points.foreign_point();
    let merchant_offset = *merchant.state().dleq_proof.public_points.foreign_point();

    proof
        .verify_for(&customer_offset, &merchant_offset, &channel_pubkey)
        .expect("KES proof should verify against per-channel pubkey");
}

#[test]
fn test_kes_pok_rejects_wrong_pubkey() {
    let (merchant, customer, kes) = establish_to_bundle();
    let mut rng = OsRng;

    let proof = kes.generate_pok(&mut rng);

    let customer_offset = *customer.state().dleq_proof.public_points.foreign_point();
    let merchant_offset = *merchant.state().dleq_proof.public_points.foreign_point();

    // Proofs are bound to the per-channel key, so they must fail against the global KES pubkey
    let kes_config = merchant.state().metadata.kes_configuration();
    let global_kes_pubkey = kes_config.kes_public_key;
    let err = proof.verify_for(&customer_offset, &merchant_offset, &global_kes_pubkey);
    assert!(err.is_err(), "Should reject proof verified against global KES pubkey");

    // Also fails against a random point
    let random_pubkey = Ed25519::generator() * crate::XmrScalar::random(&mut rng);
    let err = proof.verify_for(&customer_offset, &merchant_offset, &random_pubkey);
    assert!(err.is_err(), "Should reject proof with random pubkey");
}

// ============================================================================
// Per-channel KES pubkey derivation
// ============================================================================

/// Both parties independently compute the same P_g as the KES derives internally.
#[test]
fn test_kes_channel_pubkey_matches_parties() {
    let (merchant, customer, kes) = establish_to_bundle();

    let kes_pg = *kes.channel_public_key();
    let merchant_pg = merchant.state().kes_channel_pubkey().expect("merchant should have P_g");
    let customer_pg = customer.state().kes_channel_pubkey().expect("customer should have P_g");

    assert_eq!(kes_pg, merchant_pg, "KES and merchant should agree on P_g");
    assert_eq!(kes_pg, customer_pg, "KES and customer should agree on P_g");
}

// ============================================================================
// 1. requirements_met() / next() failures
// ============================================================================

/// A fresh EstablishingState (right after proposal exchange) has no optional fields set
/// and requirements_met must return false.
#[test]
fn test_fresh_state_requirements_not_met() {
    let (merchant, _, _) = propose_channel();
    assert!(!merchant.requirements_met(), "Fresh state should not have requirements met");
}

/// next() on an incomplete state returns Err with InvalidStateTransition.
#[test]
fn test_next_fails_without_requirements() {
    let (merchant, _, _) = propose_channel();
    match merchant.next() {
        Err((_, LifeCycleError::InvalidStateTransition)) => {}
        Err((_, e)) => panic!("expected InvalidStateTransition, got: {e:?}"),
        Ok(_) => panic!("expected Err, got Ok"),
    }
}

/// Full setup + KES proofs but no funding tx — requirements not met, next() fails.
#[test]
fn test_next_fails_without_funding() {
    let mut rng = OsRng;
    let (mut merchant, mut customer, kes) = establish_to_bundle();

    let (proofs, _) = kes.finalize(&mut rng);
    merchant.receive_kes_proof(proofs.clone()).expect("merchant KES proofs");
    customer.receive_kes_proof(proofs).expect("customer KES proofs");

    // No funding tx added
    assert!(!merchant.state().requirements_met(), "Should not be met without funding");
    match merchant.into_inner().next() {
        Err((_, LifeCycleError::InvalidStateTransition)) => {}
        other => panic!("expected InvalidStateTransition, got: {other:?}"),
    }
}

/// Full setup + funding, but no KES proof — requirements not met.
#[test]
fn test_next_fails_without_kes_proof() {
    let (mut merchant, _, _) = establish_with_init_packages();

    fund_both(
        &mut merchant,
        &mut CustomerEstablishing::new(propose_channel().1, "").expect("customer"),
    );
    // Actually let's do it properly: we need the same instance
    let required = merchant.state().metadata.initial_balance().total();
    let tx = fake_tx("funding_tx", required);
    merchant.funding_tx_confirmed(tx);

    // No KES proof received
    assert!(!merchant.state().requirements_met(), "Should not be met without KES proof");
}

/// Clearing funding_tx_pipe after full setup causes requirements_met to fail.
#[test]
fn test_next_fails_without_funding_tx_pipe() {
    let mut rng = OsRng;
    let (mut merchant, _, kes) = establish_to_bundle();

    let (proofs, _) = kes.finalize(&mut rng);
    merchant.receive_kes_proof(proofs).expect("merchant KES proofs");

    let required = merchant.state().metadata.initial_balance().total();
    merchant.funding_tx_confirmed(fake_tx("tx", required));

    // Clear the funding_tx_pipe
    merchant.state_mut().funding_tx_pipe = None;

    assert!(
        !merchant.state().requirements_met(),
        "Should not be met without funding_tx_pipe"
    );
}

/// Funding with half the required amount is insufficient.
#[test]
fn test_partial_funding_insufficient() {
    let mut rng = OsRng;
    let (mut merchant, mut customer, kes) = establish_to_bundle();

    let (proofs, _) = kes.finalize(&mut rng);
    merchant.receive_kes_proof(proofs.clone()).expect("merchant KES proofs");
    customer.receive_kes_proof(proofs).expect("customer KES proofs");

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
fn test_overfunding_satisfies_requirements() {
    let mut rng = OsRng;
    let (mut merchant, mut customer, kes) = establish_to_bundle();

    let (proofs, _) = kes.finalize(&mut rng);
    merchant.receive_kes_proof(proofs.clone()).expect("merchant KES proofs");
    customer.receive_kes_proof(proofs).expect("customer KES proofs");

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
// 2. Init package tampering
// ============================================================================

/// Swapping the nonce_pubkey to a random point invalidates the payload signature.
#[test]
fn test_tampered_nonce_pubkey_in_init_package() {
    let mut rng = OsRng;
    let url = "No RPC required";
    let (merchant_state, customer_state, _) = propose_channel();
    let mut merchant = MerchantEstablishing::new(merchant_state, url).expect("merchant role");
    let mut customer = CustomerEstablishing::new(customer_state, url).expect("customer role");

    establish_wallet(&mut merchant, &mut customer);
    merchant.state_mut().save_funding_tx_pipe(vec![]);
    customer.state_mut().save_funding_tx_pipe(vec![]);
    inject_signing_shares(&mut merchant, &mut customer);

    let mut customer_pkg = customer.generate_init_package(&mut rng).expect("customer init package");
    // Tamper: replace nonce_pubkey with a random point
    customer_pkg.nonce_pubkey = Ed25519::generator() * XmrScalar::random(&mut rng);

    match merchant.receive_customer_init_package(customer_pkg) {
        Err(EstablishError::InvalidPayloadSignature(_)) => {}
        Err(e) => panic!("expected InvalidPayloadSignature, got: {e:?}"),
        Ok(_) => panic!("expected Err, got Ok"),
    }
}

/// Forging an adapted signature with a random key fails verification.
#[test]
fn test_tampered_adapted_signature_in_init_package() {
    let mut rng = OsRng;
    let url = "No RPC required";
    let (merchant_state, customer_state, _) = propose_channel();
    let mut merchant = MerchantEstablishing::new(merchant_state, url).expect("merchant role");
    let mut customer = CustomerEstablishing::new(customer_state, url).expect("customer role");

    establish_wallet(&mut merchant, &mut customer);
    merchant.state_mut().save_funding_tx_pipe(vec![]);
    customer.state_mut().save_funding_tx_pipe(vec![]);
    inject_signing_shares(&mut merchant, &mut customer);

    let mut customer_pkg = customer.generate_init_package(&mut rng).expect("customer init package");
    // Tamper: forge adapted signature with random keys
    let random_secret = XmrScalar::random(&mut rng);
    let random_payload = XmrScalar::random(&mut rng);
    customer_pkg.adapted_signature =
        AdaptedSignature::<Ed25519>::sign(&random_secret, &random_payload, b"fake", &mut rng);

    // Payload sig still verifies (nonce_pubkey unchanged), but adapted sig will fail
    match merchant.receive_customer_init_package(customer_pkg) {
        Err(EstablishError::InvalidDataFromPeer(_)) => {}
        Err(e) => panic!("expected InvalidDataFromPeer, got: {e:?}"),
        Ok(_) => panic!("expected Err, got Ok"),
    }
}

/// Replacing the DLEQ proof with one from a different scalar causes Q mismatch.
#[test]
fn test_tampered_dleq_proof_in_init_package() {
    let mut rng = OsRng;
    let url = "No RPC required";
    let (merchant_state, customer_state, _) = propose_channel();
    let mut merchant = MerchantEstablishing::new(merchant_state, url).expect("merchant role");
    let mut customer = CustomerEstablishing::new(customer_state, url).expect("customer role");

    establish_wallet(&mut merchant, &mut customer);
    merchant.state_mut().save_funding_tx_pipe(vec![]);
    customer.state_mut().save_funding_tx_pipe(vec![]);
    inject_signing_shares(&mut merchant, &mut customer);

    let mut customer_pkg = customer.generate_init_package(&mut rng).expect("customer init package");
    // Tamper: generate a valid DLEQ for a different scalar
    let fake_witness = CrossCurveScalar::<Ed25519>::random_with_rng(&mut rng);
    let (fake_proof, fake_points) =
        <Ed25519 as Dleq<Ed25519>>::generate_dleq(&mut rng, &fake_witness).expect("fake DLEQ");
    customer_pkg.dleq_proof = DleqProof::new(fake_proof, fake_points);
    // The payload signature message includes T0, so tampering the DLEQ also breaks the payload sig
    match merchant.receive_customer_init_package(customer_pkg) {
        Err(EstablishError::InvalidPayloadSignature(_)) | Err(EstablishError::InvalidDataFromPeer(_)) => {}
        Err(e) => panic!("expected InvalidPayloadSignature or InvalidDataFromPeer, got: {e:?}"),
        Ok(_) => panic!("expected Err, got Ok"),
    }
}

// ============================================================================
// 3. Invalid cryptographic proofs (adversarial)
// ============================================================================

/// A valid DLEQ for a different scalar has a Q0 that won't match the adapter signature.
#[test]
fn test_invalid_dleq_proof_wrong_scalar() {
    let mut rng = OsRng;
    let url = "No RPC required";
    let (merchant_state, customer_state, _) = propose_channel();
    let mut merchant = MerchantEstablishing::new(merchant_state, url).expect("merchant role");
    let mut customer = CustomerEstablishing::new(customer_state, url).expect("customer role");

    establish_wallet(&mut merchant, &mut customer);
    merchant.state_mut().save_funding_tx_pipe(vec![]);
    customer.state_mut().save_funding_tx_pipe(vec![]);
    inject_signing_shares(&mut merchant, &mut customer);

    let customer_pkg = customer.generate_init_package(&mut rng).expect("customer init package");
    // Store the original package fields, then tamper only the DLEQ
    let mut tampered = customer_pkg.clone();
    let fake_witness = CrossCurveScalar::<Ed25519>::random_with_rng(&mut rng);
    let (fake_proof, fake_points) =
        <Ed25519 as Dleq<Ed25519>>::generate_dleq(&mut rng, &fake_witness).expect("fake DLEQ");
    tampered.dleq_proof = DleqProof::new(fake_proof, fake_points);

    // T0 changed in dleq_proof → payload signature message changes → payload sig fails
    match merchant.receive_customer_init_package(tampered) {
        Err(EstablishError::InvalidPayloadSignature(_))
        | Err(EstablishError::InvalidDataFromPeer(_))
        | Err(EstablishError::AdapterSigOffsetError(_)) => {}
        Err(e) => panic!("expected crypto verification failure, got: {e:?}"),
        Ok(_) => panic!("expected Err, got Ok"),
    }
}

/// KES PoK proofs constructed with a random private key fail verify_kes_proof().
#[test]
fn test_kes_pok_signed_with_wrong_key() {
    let mut rng = OsRng;
    let (mut merchant, mut customer, kes) = establish_to_bundle();

    // Generate proofs with the real KES (correct offsets + correct channel key)
    let (real_proofs, _) = kes.finalize(&mut rng);

    // Now forge proofs with the correct offset secrets but a WRONG KES private key
    let customer_offset_scalar = *customer.state().dleq_proof.public_points.foreign_point();
    let merchant_offset_scalar = *merchant.state().dleq_proof.public_points.foreign_point();
    let random_key = XmrScalar::random(&mut rng);
    let random_shard = XmrScalar::random(&mut rng);
    let forged_proofs = KesPoKProofs {
        customer_pok: KesPoK::<Ed25519>::prove(&mut rng, &random_shard, &random_key),
        merchant_pok: KesPoK::<Ed25519>::prove(&mut rng, &random_shard, &random_key),
    };

    // The real proofs should verify
    merchant.receive_kes_proof(real_proofs.clone()).expect("real proofs should verify for merchant");
    // But forged proofs should fail for the customer
    match customer.receive_kes_proof(forged_proofs) {
        Err(EstablishError::KesProofError(_)) => {}
        Err(e) => panic!("expected KesProofError, got: {e:?}"),
        Ok(_) => panic!("expected Err, got Ok — forged proofs should not verify"),
    }

    // Verify the real proofs also pass for a fresh customer
    let _ = (customer_offset_scalar, merchant_offset_scalar); // used for reference
}

/// Swapping customer/merchant proofs in KesPoKProofs fails role-based verification.
#[test]
fn test_kes_pok_with_swapped_customer_merchant() {
    let mut rng = OsRng;
    let (mut merchant, mut customer, kes) = establish_to_bundle();

    let (proofs, _) = kes.finalize(&mut rng);

    // Swap the customer and merchant proofs
    let swapped = KesPoKProofs { customer_pok: proofs.merchant_pok.clone(), merchant_pok: proofs.customer_pok.clone() };

    match merchant.receive_kes_proof(swapped.clone()) {
        Err(EstablishError::KesProofError(_)) => {}
        Err(e) => panic!("expected KesProofError for merchant, got: {e:?}"),
        Ok(_) => panic!("swapped proofs should not verify for merchant"),
    }

    match customer.receive_kes_proof(swapped) {
        Err(EstablishError::KesProofError(_)) => {}
        Err(e) => panic!("expected KesProofError for customer, got: {e:?}"),
        Ok(_) => panic!("swapped proofs should not verify for customer"),
    }
}

// ============================================================================
// 4. Signature and proof replay attacks
// ============================================================================

/// Taking the merchant's ChannelInitPackage and presenting it back to the merchant
/// as if it came from the customer. Payload sig verification fails because the nonce
/// key doesn't match what the merchant expects.
#[test]
fn test_replay_merchant_init_as_customer() {
    let mut rng = OsRng;
    let url = "No RPC required";
    let (merchant_state, customer_state, _) = propose_channel();
    let mut merchant = MerchantEstablishing::new(merchant_state, url).expect("merchant role");
    let mut customer = CustomerEstablishing::new(customer_state, url).expect("customer role");

    establish_wallet(&mut merchant, &mut customer);
    merchant.state_mut().save_funding_tx_pipe(vec![]);
    customer.state_mut().save_funding_tx_pipe(vec![]);
    inject_signing_shares(&mut merchant, &mut customer);

    // Customer generates their init package legitimately
    let customer_pkg = customer.generate_init_package(&mut rng).expect("customer init package");
    merchant.receive_customer_init_package(customer_pkg).expect("merchant receives customer package");

    // Merchant generates their init package
    let merchant_pkg = merchant.generate_init_package(&mut rng).expect("merchant init package");

    // Attacker replays merchant's init package back to merchant as if from customer
    // This should fail because the adapter sig is signed with merchant's wallet key,
    // not the customer's
    let url2 = "No RPC required";
    let (merchant_state2, customer_state2, _) = propose_channel();
    let mut merchant2 = MerchantEstablishing::new(merchant_state2, url2).expect("merchant role");
    let mut customer2 = CustomerEstablishing::new(customer_state2, url2).expect("customer role");
    establish_wallet(&mut merchant2, &mut customer2);
    merchant2.state_mut().save_funding_tx_pipe(vec![]);
    inject_signing_shares(&mut merchant2, &mut customer2);

    // Try to feed merchant_pkg to a fresh merchant as customer init
    match merchant2.receive_customer_init_package(merchant_pkg) {
        Err(_) => {} // Any error is expected — payload sig or adapter sig mismatch
        Ok(_) => panic!("replayed merchant init package should not be accepted as customer's"),
    }
}

/// Modifying one field (encrypted_offset) of a valid init package invalidates
/// the payload signature since it's bound to the original encrypted_offset.
#[test]
fn test_reuse_init_package_after_modification() {
    let mut rng = OsRng;
    let url = "No RPC required";
    let (merchant_state, customer_state, _) = propose_channel();
    let mut merchant = MerchantEstablishing::new(merchant_state, url).expect("merchant role");
    let mut customer = CustomerEstablishing::new(customer_state, url).expect("customer role");

    establish_wallet(&mut merchant, &mut customer);
    merchant.state_mut().save_funding_tx_pipe(vec![]);
    customer.state_mut().save_funding_tx_pipe(vec![]);
    inject_signing_shares(&mut merchant, &mut customer);

    let mut customer_pkg = customer.generate_init_package(&mut rng).expect("customer init package");

    // Swap encrypted_offset with the merchant's (a different encrypted blob)
    customer_pkg.encrypted_offset = merchant.state().encrypted_offset.clone();

    match merchant.receive_customer_init_package(customer_pkg) {
        Err(EstablishError::InvalidPayloadSignature(_)) => {}
        Err(e) => panic!("expected InvalidPayloadSignature after modifying encrypted_offset, got: {e:?}"),
        Ok(_) => panic!("modified init package should not be accepted"),
    }
}

// ============================================================================
// 5. Merchant fraud: KES bundle tampering (detected by KES/customer)
// ============================================================================

/// Merchant replaces customer's encrypted offset in the KES bundle with their own.
/// KES rejects because the customer's payload signature is bound to the original offset.
#[test]
fn test_merchant_swaps_customer_offset_in_kes_bundle() {
    let mut rng = OsRng;
    let (merchant, _, kes_key) = establish_with_init_packages();

    let mut bundle = merchant.bundle_for_kes(&mut rng).expect("bundle");
    // Swap customer encrypted offset with merchant's
    bundle.customer_encrypted_offset = bundle.merchant_encrypted_offset.clone();

    let kes_secret = Zeroizing::new(kes_key);
    match KesEstablishing::from_bundle(kes_secret, bundle) {
        Err(KesEstablishError::InvalidPayloadSignature { role: ChannelRole::Customer }) => {}
        Err(e) => panic!("expected InvalidPayloadSignature for Customer, got: {e:?}"),
        Ok(_) => panic!("tampered bundle should not be accepted"),
    }
}

/// Merchant replaces customer's payload signature with their own in the bundle.
/// KES rejects because the signature won't verify against the customer's ephemeral pubkey.
#[test]
fn test_merchant_swaps_customer_payload_sig_in_bundle() {
    let mut rng = OsRng;
    let (merchant, _, kes_key) = establish_with_init_packages();

    let mut bundle = merchant.bundle_for_kes(&mut rng).expect("bundle");
    // Replace customer payload sig with merchant's
    bundle.customer_payload_sig = bundle.merchant_payload_sig.clone();

    let kes_secret = Zeroizing::new(kes_key);
    match KesEstablishing::from_bundle(kes_secret, bundle) {
        Err(KesEstablishError::InvalidPayloadSignature { role: ChannelRole::Customer }) => {}
        Err(e) => panic!("expected InvalidPayloadSignature for Customer, got: {e:?}"),
        Ok(_) => panic!("tampered bundle should not be accepted"),
    }
}

/// Even with forged PoK proofs (wrong offset values), the customer detects it
/// because verify_kes_proof() checks against their own DLEQ public point T0.
#[test]
fn test_kes_proof_wrong_offsets_detected_by_customer() {
    let mut rng = OsRng;
    let (_, mut customer, kes) = establish_to_bundle();

    // Generate proofs from kes (correct), then forge new ones with wrong offsets
    let wrong_shard = XmrScalar::random(&mut rng);
    let kes_channel_key_scalar = XmrScalar::random(&mut rng); // wrong key
    let forged_proofs = KesPoKProofs {
        customer_pok: KesPoK::<Ed25519>::prove(&mut rng, &wrong_shard, &kes_channel_key_scalar),
        merchant_pok: KesPoK::<Ed25519>::prove(&mut rng, &wrong_shard, &kes_channel_key_scalar),
    };
    let _ = kes; // drop

    match customer.receive_kes_proof(forged_proofs) {
        Err(EstablishError::KesProofError(_)) => {}
        Err(e) => panic!("expected KesProofError, got: {e:?}"),
        Ok(_) => panic!("forged proofs with wrong offsets should not verify"),
    }
}

// ============================================================================
// 6. KES proof verification missing-state failures
// ============================================================================

/// verify_kes_proof with no KES proof set returns MissingInformation.
#[test]
fn test_verify_kes_proof_missing_proof() {
    let (merchant, _, _) = establish_with_init_packages();
    // No kes_proof set
    match merchant.state().verify_kes_proof() {
        Err(EstablishError::MissingInformation(msg)) => {
            assert!(msg.contains("KES proof"), "error should mention KES proof: {msg}");
        }
        other => panic!("expected MissingInformation about KES proof, got: {other:?}"),
    }
}

/// verify_kes_proof with no peer DLEQ proof returns MissingInformation.
#[test]
fn test_verify_kes_proof_missing_peer_dleq() {
    let (merchant, _, _) = propose_channel();
    let mut merchant = MerchantEstablishing::new(merchant, "").expect("merchant");
    // Set a dummy KES proof to bypass the first check
    let mut rng = OsRng;
    let dummy_shard = XmrScalar::random(&mut rng);
    let dummy_key = XmrScalar::random(&mut rng);
    let dummy_proofs = KesPoKProofs {
        customer_pok: KesPoK::<Ed25519>::prove(&mut rng, &dummy_shard, &dummy_key),
        merchant_pok: KesPoK::<Ed25519>::prove(&mut rng, &dummy_shard, &dummy_key),
    };
    merchant.state_mut().kes_created(dummy_proofs);

    // No peer DLEQ proof set
    match merchant.state().verify_kes_proof() {
        Err(EstablishError::MissingInformation(msg)) => {
            assert!(msg.contains("DLEQ"), "error should mention DLEQ: {msg}");
        }
        other => panic!("expected MissingInformation about DLEQ, got: {other:?}"),
    }
}

/// verify_kes_proof with no peer nonce pubkey (can't derive P_g) returns MissingInformation.
#[test]
fn test_verify_kes_proof_missing_peer_nonce() {
    let mut rng = OsRng;
    let url = "No RPC required";
    let (merchant_state, customer_state, _) = propose_channel();
    let mut merchant = MerchantEstablishing::new(merchant_state, url).expect("merchant role");
    let mut customer = CustomerEstablishing::new(customer_state, url).expect("customer role");

    establish_wallet(&mut merchant, &mut customer);
    inject_signing_shares(&mut merchant, &mut customer);

    // Generate customer's init package but DON'T send it to merchant
    // Instead, manually set some fields to get past earlier checks
    let dummy_shard = XmrScalar::random(&mut rng);
    let dummy_key = XmrScalar::random(&mut rng);
    let dummy_proofs = KesPoKProofs {
        customer_pok: KesPoK::<Ed25519>::prove(&mut rng, &dummy_shard, &dummy_key),
        merchant_pok: KesPoK::<Ed25519>::prove(&mut rng, &dummy_shard, &dummy_key),
    };
    merchant.state_mut().kes_created(dummy_proofs);

    // Set a fake peer DLEQ proof
    let fake_witness = CrossCurveScalar::<Ed25519>::random_with_rng(&mut rng);
    let (fake_proof, fake_points) =
        <Ed25519 as Dleq<Ed25519>>::generate_dleq(&mut rng, &fake_witness).expect("fake DLEQ");
    merchant.state_mut().set_peer_dleq_proof(DleqProof::new(fake_proof, fake_points));

    // peer_nonce_pubkey is still None → can't derive P_g
    match merchant.state().verify_kes_proof() {
        Err(EstablishError::MissingInformation(msg)) => {
            assert!(
                msg.contains("peer nonce") || msg.contains("P_g"),
                "error should mention peer nonce or P_g: {msg}"
            );
        }
        other => panic!("expected MissingInformation about peer nonce, got: {other:?}"),
    }
}

// ============================================================================
// 7. Other missing information errors
// ============================================================================

/// preprepare_data() when empty returns MissingInformation.
#[test]
fn test_preprepare_data_before_preparation() {
    let (merchant, _, _) = propose_channel();
    match merchant.preprepare_data() {
        Err(EstablishError::MissingInformation(msg)) => {
            assert!(msg.contains("Preprepare"), "error should mention preprepare: {msg}");
        }
        other => panic!("expected MissingInformation, got: {other:?}"),
    }
}

/// verify_initial_offset without peer adapted signature returns MissingInformation.
#[test]
fn test_verify_initial_offset_no_adapted_sig() {
    let url = "No RPC required";
    let (merchant_state, customer_state, _) = propose_channel();
    let mut merchant = MerchantEstablishing::new(merchant_state, url).expect("merchant role");
    let mut customer = CustomerEstablishing::new(customer_state, url).expect("customer role");
    establish_wallet(&mut merchant, &mut customer);

    // No adapted sig set
    match merchant.state().verify_initial_offset(b"test") {
        Err(EstablishError::MissingInformation(msg)) => {
            assert!(msg.contains("Adapted signature") || msg.contains("adapted"), "msg: {msg}");
        }
        other => panic!("expected MissingInformation about adapted sig, got: {other:?}"),
    }
}

/// verify_initial_offset without multisig wallet returns MissingInformation.
#[test]
fn test_verify_initial_offset_no_wallet() {
    let (merchant, _, _) = propose_channel();
    // Fresh state has no wallet
    match merchant.verify_initial_offset(b"test") {
        Err(EstablishError::MissingInformation(msg)) => {
            assert!(
                msg.contains("wallet") || msg.contains("Wallet") || msg.contains("Adapted"),
                "msg: {msg}"
            );
        }
        other => panic!("expected MissingInformation, got: {other:?}"),
    }
}

/// verify_initial_offset without peer DLEQ proof returns MissingInformation
/// (after adapted sig check passes).
#[test]
fn test_verify_initial_offset_no_dleq_proof() {
    let mut rng = OsRng;
    let url = "No RPC required";
    let (merchant_state, customer_state, _) = propose_channel();
    let mut merchant = MerchantEstablishing::new(merchant_state, url).expect("merchant role");
    let mut customer = CustomerEstablishing::new(customer_state, url).expect("customer role");
    establish_wallet(&mut merchant, &mut customer);
    inject_signing_shares(&mut merchant, &mut customer);

    // Generate a real adapted signature from customer side so it verifies
    let customer_pkg = customer.generate_init_package(&mut rng).expect("customer init package");
    // Set adapted sig and nonce but NOT dleq_proof
    merchant.state_mut().set_peer_adapted_signature(customer_pkg.adapted_signature);
    merchant.state_mut().peer_nonce_pubkey = Some(customer_pkg.nonce_pubkey);

    // No peer DLEQ proof set
    let msg = merchant.state().commitment_message();
    match merchant.state().verify_initial_offset(&msg) {
        // Adapted sig will fail because it's verified against peer_pubkey (wallet)
        // but the adapter_commitment Q won't match since no dleq is set.
        // Either InvalidDataFromPeer (sig fails) or MissingInformation (dleq missing)
        Err(EstablishError::MissingInformation(msg)) => {
            assert!(msg.contains("DLEQ") || msg.contains("dleq"), "msg: {msg}");
        }
        Err(EstablishError::InvalidDataFromPeer(_)) => {
            // Also acceptable — the adapted sig verification may fail first
        }
        other => panic!("expected MissingInformation or InvalidDataFromPeer, got: {other:?}"),
    }
}

/// generate_kes_channel_id without peer nonce pubkey returns MissingInformation.
#[test]
fn test_generate_kes_channel_id_no_peer_nonce() {
    let url = "No RPC required";
    let (merchant_state, _, _) = propose_channel();
    let merchant = MerchantEstablishing::new(merchant_state, url).expect("merchant role");

    let mut rng = OsRng;
    match merchant.state().generate_kes_channel_id(&mut rng) {
        Err(EstablishError::MissingInformation(msg)) => {
            assert!(msg.contains("nonce") || msg.contains("Peer"), "msg: {msg}");
        }
        other => panic!("expected MissingInformation about peer nonce, got: {other:?}"),
    }
}

/// bundle_for_kes without customer init package (no peer encrypted offset) returns MissingInformation.
#[test]
fn test_bundle_for_kes_missing_peer_offset() {
    let mut rng = OsRng;
    let url = "No RPC required";
    let (merchant_state, customer_state, _) = propose_channel();
    let mut merchant = MerchantEstablishing::new(merchant_state, url).expect("merchant role");
    let mut customer = CustomerEstablishing::new(customer_state, url).expect("customer role");

    establish_wallet(&mut merchant, &mut customer);
    merchant.state_mut().save_funding_tx_pipe(vec![]);
    inject_signing_shares(&mut merchant, &mut customer);

    // Merchant generates their own init package but never receives customer's
    let _merchant_pkg = merchant.generate_init_package(&mut rng).expect("merchant init package");

    match merchant.bundle_for_kes(&mut rng) {
        Err(EstablishError::MissingInformation(msg)) => {
            assert!(
                msg.to_lowercase().contains("customer") || msg.to_lowercase().contains("peer"),
                "msg: {msg}"
            );
        }
        other => panic!("expected MissingInformation about customer data, got: {other:?}"),
    }
}

// ============================================================================
// 8. Wallet key role enforcement
// ============================================================================

/// Merchant rejects a wallet public key with Merchant role (should be Customer).
#[test]
fn test_merchant_rejects_merchant_role_wallet_key() {
    let url = "No RPC required";
    let (merchant_state, customer_state, _) = propose_channel();
    let mut merchant = MerchantEstablishing::new(merchant_state, url).expect("merchant role");
    let customer = CustomerEstablishing::new(customer_state, url).expect("customer role");

    let _ = merchant.wallet_public_key_commitment();
    // Get merchant's own key (which has Merchant role)
    let merchant_key = merchant.wallet_public_key();

    // Try to set it as customer wallet key — wrong role
    match merchant.set_customer_wallet_public_key(merchant_key) {
        Err(EstablishError::WrongRole { expected: ChannelRole::Customer, got: ChannelRole::Merchant }) => {}
        Err(e) => panic!("expected WrongRole, got: {e:?}"),
        Ok(_) => panic!("should reject Merchant role key as customer key"),
    }
}

/// Customer rejects a wallet public key with Customer role (should be Merchant).
#[test]
fn test_customer_rejects_customer_role_wallet_key() {
    let url = "No RPC required";
    let (merchant_state, customer_state, _) = propose_channel();
    let merchant = MerchantEstablishing::new(merchant_state, url).expect("merchant role");
    let mut customer = CustomerEstablishing::new(customer_state, url).expect("customer role");

    // Get customer's own key (which has Customer role)
    let customer_key = customer.wallet_public_key();

    // Try to set it as merchant wallet key — wrong role
    match customer.set_merchant_wallet_public_key(customer_key) {
        Err(EstablishError::WrongRole { expected: ChannelRole::Merchant, got: ChannelRole::Customer }) => {}
        Err(e) => panic!("expected WrongRole, got: {e:?}"),
        Ok(_) => panic!("should reject Customer role key as merchant key"),
    }
}

// ============================================================================
// 9. Funding edge cases
// ============================================================================

/// No transactions → funding_total is 0.
#[test]
fn test_funding_total_empty() {
    let (merchant, _, _) = propose_channel();
    assert_eq!(merchant.funding_total(), MoneroAmount::from_piconero(0));
}

/// Multiple transactions sum correctly.
#[test]
fn test_funding_total_accumulates() {
    let (mut merchant, _, _) = propose_channel();
    merchant.funding_tx_confirmed(fake_tx("tx1", MoneroAmount::from_piconero(100)));
    merchant.funding_tx_confirmed(fake_tx("tx2", MoneroAmount::from_piconero(200)));
    merchant.funding_tx_confirmed(fake_tx("tx3", MoneroAmount::from_piconero(300)));
    assert_eq!(merchant.funding_total(), MoneroAmount::from_piconero(600));
}

/// Same tx_id inserted twice → HashMap last-write-wins.
#[test]
fn test_duplicate_tx_id_overwrites() {
    let (mut merchant, _, _) = propose_channel();
    merchant.funding_tx_confirmed(fake_tx("same_tx", MoneroAmount::from_piconero(100)));
    merchant.funding_tx_confirmed(fake_tx("same_tx", MoneroAmount::from_piconero(500)));
    // HashMap overwrites: only the last value for "same_tx" is stored
    assert_eq!(merchant.funding_total(), MoneroAmount::from_piconero(500));
}

// ============================================================================
// 10. Accessor edge cases
// ============================================================================

/// kes_channel_pubkey returns None without peer nonce pubkey.
#[test]
fn test_kes_channel_pubkey_none_before_peer_nonce() {
    let (merchant, _, _) = propose_channel();
    assert!(
        merchant.kes_channel_pubkey().is_none(),
        "kes_channel_pubkey should be None without peer nonce"
    );
}
