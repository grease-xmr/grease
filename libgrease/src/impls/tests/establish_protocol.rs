//! Tests for the channel establishment protocol.
//!
//! These tests cover:
//! - Protocol context initialization (wallet keyrings, KES clients)
//! - Init package generation and exchange (adapted signatures, DLEQ proofs, encrypted offsets)
//! - Verification of tampered proofs and signatures
//! - Wallet commitment flow (customer verifies merchant's committed key)
//! - Requirements checking and state transitions
//! - KES establishing flow (receive offsets, decrypt)

use crate::cryptography::dleq::DleqProof;
use crate::cryptography::keys::{Curve25519PublicKey, Curve25519Secret, PublicKey};
use crate::cryptography::pok::KesPoK;
use crate::cryptography::pok::KesPoKProofs;
use crate::cryptography::secret_encryption::{EncryptedSecret, SecretWithRole};
use crate::cryptography::{AsXmrPoint, ChannelWitnessPublic};
use crate::grease_protocol::establish_channel::EstablishError;
use crate::grease_protocol::kes_establishing::KesEstablishing;
use crate::grease_protocol::multisig_wallet::{HasPublicKey, LinkedMultisigWallets, MultisigWalletError};
use crate::monero::data_objects::{TransactionId, TransactionRecord};
use crate::payment_channel::{ChannelRole, HasRole};
use crate::state_machine::commitment_transaction_message;
use crate::state_machine::lifecycle::{LifeCycle, LifecycleStage};
use crate::state_machine::{CustomerEstablishing, EstablishingState, MerchantEstablishing};
use crate::XmrPoint;
use ciphersuite::group::ff::Field;
use ciphersuite::group::Group;
use ciphersuite::{Ciphersuite, Ed25519};
use rand_core::OsRng;
use std::str::FromStr;
use zeroize::Zeroizing;

use super::propose_protocol::{establish_channel, establish_channel_with_kes_key};

/// Create a dummy `KesPoKProofs<Ed25519>` using random scalars.
/// These proofs are structurally valid but won't verify against real channel offsets.
fn dummy_kes_pok_proofs() -> KesPoKProofs<Ed25519> {
    let mut rng = OsRng;
    let shard = crate::XmrScalar::random(&mut rng);
    let private_key = crate::XmrScalar::random(&mut rng);
    KesPoKProofs {
        customer_pok: KesPoK::<Ed25519>::prove(&mut rng, &shard, &private_key),
        merchant_pok: KesPoK::<Ed25519>::prove(&mut rng, &shard, &private_key),
    }
}

// ============================================================================
// Phase helpers
// ============================================================================

/// Create a paired (merchant, customer) `EstablishingState` with protocol context
/// and channel secrets (DLEQ proof, adapter signature, encrypted offset) already initialized.
pub fn establish_with_protocol_context() -> (EstablishingState, EstablishingState) {
    let (merchant, customer, _kes_key) = establish_with_protocol_context_and_kes_key();
    (merchant, customer)
}

/// Like [`establish_with_protocol_context`] but also returns the KES private key.
pub fn establish_with_protocol_context_and_kes_key() -> (EstablishingState, EstablishingState, crate::XmrScalar) {
    let (mut merchant, mut customer, kes_key) = establish_channel_with_kes_key();
    let mut rng = OsRng;
    merchant.generate_channel_secrets(&mut rng).expect("channel secret generation");
    customer.generate_channel_secrets(&mut rng).expect("channel secret generation");
    (merchant, customer, kes_key)
}

/// Full establishment flow: protocol context, KES init, generate and exchange init packages,
/// exchange wallet public keys.
pub fn full_establish_flow() -> (EstablishingState, EstablishingState) {
    let (merchant, customer, _kes_key) = full_establish_flow_with_kes_key();
    (merchant, customer)
}

/// Like [`full_establish_flow`] but also returns the KES private key.
pub fn full_establish_flow_with_kes_key() -> (EstablishingState, EstablishingState, crate::XmrScalar) {
    let (merchant_state, customer_state, kes_key) = establish_with_protocol_context_and_kes_key();

    let mut merchant = MerchantEstablishing::new(merchant_state).expect("merchant role");
    let mut customer = CustomerEstablishing::new(customer_state).expect("customer role");
    let mut rng = OsRng;

    // Exchange wallet public keys
    let merchant_shared_key = merchant.state().wallet_keyring.as_ref().map(|w| w.shared_public_key()).unwrap();
    let customer_shared_key = customer.state().wallet_keyring.as_ref().map(|w| w.shared_public_key()).unwrap();
    customer.state_mut().wallet_keyring.as_mut().map(|w| w.set_peer_public_key(merchant_shared_key));
    merchant.state_mut().wallet_keyring.as_mut().map(|w| w.set_peer_public_key(customer_shared_key));

    // Generate and exchange init packages
    let merchant_pkg = merchant.generate_init_package(&mut rng).expect("merchant init package");
    let customer_pkg = customer.generate_init_package(&mut rng).expect("customer init package");

    customer.receive_merchant_init_package(merchant_pkg).expect("customer receives merchant package");
    merchant.receive_customer_init_package(customer_pkg).expect("merchant receives customer package");

    (merchant.into_inner(), customer.into_inner(), kes_key)
}

// ============================================================================
// Protocol context initialization
// ============================================================================

#[test]
fn test_init_protocol_context() {
    let (merchant, customer) = establish_channel();
    let mut rng = OsRng;

    // Before init, wallet should panic (tested via the wrapper)
    let mut merchant = merchant;
    merchant.generate_channel_secrets(&mut rng).expect("channel secret generation");

    assert_eq!(
        merchant.wallet_keyring.as_ref().map(|w| w.role()).unwrap(),
        ChannelRole::Merchant
    );
    assert_eq!(HasRole::role(&merchant), ChannelRole::Merchant);

    let mut customer = customer;
    customer.generate_channel_secrets(&mut rng).expect("channel secret generation");

    assert_eq!(
        customer.wallet_keyring.as_ref().map(|w| w.role()).unwrap(),
        ChannelRole::Customer
    );
    assert_eq!(HasRole::role(&customer), ChannelRole::Customer);
}

// ============================================================================
// KES client initialization
// ============================================================================

#[test]
fn test_init_channel_secrets() {
    let (mut merchant, mut customer) = establish_channel();
    let mut rng = OsRng;
    // init_protocol_context generates channel secrets (DLEQ proof, encrypted offset, stores witness)
    // The adapter signature is deferred to generate_init_package.
    merchant.generate_channel_secrets(&mut rng).expect("channel secret generation");
    customer.generate_channel_secrets(&mut rng).expect("channel secret generation");

    // DLEQ proofs should be set and valid
    let merchant_dleq = merchant.dleq_proof.as_ref().expect("merchant dleq_proof");
    assert_eq!(HasRole::role(&merchant), ChannelRole::Merchant);
    merchant_dleq.verify().expect("merchant DLEQ proof should be valid");

    let customer_dleq = customer.dleq_proof.as_ref().expect("customer dleq_proof");
    assert_eq!(HasRole::role(&customer), ChannelRole::Customer);
    customer_dleq.verify().expect("customer DLEQ proof should be valid");

    // Encrypted offsets and channel witnesses should be populated; adapter sig is deferred
    assert!(merchant.encrypted_offset.is_some(), "merchant encrypted_offset should be set");
    assert!(merchant.channel_witness.is_some(), "merchant channel_witness should be set");
    assert!(merchant.adapted_sig.is_none(), "merchant adapted_sig should NOT be set yet");
    assert!(customer.encrypted_offset.is_some(), "customer encrypted_offset should be set");
    assert!(customer.channel_witness.is_some(), "customer channel_witness should be set");
    assert!(customer.adapted_sig.is_none(), "customer adapted_sig should NOT be set yet");
}

#[test]
fn test_channel_secrets_not_initialized_error() {
    let (mut merchant, _customer) = establish_channel();
    let mut rng = OsRng;
    // Before init_protocol_context, channel secrets are not set
    assert!(merchant.dleq_proof.is_none());
    assert!(merchant.adapted_sig.is_none());
    assert!(merchant.encrypted_offset.is_none());
    assert!(merchant.channel_witness.is_none());
    // generate_init_package should fail with MissingInformation (no witness)
    let err = merchant.generate_init_package(&mut rng).unwrap_err();
    assert!(matches!(err, EstablishError::MissingInformation(_)));
}

// ============================================================================
// Init package generation
// ============================================================================

#[test]
fn test_merchant_generate_init_package() {
    let (merchant_state, _) = establish_with_protocol_context();
    let mut merchant = MerchantEstablishing::new(merchant_state).expect("merchant role");
    let mut rng = OsRng;

    let package = merchant.generate_init_package(&mut rng).expect("generate merchant init package");

    // Adapted signature should verify against the real commitment transaction message
    let pubkey = merchant.state().public_key();
    let msg =
        commitment_transaction_message(merchant.state().metadata(), &merchant.state().metadata().initial_balance(), 0);
    assert!(
        package.adapted_signature.verify(&pubkey.as_point(), &msg),
        "adapted sig should verify"
    );

    // DLEQ proof should be valid
    package.dleq_proof.verify().expect("DLEQ proof should verify");

    // Q from adapted sig should match the xmr_point from the DLEQ proof
    let q0 = package.adapted_signature.adapter_commitment();
    assert_eq!(q0, *package.dleq_proof.public_points.as_xmr_point());
}

#[test]
fn test_customer_generate_init_package() {
    let (_, customer_state) = establish_with_protocol_context();
    let mut customer = CustomerEstablishing::new(customer_state).expect("customer role");
    let mut rng = OsRng;

    let package = customer.generate_init_package(&mut rng).expect("generate customer init package");

    let pubkey = customer.state().public_key();
    let msg =
        commitment_transaction_message(customer.state().metadata(), &customer.state().metadata().initial_balance(), 0);
    assert!(
        package.adapted_signature.verify(&pubkey.as_point(), &msg),
        "adapted sig should verify"
    );
    package.dleq_proof.verify().expect("DLEQ proof should verify");

    let q0 = package.adapted_signature.adapter_commitment();
    assert_eq!(q0, *package.dleq_proof.public_points.as_xmr_point());
}

// ============================================================================
// Init package exchange
// ============================================================================

#[test]
fn test_exchange_init_packages() {
    let (merchant_state, customer_state) = establish_with_protocol_context();

    let mut merchant = MerchantEstablishing::new(merchant_state).expect("merchant role");
    let mut customer = CustomerEstablishing::new(customer_state).expect("customer role");

    // Exchange wallet public keys first (required for verification)
    let merchant_shared_key = merchant.state().wallet_keyring.as_ref().map(|w| w.shared_public_key()).unwrap();
    let customer_shared_key = customer.state().wallet_keyring.as_ref().map(|w| w.shared_public_key()).unwrap();
    customer.state_mut().wallet_keyring.as_mut().map(|w| w.set_peer_public_key(merchant_shared_key));
    merchant.state_mut().wallet_keyring.as_mut().map(|w| w.set_peer_public_key(customer_shared_key));

    // Generate packages
    let mut rng = OsRng;
    let merchant_pkg = merchant.generate_init_package(&mut rng).expect("merchant package");
    let customer_pkg = customer.generate_init_package(&mut rng).expect("customer package");

    // Cross-verify
    customer.receive_merchant_init_package(merchant_pkg).expect("customer should accept merchant's package");
    merchant.receive_customer_init_package(customer_pkg).expect("merchant should accept customer's package");

    // Peer data should be stored
    assert!(merchant.state().peer_dleq_proof().is_some());
    assert!(merchant.state().peer_adapted_signature().is_some());
    assert!(merchant.state().peer_encrypted_offset().is_some());
    assert!(customer.state().peer_dleq_proof().is_some());
    assert!(customer.state().peer_adapted_signature().is_some());
    assert!(customer.state().peer_encrypted_offset().is_some());
}

// ============================================================================
// Bad proof / signature rejection
// ============================================================================

#[test]
fn test_receive_bad_dleq_proof() {
    let (merchant_state, customer_state) = establish_with_protocol_context();
    let mut rng = OsRng;

    let mut merchant = MerchantEstablishing::new(merchant_state).expect("merchant role");
    let mut customer = CustomerEstablishing::new(customer_state).expect("customer role");

    // Exchange wallet keys (merchant needs customer's key to verify)
    let customer_shared_key = customer.state().wallet_keyring.as_ref().map(|w| w.shared_public_key()).unwrap();
    merchant.state_mut().wallet_keyring.as_mut().map(|w| w.set_peer_public_key(customer_shared_key));

    let mut customer_pkg = customer.generate_init_package(&mut rng).expect("customer package");

    // Tamper with the DLEQ proof's public points (swap the xmr point for a random one)
    let random_point = XmrPoint::generator() * crate::XmrScalar::random(&mut rng);
    let bad_public = ChannelWitnessPublic::new(random_point, *customer_pkg.dleq_proof.public_points.snark_point());
    customer_pkg.dleq_proof = DleqProof::new(customer_pkg.dleq_proof.proof.clone(), bad_public);

    let err = merchant.receive_customer_init_package(customer_pkg).unwrap_err();
    assert!(
        matches!(
            err,
            EstablishError::InvalidDataFromPeer(_) | EstablishError::AdapterSigOffsetError(_)
        ),
        "Should reject bad DLEQ proof, got: {err:?}"
    );
}

#[test]
fn test_receive_bad_adapter_sig() {
    let (merchant_state, customer_state) = establish_with_protocol_context();
    let mut rng = OsRng;

    let mut merchant = MerchantEstablishing::new(merchant_state).expect("merchant role");
    let mut customer = CustomerEstablishing::new(customer_state).expect("customer role");

    // Exchange wallet keys — but give the merchant a *wrong* peer key so verification fails
    let customer_shared_key = customer.state().wallet_keyring.as_ref().map(|w| w.shared_public_key()).unwrap();
    merchant.state_mut().wallet_keyring.as_mut().map(|w| w.set_peer_public_key(customer_shared_key));

    let mut customer_pkg = customer.generate_init_package(&mut rng).expect("customer package");

    // Tamper with the adapted signature by generating a fresh one with a different key
    let (rogue_secret, _) = Curve25519PublicKey::keypair(&mut rng);
    let rogue_offset = crate::XmrScalar::random(&mut rng);
    let bad_sig = crate::cryptography::adapter_signature::AdaptedSignature::<Ed25519>::sign(
        rogue_secret.as_scalar(),
        &rogue_offset,
        b"rogue-message",
        &mut rng,
    );
    customer_pkg.adapted_signature = bad_sig;

    let err = merchant.receive_customer_init_package(customer_pkg).unwrap_err();
    assert!(
        matches!(err, EstablishError::InvalidDataFromPeer(_)),
        "Should reject bad adapted signature, got: {err:?}"
    );
}

// ============================================================================
// Wallet commitment flow
// ============================================================================

#[test]
fn test_customer_verify_merchant_commitment() {
    let (merchant_state, customer_state) = establish_with_protocol_context();

    let merchant = MerchantEstablishing::new(merchant_state).expect("merchant role");
    let mut customer = CustomerEstablishing::new(customer_state).expect("customer role");

    // Merchant commits to their shared public key, customer stores the commitment
    let commitment = merchant.state().wallet_keyring.as_ref().map(|w| w.commit_to_public_key()).unwrap();
    customer.state_mut().wallet_keyring.as_mut().map(|w| w.set_peer_public_key_commitment(commitment));

    // Customer then receives the merchant's actual public key
    let merchant_shared_key = merchant.state().wallet_keyring.as_ref().map(|w| w.shared_public_key()).unwrap();
    customer.state_mut().wallet_keyring.as_mut().map(|w| w.set_peer_public_key(merchant_shared_key));

    // Verification should succeed
    customer
        .state()
        .wallet_keyring
        .as_ref()
        .unwrap()
        .verify_peer_public_key()
        .expect("commitment verification should succeed");
}

#[test]
fn test_customer_verify_merchant_commitment_mismatch() {
    let (merchant_state, customer_state) = establish_with_protocol_context();
    let mut rng = OsRng;

    let merchant = MerchantEstablishing::new(merchant_state).expect("merchant role");
    let mut customer = CustomerEstablishing::new(customer_state).expect("customer role");

    // Create a commitment from a different (rogue) keypair
    let rogue_keyring = crate::impls::multisig::MultisigWalletKeyRing::random(&mut rng, ChannelRole::Merchant);
    let bad_commitment = rogue_keyring.commit_to_public_key();
    customer.state_mut().wallet_keyring.as_mut().map(|w| w.set_peer_public_key_commitment(bad_commitment));

    // Set the real merchant's key
    let merchant_shared_key = merchant.state().wallet_keyring.as_ref().map(|w| w.shared_public_key()).unwrap();
    customer.state_mut().wallet_keyring.as_mut().map(|w| w.set_peer_public_key(merchant_shared_key));

    // Verification should fail because commitment doesn't match key
    let err = customer.state().wallet_keyring.as_ref().unwrap().verify_peer_public_key().unwrap_err();
    assert!(
        matches!(err, MultisigWalletError::IncorrectPublicKey),
        "Should fail with wallet error, got: {err:?}"
    );
}

// ============================================================================
// Requirements and state transitions
// ============================================================================

#[test]
fn test_requirements_met_incomplete() {
    let (merchant, _) = establish_channel();
    // Fresh establishing state has nothing, so requirements should not be met
    assert!(!merchant.requirements_met());
}

#[test]
fn test_requirements_met_no_wallet() {
    let (mut merchant, _) = establish_channel();
    let mut rng = OsRng;
    merchant.generate_channel_secrets(&mut rng).expect("channel secret generation");
    // No multisig wallet, no kes proof, no funding, no peer data — not met
    assert!(!merchant.requirements_met());
}

#[test]
fn test_establishing_to_open_fails_without_requirements() {
    let (merchant, _) = establish_channel();
    let result = merchant.next();
    assert!(result.is_err(), "Should not transition without requirements met");
    let (state, err) = result.unwrap_err();
    assert_eq!(state.stage(), LifecycleStage::Establishing);
    assert!(matches!(
        err,
        crate::state_machine::error::LifeCycleError::InvalidStateTransition
    ));
}

#[test]
fn test_establishing_to_open_with_all_requirements() {
    let (mut merchant, _) = establish_channel();
    let mut rng = OsRng;
    merchant.generate_channel_secrets(&mut rng).expect("channel secret generation");

    // Set up multisig wallet data
    let (secret, pubkey) = Curve25519PublicKey::keypair(&mut rng);
    let (_, peer_pubkey) = Curve25519PublicKey::keypair(&mut rng);
    let mut sorted = [pubkey, peer_pubkey];
    crate::multisig::sort_pubkeys(&mut sorted);
    let (view_key, _) = crate::multisig::musig_dh_viewkey(&secret, &peer_pubkey);
    let wallet = crate::multisig::MultisigWalletData {
        role: ChannelRole::Merchant,
        my_spend_key: secret,
        my_public_key: pubkey,
        sorted_pubkeys: sorted,
        joint_private_view_key: Curve25519Secret::from(*view_key),
        joint_public_spend_key: pubkey, // placeholder
        birthday: 0,
        known_outputs: vec![],
    };
    merchant.wallet_created(wallet);

    // Generate init package to populate adapted_sig (deferred from init_protocol_context)
    let _pkg = merchant.generate_init_package(&mut rng).expect("generate init package");

    // Set peer data (use own data as placeholders for requirements_met)
    let own_dleq = merchant.dleq_proof.clone().unwrap();
    merchant.set_peer_dleq_proof(own_dleq);
    let own_sig = merchant.adapted_sig.clone().unwrap();
    merchant.set_peer_adapted_signature(own_sig);
    let own_chi = merchant.encrypted_offset.clone().unwrap();
    merchant.set_peer_encrypted_offset(own_chi);
    // Use own payload sig as placeholder for peer's
    let own_payload_sig = merchant.payload_sig.clone().unwrap();
    merchant.peer_payload_sig = Some(own_payload_sig);
    merchant.save_funding_tx_pipe(vec![1]);

    // Set KES proof
    merchant.kes_created(dummy_kes_pok_proofs());

    // Fund the channel
    let required = merchant.metadata.initial_balance().total();
    let tx = TransactionRecord {
        channel_name: "test".into(),
        transaction_id: TransactionId::new("fake_tx"),
        amount: required,
        serialized: vec![],
    };
    merchant.funding_tx_confirmed(tx);

    assert!(merchant.requirements_met());

    let open = merchant.next().expect("Should transition to Open");
    assert_eq!(open.metadata.role(), ChannelRole::Merchant);
}

// ============================================================================
// KES establishing flow
// ============================================================================

#[test]
fn test_kes_establishing_flow() {
    let mut rng = OsRng;

    // Create KES keypair
    let kes_secret = Zeroizing::new(crate::XmrScalar::random(&mut rng));
    let kes_public = Ed25519::generator() * *kes_secret;

    let mut kes = KesEstablishing::<Ed25519>::new(kes_secret, kes_public);
    assert!(!kes.has_both_offsets());

    // Create encrypted offsets from customer and merchant
    let customer_secret = SecretWithRole::new(crate::XmrScalar::random(&mut rng), ChannelRole::Customer);
    let merchant_secret = SecretWithRole::new(crate::XmrScalar::random(&mut rng), ChannelRole::Merchant);

    let channel_id =
        crate::channel_id::ChannelId::from_str("XGC4a7024e7fd6f5c6a2d0131d12fd91ecd17f5da61c2970d603a05053b41a383")
            .unwrap();
    let domain = crate::grease_protocol::kes_establishing::kes_offset_domain(&channel_id);
    let customer_chi = EncryptedSecret::<Ed25519>::encrypt(customer_secret.clone(), &kes_public, &mut rng, &domain);
    let merchant_chi = EncryptedSecret::<Ed25519>::encrypt(merchant_secret.clone(), &kes_public, &mut rng, &domain);
    kes.set_channel_id(channel_id);

    kes.receive_customer_offset(customer_chi).expect("receive customer offset");
    assert!(!kes.has_both_offsets());

    kes.receive_merchant_offset(merchant_chi).expect("receive merchant offset");
    assert!(kes.has_both_offsets());

    // Decrypt and verify
    let offsets = kes.decrypt_offsets().expect("decrypt offsets");

    use subtle::ConstantTimeEq;
    assert_eq!(
        offsets.customer().ct_eq(&customer_secret).unwrap_u8(),
        1,
        "Customer offset mismatch"
    );
    assert_eq!(
        offsets.merchant().ct_eq(&merchant_secret).unwrap_u8(),
        1,
        "Merchant offset mismatch"
    );
}

#[test]
fn test_kes_establishing_wrong_role() {
    let mut rng = OsRng;
    let kes_secret = Zeroizing::new(crate::XmrScalar::random(&mut rng));
    let kes_public = Ed25519::generator() * *kes_secret;
    let mut kes = KesEstablishing::<Ed25519>::new(kes_secret, kes_public);

    // Create a merchant-role secret but try to submit as customer
    let merchant_secret = SecretWithRole::new(crate::XmrScalar::random(&mut rng), ChannelRole::Merchant);
    let channel_id =
        crate::channel_id::ChannelId::from_str("XGC4a7024e7fd6f5c6a2d0131d12fd91ecd17f5da61c2970d603a05053b41a383")
            .unwrap();
    let domain = crate::grease_protocol::kes_establishing::kes_offset_domain(&channel_id);
    let merchant_chi = EncryptedSecret::<Ed25519>::encrypt(merchant_secret, &kes_public, &mut rng, &domain);

    let err = kes.receive_customer_offset(merchant_chi).unwrap_err();
    assert!(
        matches!(
            err,
            crate::grease_protocol::kes_establishing::KesEstablishError::WrongRole { .. }
        ),
        "Should reject wrong role, got: {err:?}"
    );
}

#[test]
fn test_kes_establishing_missing_offset() {
    let mut rng = OsRng;
    let kes_secret = Zeroizing::new(crate::XmrScalar::random(&mut rng));
    let kes_public = Ed25519::generator() * *kes_secret;
    let mut kes = KesEstablishing::<Ed25519>::new(kes_secret, kes_public);

    // Without a channel ID, decrypt_offsets should fail with MissingChannelId
    let err = kes.decrypt_offsets().unwrap_err();
    assert!(
        matches!(
            err,
            crate::grease_protocol::kes_establishing::KesEstablishError::MissingChannelId
        ),
        "Should report missing channel ID, got: {err:?}"
    );

    // With a channel ID but no offsets, should fail with MissingOffset
    let channel_id =
        crate::channel_id::ChannelId::from_str("XGC4a7024e7fd6f5c6a2d0131d12fd91ecd17f5da61c2970d603a05053b41a383")
            .unwrap();
    kes.set_channel_id(channel_id);
    let err = kes.decrypt_offsets().unwrap_err();
    assert!(
        matches!(
            err,
            crate::grease_protocol::kes_establishing::KesEstablishError::MissingOffset(ChannelRole::Customer)
        ),
        "Should report missing customer offset, got: {err:?}"
    );
}

// ============================================================================
// Wrapper role enforcement
// ============================================================================

#[test]
fn test_merchant_wrapper_rejects_customer() {
    let (_, customer) = establish_channel();
    match MerchantEstablishing::new(customer) {
        Err(EstablishError::WrongRole { expected: ChannelRole::Merchant, got: ChannelRole::Customer }) => {}
        Err(e) => panic!("expected WrongRole, got: {e:?}"),
        Ok(_) => panic!("expected Err, got Ok"),
    }
}

#[test]
fn test_customer_wrapper_rejects_merchant() {
    let (merchant, _) = establish_channel();
    match CustomerEstablishing::new(merchant) {
        Err(EstablishError::WrongRole { expected: ChannelRole::Customer, got: ChannelRole::Merchant }) => {}
        Err(e) => panic!("expected WrongRole, got: {e:?}"),
        Ok(_) => panic!("expected Err, got Ok"),
    }
}

// ============================================================================
// KES proof-of-knowledge
// ============================================================================

/// Helper: set up a KES establishing instance with both encrypted offsets from
/// the init packages generated by the two parties.
///
/// `kes_private_key` must be the KES secret key that corresponds to the KES
/// public key stored in the channel metadata (i.e. the one from proposal setup).
fn kes_with_offsets_from_flow(
    merchant: &EstablishingState,
    customer: &EstablishingState,
    kes_private_key: &crate::XmrScalar,
) -> KesEstablishing<Ed25519> {
    let kes_secret = Zeroizing::new(*kes_private_key);
    let kes_public = Ed25519::generator() * *kes_secret;
    let mut kes = KesEstablishing::<Ed25519>::new(kes_secret, kes_public);

    // Use the already-encrypted offsets generated during init_protocol_context.
    // These were encrypted to the KES public key from channel metadata.
    let channel_id = merchant.metadata.channel_id().name();
    kes.set_channel_id(channel_id);
    let customer_chi = customer.encrypted_offset.clone().expect("customer encrypted offset");
    let merchant_chi = merchant.encrypted_offset.clone().expect("merchant encrypted offset");

    kes.receive_customer_offset(customer_chi).expect("receive customer offset");
    kes.receive_merchant_offset(merchant_chi).expect("receive merchant offset");
    kes
}

#[test]
fn test_kes_generate_pok() {
    let (merchant, customer, kes_key) = establish_with_protocol_context_and_kes_key();
    let kes = kes_with_offsets_from_flow(&merchant, &customer, &kes_key);
    let mut rng = OsRng;

    let proof = kes.generate_pok(&mut rng).expect("generate_pok");
    // Verify the proof is structurally valid by checking it against the real offset points
    let customer_offset = *customer.dleq_proof.as_ref().unwrap().public_points.snark_point();
    let merchant_offset = *merchant.dleq_proof.as_ref().unwrap().public_points.snark_point();
    let kes_pubkey = *kes.public_key();
    proof.verify_for(&customer_offset, &merchant_offset, &kes_pubkey).expect("generated proof should verify");
}

#[test]
fn test_kes_pok_verifies_for_parties() {
    let (merchant, customer, kes_key) = establish_with_protocol_context_and_kes_key();
    let kes = kes_with_offsets_from_flow(&merchant, &customer, &kes_key);
    let mut rng = OsRng;

    let proof = kes.generate_pok(&mut rng).expect("generate_pok");

    // Verify using the offset public points from the DLEQ proofs and the KES public key
    let customer_offset = *customer.dleq_proof.as_ref().unwrap().public_points.snark_point();
    let merchant_offset = *merchant.dleq_proof.as_ref().unwrap().public_points.snark_point();
    let kes_pubkey = *kes.public_key();

    proof
        .verify_for(&customer_offset, &merchant_offset, &kes_pubkey)
        .expect("KES proof should verify for both parties");
}

#[test]
fn test_kes_pok_rejects_wrong_kes_pubkey() {
    let (merchant, customer, kes_key) = establish_with_protocol_context_and_kes_key();
    let kes = kes_with_offsets_from_flow(&merchant, &customer, &kes_key);
    let mut rng = OsRng;

    let proof = kes.generate_pok(&mut rng).expect("generate_pok");

    let customer_offset = *customer.dleq_proof.as_ref().unwrap().public_points.snark_point();
    let merchant_offset = *merchant.dleq_proof.as_ref().unwrap().public_points.snark_point();
    // Use a random point instead of the real KES pubkey
    let wrong_pubkey = Ed25519::generator() * crate::XmrScalar::random(&mut rng);

    let err = proof.verify_for(&customer_offset, &merchant_offset, &wrong_pubkey);
    assert!(err.is_err(), "Should reject proof with wrong KES pubkey");
}

#[test]
fn test_requirements_fail_without_kes_proof() {
    let (mut merchant, _) = establish_channel();
    let mut rng = OsRng;
    merchant.generate_channel_secrets(&mut rng).expect("channel secret generation");

    // Generate init package to populate adapted_sig
    let _pkg = merchant.generate_init_package(&mut rng).expect("generate init package");

    // Set up multisig wallet data
    let wallet = crate::state_machine::lifecycle::test::create_wallet(ChannelRole::Merchant);
    merchant.wallet_created(wallet);

    // Set peer data (use own data as placeholders)
    let own_dleq = merchant.dleq_proof.clone().unwrap();
    merchant.set_peer_dleq_proof(own_dleq);
    let own_sig = merchant.adapted_sig.clone().unwrap();
    merchant.set_peer_adapted_signature(own_sig);
    let own_chi = merchant.encrypted_offset.clone().unwrap();
    merchant.set_peer_encrypted_offset(own_chi);
    let own_payload_sig = merchant.payload_sig.clone().unwrap();
    merchant.peer_payload_sig = Some(own_payload_sig);
    merchant.save_funding_tx_pipe(vec![1]);

    // Fund the channel
    let required = merchant.metadata.initial_balance().total();
    let tx = TransactionRecord {
        channel_name: "test".into(),
        transaction_id: TransactionId::new("fake_tx"),
        amount: required,
        serialized: vec![],
    };
    merchant.funding_tx_confirmed(tx);

    // No KES proof set — requirements should not be met
    assert!(
        !merchant.requirements_met(),
        "missing KES proof should not satisfy requirements"
    );

    // Set a real KES proof
    merchant.kes_created(dummy_kes_pok_proofs());
    assert!(merchant.requirements_met(), "present KES proof should satisfy requirements");
}

// ============================================================================
// KES verify_kes_proof integration
// ============================================================================

#[test]
fn test_verify_kes_proof_end_to_end() {
    // Do full establish flow to get both parties with exchanged init packages
    let (mut merchant, mut customer, kes_key) = full_establish_flow_with_kes_key();

    // Set up a KES instance that can decrypt the offsets (using the real KES key from metadata)
    let kes = kes_with_offsets_from_flow(&merchant, &customer, &kes_key);
    let mut rng = OsRng;

    // Generate the KES proof
    let proof = kes.generate_pok(&mut rng).expect("generate_pok");

    // Both parties store the proof
    merchant.kes_created(proof.clone());
    customer.kes_created(proof);

    // Both parties should be able to verify
    merchant.verify_kes_proof().expect("merchant should verify KES proof");
    customer.verify_kes_proof().expect("customer should verify KES proof");
}

// ============================================================================
// Channel key derivation
// ============================================================================

#[test]
fn test_prepare_kes_channel_id() {
    let (mut merchant, _customer) = establish_with_protocol_context();
    let mut rng = OsRng;

    let ephemeral_id = merchant.prepare_kes_channel_id(&mut rng).expect("prepare_kes_channel_id");
    // Just verify it doesn't panic and returns successfully — the inner encryption
    // is tested by channel_keys.rs's own tests.
    drop(ephemeral_id);
}

#[test]
fn test_kes_derive_channel_keys_roundtrip() {
    let (mut merchant, _customer) = establish_with_protocol_context();
    let mut rng = OsRng;

    // Create a standalone KES for key derivation
    let kes_secret = Zeroizing::new(crate::XmrScalar::random(&mut rng));
    let kes_public = Ed25519::generator() * *kes_secret;
    let kes = KesEstablishing::<Ed25519>::new(kes_secret, kes_public);

    // Generate an ephemeral channel ID from the merchant
    let ephemeral_id = merchant.prepare_kes_channel_id(&mut rng).expect("prepare_kes_channel_id");

    // KES derives channel keys
    let keypair = kes.derive_channel_keys(ephemeral_id);

    // The derived public key should match secret * G
    let expected_public = Ed25519::generator() * *keypair.secret;
    assert_eq!(
        keypair.public, expected_public,
        "derived public key should be consistent with secret"
    );
}

// ============================================================================
// Full integration test
// ============================================================================

#[test]
fn test_full_establish_flow() {
    let (merchant, customer) = full_establish_flow();

    // Both parties should have peer data
    assert!(merchant.peer_dleq_proof().is_some());
    assert!(merchant.peer_adapted_signature().is_some());
    assert!(merchant.peer_encrypted_offset().is_some());
    assert!(customer.peer_dleq_proof().is_some());
    assert!(customer.peer_adapted_signature().is_some());
    assert!(customer.peer_encrypted_offset().is_some());

    // Roles should be correct
    assert_eq!(HasRole::role(&merchant), ChannelRole::Merchant);
    assert_eq!(HasRole::role(&customer), ChannelRole::Customer);
    assert_eq!(merchant.stage(), LifecycleStage::Establishing);
    assert_eq!(customer.stage(), LifecycleStage::Establishing);
}

// ============================================================================
// Merchant-as-KES-proxy
// ============================================================================

#[test]
fn test_merchant_as_kes_proxy() {
    use crate::grease_protocol::kes_establishing::KesEstablishing;

    let (merchant_state, customer_state, kes_key) = full_establish_flow_with_kes_key();
    let mut rng = OsRng;

    // Wrap in role wrappers
    let merchant = MerchantEstablishing::new(merchant_state).expect("merchant role");

    // Merchant has both offsets (own + customer's from the init package exchange)
    assert!(merchant.has_both_offsets(), "merchant should have both offsets after full flow");

    // Bundle for KES
    let bundle = merchant.bundle_for_kes().expect("bundle_for_kes");

    // Create a KES instance and receive the bundle
    let kes_secret = Zeroizing::new(kes_key);
    let kes_public = Ed25519::generator() * *kes_secret;
    let mut kes = KesEstablishing::<Ed25519>::new(kes_secret, kes_public);
    kes.receive_bundle(bundle).expect("receive_bundle");
    assert!(kes.has_both_offsets());

    // Generate proof
    let proof = kes.generate_pok(&mut rng).expect("generate_pok");

    // Merchant receives proof and stores it
    let mut merchant = merchant;
    merchant.receive_kes_proof(proof.clone());

    // Verify on both sides
    let merchant_state = merchant.into_inner();
    merchant_state.verify_kes_proof().expect("merchant verifies KES proof");

    let mut customer_state = customer_state;
    customer_state.kes_created(proof);
    customer_state.verify_kes_proof().expect("customer verifies KES proof");
}

// ============================================================================
// Channel nonce
// ============================================================================

// ============================================================================
// Serialization roundtrip
// ============================================================================

/// Full roundtrip test with all fields populated to non-default values.
///
/// Uses `full_establish_flow` to get a merchant state with all protocol context fields set
/// (wallet keyring, DLEQ proofs, adapted signatures, encrypted offsets, channel witness,
/// payload signatures, peer nonce pubkey), then adds multisig wallet, funding transactions,
/// KES proof, and funding pipe data.
///
/// Verifies that every field survives JSON serialization and deserialization, including
/// encrypted-at-rest fields (channel_witness, wallet_keyring).
#[test]
fn test_establishing_state_serialization_roundtrip() {
    use crate::amount::MoneroAmount;
    use crate::cryptography::encryption_context::{with_encryption_context, AesGcmEncryption};
    use crate::cryptography::Offset;
    use ciphersuite::group::ff::PrimeField;
    use std::sync::Arc;

    let (mut merchant, _customer, _kes_key) = full_establish_flow_with_kes_key();
    let mut rng = OsRng;

    // Populate remaining fields
    let wallet = crate::state_machine::lifecycle::test::create_wallet(ChannelRole::Merchant);
    merchant.wallet_created(wallet);
    merchant.save_funding_tx_pipe(vec![0xDE, 0xAD]);
    merchant.kes_created(dummy_kes_pok_proofs());
    let tx = TransactionRecord {
        channel_name: "test".into(),
        transaction_id: TransactionId::new("funding_tx_1"),
        amount: MoneroAmount::from_xmr("0.5").unwrap(),
        serialized: vec![1, 2, 3],
    };
    merchant.funding_tx_confirmed(tx);
    let tx2 = TransactionRecord {
        channel_name: "test".into(),
        transaction_id: TransactionId::new("funding_tx_2"),
        amount: MoneroAmount::from_xmr("0.75").unwrap(),
        serialized: vec![4, 5, 6],
    };
    merchant.funding_tx_confirmed(tx2);

    // Verify all Option fields are populated before serialization
    assert!(merchant.requirements_met());

    // Save original values for comparison
    let original_role = HasRole::role(&merchant);
    let original_channel_id = merchant.metadata.channel_id().name();
    let original_nonce = *merchant.channel_nonce.nonce();
    let original_tx_count = merchant.funding_transaction_ids.len();
    let original_pipe = merchant.funding_tx_pipe.clone();
    let original_witness_offset = *merchant.channel_witness.as_ref().unwrap().offset();
    let original_keyring_pubkey = merchant.wallet_keyring.as_ref().unwrap().public_key;
    let original_keyring_role = merchant.wallet_keyring.as_ref().unwrap().role;
    let original_peer_nonce = merchant.peer_nonce_pubkey.unwrap();

    // Serialize with encryption context
    let ctx = Arc::new(AesGcmEncryption::random());
    let json = with_encryption_context(ctx.clone(), || serde_json::to_string(&merchant).expect("serialize"));

    // Verify secrets are encrypted in the serialized output (not plaintext)
    assert!(
        json.contains("enc:"),
        "channel_witness and wallet_keyring secrets should be encrypted"
    );
    // The raw witness offset hex should NOT appear in the output
    let raw_witness_hex = hex::encode(original_witness_offset.to_repr());
    assert!(
        !json.contains(&raw_witness_hex),
        "plaintext witness offset should not appear in serialized JSON"
    );

    // Deserialize with same context
    let recovered: EstablishingState =
        with_encryption_context(ctx, || serde_json::from_str(&json).expect("deserialize"));

    // Assert metadata and basic fields
    assert_eq!(HasRole::role(&recovered), original_role);
    assert_eq!(recovered.metadata.channel_id().name(), original_channel_id);
    assert!(recovered.multisig_wallet.is_some(), "multisig wallet should survive roundtrip");
    assert_eq!(recovered.funding_transaction_ids.len(), original_tx_count);
    assert!(recovered.kes_proof.is_some(), "kes_proof should survive roundtrip");
    assert_eq!(recovered.funding_tx_pipe, original_pipe);
    assert_eq!(
        *recovered.channel_nonce.nonce(),
        original_nonce,
        "channel nonce should decrypt correctly"
    );

    let keyring = recovered.wallet_keyring.as_ref().expect("wallet_keyring should survive roundtrip");
    assert_eq!(keyring.role, original_keyring_role);
    assert_eq!(keyring.public_key, original_keyring_pubkey);

    assert!(
        recovered.encrypted_offset.is_some(),
        "encrypted_offset should survive roundtrip"
    );
    assert!(
        recovered.peer_encrypted_offset.is_some(),
        "peer_encrypted_offset should survive roundtrip"
    );

    // DLEQ proofs should still verify after roundtrip
    let dleq = recovered.dleq_proof.as_ref().expect("dleq_proof should survive roundtrip");
    dleq.verify().expect("own DLEQ proof should verify after roundtrip");
    let peer_dleq = recovered.peer_dleq_proof.as_ref().expect("peer_dleq_proof should survive roundtrip");
    peer_dleq.verify().expect("peer DLEQ proof should verify after roundtrip");

    // Adapted signatures should survive roundtrip
    assert!(recovered.adapted_sig.is_some(), "adapted_sig should survive roundtrip");
    assert!(
        recovered.peer_adapted_sig.is_some(),
        "peer_adapted_sig should survive roundtrip"
    );

    // Channel witness should decrypt and match (encrypted at rest)
    let witness = recovered.channel_witness.as_ref().expect("channel_witness should survive roundtrip");
    assert_eq!(
        *witness.offset(),
        original_witness_offset,
        "channel witness offset should match after roundtrip"
    );

    // Payload signatures should survive roundtrip
    assert!(recovered.payload_sig.is_some(), "payload_sig should survive roundtrip");
    assert!(
        recovered.peer_payload_sig.is_some(),
        "peer_payload_sig should survive roundtrip"
    );

    // Peer nonce pubkey should survive roundtrip
    let nonce_pk = recovered.peer_nonce_pubkey.expect("peer_nonce_pubkey should survive roundtrip");
    assert_eq!(nonce_pk, original_peer_nonce, "peer nonce pubkey should match after roundtrip");
}

// ============================================================================
// Payload signature validation
// ============================================================================

#[test]
fn test_payload_signature_rejects_tampered_offset() {
    let (merchant_state, customer_state) = establish_with_protocol_context();
    let mut rng = OsRng;

    let mut merchant = MerchantEstablishing::new(merchant_state).expect("merchant role");
    let mut customer = CustomerEstablishing::new(customer_state).expect("customer role");

    // Exchange wallet keys
    let merchant_shared_key = merchant.state().wallet_keyring.as_ref().map(|w| w.shared_public_key()).unwrap();
    let customer_shared_key = customer.state().wallet_keyring.as_ref().map(|w| w.shared_public_key()).unwrap();
    customer.state_mut().wallet_keyring.as_mut().map(|w| w.set_peer_public_key(merchant_shared_key));
    merchant.state_mut().wallet_keyring.as_mut().map(|w| w.set_peer_public_key(customer_shared_key));

    let mut customer_pkg = customer.generate_init_package(&mut rng).expect("customer package");

    // Tamper with the encrypted offset after signing
    let tampered_secret = crate::cryptography::secret_encryption::SecretWithRole::new(
        crate::XmrScalar::random(&mut rng),
        ChannelRole::Customer,
    );
    let kes_pubkey = merchant.state().metadata().kes_configuration().kes_public_key;
    let channel_id = merchant.state().metadata().channel_id().name();
    let domain = crate::grease_protocol::kes_establishing::kes_offset_domain(&channel_id);
    customer_pkg.encrypted_offset = crate::cryptography::secret_encryption::EncryptedSecret::<Ed25519>::encrypt(
        tampered_secret,
        &kes_pubkey,
        &mut rng,
        &domain,
    );

    let err = merchant.receive_customer_init_package(customer_pkg).unwrap_err();
    assert!(
        matches!(err, EstablishError::InvalidPayloadSignature(_)),
        "Should reject tampered encrypted offset, got: {err:?}"
    );
}

#[test]
fn test_payload_signature_rejects_wrong_signer() {
    use crate::cryptography::adapter_signature::SchnorrSignature;

    let (merchant_state, customer_state) = establish_with_protocol_context();
    let mut rng = OsRng;

    let mut merchant = MerchantEstablishing::new(merchant_state).expect("merchant role");
    let mut customer = CustomerEstablishing::new(customer_state).expect("customer role");

    // Exchange wallet keys
    let merchant_shared_key = merchant.state().wallet_keyring.as_ref().map(|w| w.shared_public_key()).unwrap();
    let customer_shared_key = customer.state().wallet_keyring.as_ref().map(|w| w.shared_public_key()).unwrap();
    customer.state_mut().wallet_keyring.as_mut().map(|w| w.set_peer_public_key(merchant_shared_key));
    merchant.state_mut().wallet_keyring.as_mut().map(|w| w.set_peer_public_key(customer_shared_key));

    let mut customer_pkg = customer.generate_init_package(&mut rng).expect("customer package");

    // Re-sign with a random key (not the customer's ephemeral key)
    let rogue_key = crate::XmrScalar::random(&mut rng);
    customer_pkg.payload_signature = SchnorrSignature::<Ed25519>::sign(&rogue_key, b"whatever", &mut rng);

    let err = merchant.receive_customer_init_package(customer_pkg).unwrap_err();
    assert!(
        matches!(err, EstablishError::InvalidPayloadSignature(_)),
        "Should reject wrong signer, got: {err:?}"
    );
}

#[test]
fn test_kes_rejects_invalid_bundle_signature() {
    use crate::cryptography::adapter_signature::SchnorrSignature;
    use crate::grease_protocol::kes_establishing::KesEstablishError;

    let (merchant_state, customer_state, kes_key) = full_establish_flow_with_kes_key();
    let merchant = MerchantEstablishing::new(merchant_state).expect("merchant role");
    let mut bundle = merchant.bundle_for_kes().expect("bundle_for_kes");

    // Tamper with the customer's payload signature
    let mut rng = OsRng;
    let rogue_key = crate::XmrScalar::random(&mut rng);
    bundle.customer_payload_sig = SchnorrSignature::<Ed25519>::sign(&rogue_key, b"tampered", &mut rng);

    let kes_secret = Zeroizing::new(kes_key);
    let kes_public = Ed25519::generator() * *kes_secret;
    let mut kes = KesEstablishing::<Ed25519>::new(kes_secret, kes_public);

    let err = kes.receive_bundle(bundle).unwrap_err();
    assert!(
        matches!(err, KesEstablishError::InvalidPayloadSignature { role: ChannelRole::Customer }),
        "Should reject invalid customer signature in bundle, got: {err:?}"
    );
}
