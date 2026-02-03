use crate::cryptography::keys::PublicKeyCommitment;
use crate::grease_protocol::multisig_wallet::{HasPublicKey, LinkedMultisigWallets};
use crate::grease_protocol::utils::Readable;
use crate::impls::mock_multisig_wallet::MockMultisigWallet;
use crate::impls::multisig::MultisigWalletKeyRing;
use crate::payment_channel::{ChannelRole, HasRole};
use crate::state_machine::multisig_setup::{
    CustomerSetup, CustomerStage, MerchantSetup, MerchantStage, MultisigSetupError, SetupState,
};
use modular_frost::sign::Writable;
use rand_core::OsRng;

// ============================================================================
// Type-Safe API Tests (MerchantSetup / CustomerSetup)
// ============================================================================

#[test]
fn test_happy_path_typed_api() {
    let mut rng = OsRng;
    let merchant_keyring = MultisigWalletKeyRing::random(&mut rng, ChannelRole::Merchant);
    let customer_keyring = MultisigWalletKeyRing::random(&mut rng, ChannelRole::Customer);

    let mut merchant = MerchantSetup::new(merchant_keyring).unwrap();
    let mut customer = CustomerSetup::new(customer_keyring).unwrap();

    // Verify initial states
    assert_eq!(merchant.stage(), MerchantStage::Initialized);
    assert_eq!(customer.stage(), CustomerStage::AwaitingPeerCommitment);

    // Step 1: Merchant sends commitment
    let commitment = merchant.send_commitment().unwrap();
    assert_eq!(merchant.stage(), MerchantStage::CommitmentSent);

    // Step 2: Customer receives commitment
    customer.receive_commitment(&commitment).unwrap();
    assert_eq!(customer.stage(), CustomerStage::AwaitingPeerKey);

    // Step 3: Customer sends public key
    let customer_key = customer.send_public_key().unwrap();

    // Step 4: Merchant receives customer's key
    merchant.receive_peer_key(&customer_key).unwrap();
    assert_eq!(merchant.stage(), MerchantStage::AwaitingPeerKey);

    // Step 5: Merchant sends public key and completes
    let merchant_key = merchant.send_public_key().unwrap();
    merchant.complete().unwrap();
    assert!(merchant.is_ready());

    // Step 6: Customer receives merchant's key
    customer.receive_peer_key(&merchant_key).unwrap();
    assert_eq!(customer.stage(), CustomerStage::AwaitingVerification);

    // Step 7: Customer verifies
    customer.verify().unwrap();
    assert!(customer.is_ready());

    // Finalize both
    let merchant_wallet = merchant.finalize().unwrap();
    let customer_wallet = customer.finalize().unwrap();

    // Verify sorted public keys match
    assert_eq!(merchant_wallet.sorted_public_keys().unwrap(), customer_wallet.sorted_public_keys().unwrap());
}

#[test]
fn test_merchant_stage_transitions() {
    let mut rng = OsRng;
    let merchant_keyring = MultisigWalletKeyRing::random(&mut rng, ChannelRole::Merchant);
    let customer_keyring = MultisigWalletKeyRing::random(&mut rng, ChannelRole::Customer);

    let mut merchant = MerchantSetup::new(merchant_keyring).unwrap();
    let customer = CustomerSetup::new(customer_keyring).unwrap();

    // Initialized -> CommitmentSent
    assert_eq!(merchant.stage(), MerchantStage::Initialized);
    let commitment = merchant.send_commitment().unwrap();
    assert_eq!(merchant.stage(), MerchantStage::CommitmentSent);

    // CommitmentSent -> AwaitingPeerKey
    let customer_key = customer.wallet().shared_public_key().serialize();
    merchant.receive_peer_key(&customer_key).unwrap();
    assert_eq!(merchant.stage(), MerchantStage::AwaitingPeerKey);

    // AwaitingPeerKey -> Complete
    merchant.complete().unwrap();
    assert_eq!(merchant.stage(), MerchantStage::Complete);
}

#[test]
fn test_customer_stage_transitions() {
    let mut rng = OsRng;
    let merchant_keyring = MultisigWalletKeyRing::random(&mut rng, ChannelRole::Merchant);
    let customer_keyring = MultisigWalletKeyRing::random(&mut rng, ChannelRole::Customer);

    let mut merchant = MerchantSetup::new(merchant_keyring).unwrap();
    let mut customer = CustomerSetup::new(customer_keyring).unwrap();

    // AwaitingPeerCommitment -> AwaitingPeerKey
    assert_eq!(customer.stage(), CustomerStage::AwaitingPeerCommitment);
    let commitment = merchant.send_commitment().unwrap();
    customer.receive_commitment(&commitment).unwrap();
    assert_eq!(customer.stage(), CustomerStage::AwaitingPeerKey);

    // Exchange keys
    let customer_key = customer.send_public_key().unwrap();
    merchant.receive_peer_key(&customer_key).unwrap();

    // AwaitingPeerKey -> AwaitingVerification
    let merchant_key = merchant.send_public_key().unwrap();
    customer.receive_peer_key(&merchant_key).unwrap();
    assert_eq!(customer.stage(), CustomerStage::AwaitingVerification);

    // AwaitingVerification -> Complete
    customer.verify().unwrap();
    assert_eq!(customer.stage(), CustomerStage::Complete);
}

#[test]
fn test_merchant_invalid_transitions() {
    let mut rng = OsRng;
    let keyring = MultisigWalletKeyRing::random(&mut rng, ChannelRole::Merchant);
    let mut merchant = MerchantSetup::new(keyring).unwrap();

    // Can't receive peer key from Initialized state
    let fake_key = vec![0u8; 64];
    assert!(merchant.receive_peer_key(&fake_key).is_err());

    // Can't complete from Initialized state
    assert!(merchant.complete().is_err());

    // After sending commitment, can't send again
    merchant.send_commitment().unwrap();
    assert!(merchant.send_commitment().is_err());
}

#[test]
fn test_customer_invalid_transitions() {
    let mut rng = OsRng;
    let keyring = MultisigWalletKeyRing::random(&mut rng, ChannelRole::Customer);
    let mut customer = CustomerSetup::new(keyring).unwrap();

    // Can't send key before receiving commitment
    assert!(customer.send_public_key().is_err());

    // Can't receive peer key before receiving commitment
    let fake_key = vec![0u8; 64];
    assert!(customer.receive_peer_key(&fake_key).is_err());

    // Can't verify before receiving peer key
    assert!(customer.verify().is_err());
}

#[test]
fn test_abort_typed_api() {
    let mut rng = OsRng;
    let merchant_keyring = MultisigWalletKeyRing::random(&mut rng, ChannelRole::Merchant);
    let customer_keyring = MultisigWalletKeyRing::random(&mut rng, ChannelRole::Customer);

    let mut merchant = MerchantSetup::new(merchant_keyring).unwrap();
    let mut customer = CustomerSetup::new(customer_keyring).unwrap();

    assert!(!merchant.has_aborted());
    assert!(!customer.has_aborted());

    merchant.abort(MultisigSetupError::Timeout);
    customer.abort(MultisigSetupError::MissingData("test".into()));

    assert!(merchant.has_aborted());
    assert!(customer.has_aborted());
    assert!(matches!(merchant.abort_reason(), Some(MultisigSetupError::Timeout)));
    assert!(matches!(customer.abort_reason(), Some(MultisigSetupError::MissingData(_))));
}

// ============================================================================
// Mock Wallet Tests
// ============================================================================

#[test]
fn test_happy_path_with_mock_wallets() {
    let merchant_mock = MockMultisigWallet::new_deterministic(ChannelRole::Merchant, [1u8; 32]);
    let customer_mock = MockMultisigWallet::new_deterministic(ChannelRole::Customer, [2u8; 32]);

    let mut merchant = MerchantSetup::new(merchant_mock).unwrap();
    let mut customer = CustomerSetup::new(customer_mock).unwrap();

    let commitment = merchant.send_commitment().unwrap();
    customer.receive_commitment(&commitment).unwrap();

    let customer_key = customer.send_public_key().unwrap();
    merchant.receive_peer_key(&customer_key).unwrap();

    let merchant_key = merchant.send_public_key().unwrap();
    merchant.complete().unwrap();

    customer.receive_peer_key(&merchant_key).unwrap();
    customer.verify().unwrap();

    assert!(merchant.is_ready());
    assert!(customer.is_ready());
}

#[test]
fn test_mock_inject_verify_failure() {
    let merchant_mock = MockMultisigWallet::new_deterministic(ChannelRole::Merchant, [1u8; 32]);
    let mut customer_mock = MockMultisigWallet::new_deterministic(ChannelRole::Customer, [2u8; 32]);

    // Inject verify failure on customer
    customer_mock.inject_verify_failure();

    let mut merchant = MerchantSetup::new(merchant_mock).unwrap();
    let mut customer = CustomerSetup::new(customer_mock).unwrap();

    let commitment = merchant.send_commitment().unwrap();
    customer.receive_commitment(&commitment).unwrap();

    let customer_key = customer.send_public_key().unwrap();
    merchant.receive_peer_key(&customer_key).unwrap();

    let merchant_key = merchant.send_public_key().unwrap();
    customer.receive_peer_key(&merchant_key).unwrap();

    // Verification should fail
    let result = customer.verify();
    assert!(matches!(result, Err(MultisigSetupError::CommitmentMismatch)));
}


// ============================================================================
// Serialization Tests
// ============================================================================

#[test]
fn test_public_key_serialization_roundtrip() {
    let mut rng = OsRng;
    let keyring = MultisigWalletKeyRing::random(&mut rng, ChannelRole::Merchant);

    let shared_key = keyring.shared_public_key();
    let serialized = shared_key.serialize();

    let deserialized = crate::grease_protocol::multisig_wallet::SharedPublicKey::read(&mut &serialized[..]).unwrap();

    assert_eq!(shared_key.public_key(), deserialized.public_key());
    assert_eq!(shared_key.role(), deserialized.role());
}

#[test]
fn test_commitment_serialization_roundtrip() {
    let mut rng = OsRng;
    let keyring = MultisigWalletKeyRing::random(&mut rng, ChannelRole::Merchant);

    let commitment = keyring.commit_to_public_key();
    let serialized = commitment.serialize();

    let deserialized = PublicKeyCommitment::read(&mut &serialized[..]).unwrap();
    assert_eq!(commitment, deserialized);
}

#[test]
fn test_deserialization_error_handling() {
    let customer_mock = MockMultisigWallet::new_deterministic(ChannelRole::Customer, [1u8; 32]);
    let mut customer = CustomerSetup::new(customer_mock).unwrap();

    // Receive valid commitment first
    let merchant_mock = MockMultisigWallet::new_deterministic(ChannelRole::Merchant, [2u8; 32]);
    let commitment = merchant_mock.commit_to_public_key().serialize();
    customer.receive_commitment(&commitment).unwrap();

    // Try to receive malformed peer key
    let bad_data = vec![0xFF, 0xFF];
    let result = customer.receive_peer_key(&bad_data);
    assert!(matches!(result, Err(MultisigSetupError::DeserializationError(_))));
}

// ============================================================================
// Display/Error Format Tests
// ============================================================================

#[test]
fn test_merchant_stage_display() {
    assert_eq!(MerchantStage::Initialized.to_string(), "Initialized");
    assert_eq!(MerchantStage::CommitmentSent.to_string(), "CommitmentSent");
    assert_eq!(MerchantStage::AwaitingPeerKey.to_string(), "AwaitingPeerKey");
    assert_eq!(MerchantStage::Complete.to_string(), "Complete");
    assert_eq!(MerchantStage::Aborted.to_string(), "Aborted");
}

#[test]
fn test_customer_stage_display() {
    assert_eq!(CustomerStage::AwaitingPeerCommitment.to_string(), "AwaitingPeerCommitment");
    assert_eq!(CustomerStage::AwaitingPeerKey.to_string(), "AwaitingPeerKey");
    assert_eq!(CustomerStage::AwaitingVerification.to_string(), "AwaitingVerification");
    assert_eq!(CustomerStage::Complete.to_string(), "Complete");
    assert_eq!(CustomerStage::Aborted.to_string(), "Aborted");
}

#[test]
fn test_error_display_format() {
    let err = MultisigSetupError::InvalidStateTransition { state: "Initialized".into(), action: "test" };
    assert!(err.to_string().contains("Initialized"));
    assert!(err.to_string().contains("test"));

    let err = MultisigSetupError::CommitmentMismatch;
    assert!(err.to_string().contains("commitment"));

    let err = MultisigSetupError::Timeout;
    assert!(err.to_string().contains("timed out"));
}

// ============================================================================
// Multiple Instance Tests
// ============================================================================

#[test]
fn test_multiple_setup_instances_independent() {
    let mut rng = OsRng;

    // Setup 1
    let m1_keyring = MultisigWalletKeyRing::random(&mut rng, ChannelRole::Merchant);
    let c1_keyring = MultisigWalletKeyRing::random(&mut rng, ChannelRole::Customer);
    let mut m1 = MerchantSetup::new(m1_keyring).unwrap();
    let mut c1 = CustomerSetup::new(c1_keyring).unwrap();

    // Setup 2
    let m2_keyring = MultisigWalletKeyRing::random(&mut rng, ChannelRole::Merchant);
    let c2_keyring = MultisigWalletKeyRing::random(&mut rng, ChannelRole::Customer);
    let mut m2 = MerchantSetup::new(m2_keyring).unwrap();
    let mut c2 = CustomerSetup::new(c2_keyring).unwrap();

    // Complete setup 1
    let commitment1 = m1.send_commitment().unwrap();
    c1.receive_commitment(&commitment1).unwrap();
    let c1_key = c1.send_public_key().unwrap();
    m1.receive_peer_key(&c1_key).unwrap();
    let m1_key = m1.send_public_key().unwrap();
    m1.complete().unwrap();
    c1.receive_peer_key(&m1_key).unwrap();
    c1.verify().unwrap();

    // Complete setup 2
    let commitment2 = m2.send_commitment().unwrap();
    c2.receive_commitment(&commitment2).unwrap();
    let c2_key = c2.send_public_key().unwrap();
    m2.receive_peer_key(&c2_key).unwrap();
    let m2_key = m2.send_public_key().unwrap();
    m2.complete().unwrap();
    c2.receive_peer_key(&m2_key).unwrap();
    c2.verify().unwrap();

    // Finalize all
    let m1_wallet = m1.finalize().unwrap();
    let c1_wallet = c1.finalize().unwrap();
    let m2_wallet = m2.finalize().unwrap();
    let c2_wallet = c2.finalize().unwrap();

    let keys1 = m1_wallet.sorted_public_keys().unwrap();
    let keys2 = m2_wallet.sorted_public_keys().unwrap();

    // Different setup instances have different keys
    assert_ne!(keys1, keys2);

    // But within each setup, merchant and customer have the same sorted keys
    assert_eq!(keys1, c1_wallet.sorted_public_keys().unwrap());
    assert_eq!(keys2, c2_wallet.sorted_public_keys().unwrap());
}
