//! Tests for the UpdateProtocol traits.
//!
//! These tests verify the channel update flow between proposer (initiator) and proposee (responder).

use crate::cryptography::adapter_signature::AdaptedSignature;
use crate::cryptography::keys::{Curve25519PublicKey, Curve25519Secret, PublicKey};
use crate::cryptography::mocks::MockVCOF;
use crate::grease_protocol::adapter_signature::AdapterSignatureHandler;
use crate::grease_protocol::update_channel::{
    UpdatePackage, UpdateProtocolCommon, UpdateProtocolError, UpdateProtocolProposee, UpdateProtocolProposer,
};
use crate::payment_channel::{ChannelRole, HasRole};
use crate::XmrScalar;
use async_trait::async_trait;
use ciphersuite::{Ciphersuite, Ed25519};
use rand_core::{CryptoRng, OsRng, RngCore};

/// Test implementation of UpdateProtocolProposer
struct TestUpdateProposer {
    role: ChannelRole,
    secret_key: Curve25519Secret,
    public_key: Curve25519PublicKey,
    vcof: MockVCOF,
    update_count: u64,
    current_offset: XmrScalar,
    pending_delta: Option<i64>,
    balance: i64,
}

impl TestUpdateProposer {
    fn new<R: RngCore + CryptoRng>(rng: &mut R, role: ChannelRole, initial_balance: i64) -> Self {
        let (secret_key, public_key) = Curve25519PublicKey::keypair(rng);
        let vcof = MockVCOF::new(public_key.as_point());
        Self {
            role,
            secret_key,
            public_key,
            vcof,
            update_count: 0,
            current_offset: XmrScalar::default(),
            pending_delta: None,
            balance: initial_balance,
        }
    }
}

impl HasRole for TestUpdateProposer {
    fn role(&self) -> ChannelRole {
        self.role
    }
}

impl AdapterSignatureHandler for TestUpdateProposer {
    fn initialize_signature_offset(&mut self) {
        self.current_offset = XmrScalar::default();
    }

    fn update_signature_offset(&mut self, offset: XmrScalar) {
        self.current_offset = offset;
    }

    fn adapter_signature_offset(&self) -> &XmrScalar {
        &self.current_offset
    }
}

#[async_trait]
impl UpdateProtocolCommon<Ed25519> for TestUpdateProposer {
    type VCOF = MockVCOF;

    fn vcof(&self) -> &Self::VCOF {
        &self.vcof
    }

    fn update_count(&self) -> u64 {
        self.update_count
    }

    async fn derive_next_witness(&mut self) -> Result<(), UpdateProtocolError> {
        // Mock derivation - just increment a counter internally
        Ok(())
    }

    async fn create_vcof_proof(&self) -> Result<Vec<u8>, UpdateProtocolError> {
        Ok(vec![0xDE, 0xAD, 0xBE, 0xEF])
    }

    async fn verify_vcof_proof(
        &self,
        _proof: &[u8],
        _peer_q_prev: &<Ed25519 as Ciphersuite>::G,
        _peer_q_curr: &<Ed25519 as Ciphersuite>::G,
    ) -> Result<(), UpdateProtocolError> {
        Ok(())
    }

    fn verify_peer_adapted_signature(
        &self,
        _sig: &AdaptedSignature<Ed25519>,
        _msg: &[u8],
    ) -> Result<(), UpdateProtocolError> {
        Ok(())
    }
}

impl UpdateProtocolProposer<Ed25519> for TestUpdateProposer {
    fn initiate_update(&mut self, delta: i64) -> Result<(), UpdateProtocolError> {
        if self.pending_delta.is_some() {
            return Err(UpdateProtocolError::UpdateInProgress);
        }

        // Check if we have sufficient balance (simplified)
        let new_balance = match self.role {
            ChannelRole::Customer => self.balance - delta,
            ChannelRole::Merchant => self.balance + delta,
        };

        if new_balance < 0 {
            return Err(UpdateProtocolError::InsufficientBalance(format!(
                "would result in negative balance: {new_balance}"
            )));
        }

        self.pending_delta = Some(delta);
        Ok(())
    }

    fn generate_tx_preprocessing<R: RngCore + CryptoRng>(
        &mut self,
        _rng: &mut R,
    ) -> Result<Vec<u8>, UpdateProtocolError> {
        if self.pending_delta.is_none() {
            return Err(UpdateProtocolError::NoUpdateInProgress);
        }
        Ok(vec![0x01, 0x02, 0x03])
    }

    fn create_update_package<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Result<UpdatePackage, UpdateProtocolError> {
        if self.pending_delta.is_none() {
            return Err(UpdateProtocolError::NoUpdateInProgress);
        }

        let adapted_sig =
            AdaptedSignature::<Ed25519>::sign(self.secret_key.as_scalar(), &self.current_offset, "test_msg", rng);

        Ok(UpdatePackage {
            update_count: self.update_count + 1,
            adapted_signature: adapted_sig,
            vcof_proof: vec![0xDE, 0xAD, 0xBE, 0xEF],
            preprocess: vec![0x01, 0x02, 0x03],
        })
    }

    fn process_response(&mut self, response: &UpdatePackage) -> Result<(), UpdateProtocolError> {
        if response.update_count != self.update_count + 1 {
            return Err(UpdateProtocolError::UpdateCountMismatch {
                expected: self.update_count + 1,
                actual: response.update_count,
            });
        }
        Ok(())
    }

    fn finalize_update(&mut self) -> Result<u64, UpdateProtocolError> {
        let delta = self.pending_delta.take().ok_or(UpdateProtocolError::NoUpdateInProgress)?;

        match self.role {
            ChannelRole::Customer => self.balance -= delta,
            ChannelRole::Merchant => self.balance += delta,
        }

        self.update_count += 1;
        Ok(self.update_count)
    }

    fn abort_update(&mut self) -> Result<(), UpdateProtocolError> {
        self.pending_delta = None;
        Ok(())
    }
}

/// Test implementation of UpdateProtocolProposee
struct TestUpdateProposee {
    role: ChannelRole,
    secret_key: Curve25519Secret,
    public_key: Curve25519PublicKey,
    vcof: MockVCOF,
    update_count: u64,
    current_offset: XmrScalar,
    pending_delta: Option<i64>,
    balance: i64,
    rejected_reason: Option<String>,
}

impl TestUpdateProposee {
    fn new<R: RngCore + CryptoRng>(rng: &mut R, role: ChannelRole, initial_balance: i64) -> Self {
        let (secret_key, public_key) = Curve25519PublicKey::keypair(rng);
        let vcof = MockVCOF::new(public_key.as_point());
        Self {
            role,
            secret_key,
            public_key,
            vcof,
            update_count: 0,
            current_offset: XmrScalar::default(),
            pending_delta: None,
            balance: initial_balance,
            rejected_reason: None,
        }
    }
}

impl HasRole for TestUpdateProposee {
    fn role(&self) -> ChannelRole {
        self.role
    }
}

impl AdapterSignatureHandler for TestUpdateProposee {
    fn initialize_signature_offset(&mut self) {
        self.current_offset = XmrScalar::default();
    }

    fn update_signature_offset(&mut self, offset: XmrScalar) {
        self.current_offset = offset;
    }

    fn adapter_signature_offset(&self) -> &XmrScalar {
        &self.current_offset
    }
}

#[async_trait]
impl UpdateProtocolCommon<Ed25519> for TestUpdateProposee {
    type VCOF = MockVCOF;

    fn vcof(&self) -> &Self::VCOF {
        &self.vcof
    }

    fn update_count(&self) -> u64 {
        self.update_count
    }

    async fn derive_next_witness(&mut self) -> Result<(), UpdateProtocolError> {
        Ok(())
    }

    async fn create_vcof_proof(&self) -> Result<Vec<u8>, UpdateProtocolError> {
        Ok(vec![0xCA, 0xFE, 0xBA, 0xBE])
    }

    async fn verify_vcof_proof(
        &self,
        _proof: &[u8],
        _peer_q_prev: &<Ed25519 as Ciphersuite>::G,
        _peer_q_curr: &<Ed25519 as Ciphersuite>::G,
    ) -> Result<(), UpdateProtocolError> {
        Ok(())
    }

    fn verify_peer_adapted_signature(
        &self,
        _sig: &AdaptedSignature<Ed25519>,
        _msg: &[u8],
    ) -> Result<(), UpdateProtocolError> {
        Ok(())
    }
}

impl UpdateProtocolProposee<Ed25519> for TestUpdateProposee {
    fn receive_update_request(&mut self, delta: i64) -> Result<(), UpdateProtocolError> {
        if self.pending_delta.is_some() {
            return Err(UpdateProtocolError::UpdateInProgress);
        }

        // Check if update is valid for our side
        let new_balance = match self.role {
            ChannelRole::Customer => self.balance - delta,
            ChannelRole::Merchant => self.balance + delta,
        };

        if new_balance < 0 {
            return Err(UpdateProtocolError::InsufficientBalance(format!(
                "would result in negative balance: {new_balance}"
            )));
        }

        self.pending_delta = Some(delta);
        Ok(())
    }

    fn process_tx_preprocessing(&mut self, _preprocess: &[u8]) -> Result<Vec<u8>, UpdateProtocolError> {
        if self.pending_delta.is_none() {
            return Err(UpdateProtocolError::NoUpdateInProgress);
        }
        Ok(vec![0x04, 0x05, 0x06])
    }

    fn process_update_package(&mut self, package: &UpdatePackage) -> Result<(), UpdateProtocolError> {
        if package.update_count != self.update_count + 1 {
            return Err(UpdateProtocolError::UpdateCountMismatch {
                expected: self.update_count + 1,
                actual: package.update_count,
            });
        }
        Ok(())
    }

    fn create_response<R: RngCore + CryptoRng>(&mut self, rng: &mut R) -> Result<UpdatePackage, UpdateProtocolError> {
        if self.pending_delta.is_none() {
            return Err(UpdateProtocolError::NoUpdateInProgress);
        }

        let adapted_sig =
            AdaptedSignature::<Ed25519>::sign(self.secret_key.as_scalar(), &self.current_offset, "test_msg", rng);

        Ok(UpdatePackage {
            update_count: self.update_count + 1,
            adapted_signature: adapted_sig,
            vcof_proof: vec![0xCA, 0xFE, 0xBA, 0xBE],
            preprocess: vec![0x04, 0x05, 0x06],
        })
    }

    fn finalize_update(&mut self) -> Result<u64, UpdateProtocolError> {
        let delta = self.pending_delta.take().ok_or(UpdateProtocolError::NoUpdateInProgress)?;

        match self.role {
            ChannelRole::Customer => self.balance -= delta,
            ChannelRole::Merchant => self.balance += delta,
        }

        self.update_count += 1;
        Ok(self.update_count)
    }

    fn reject_update(&mut self, reason: &str) -> Result<(), UpdateProtocolError> {
        self.pending_delta = None;
        self.rejected_reason = Some(reason.to_string());
        Ok(())
    }
}

#[test]
fn test_update_initiation() {
    let mut rng = OsRng;
    let mut proposer = TestUpdateProposer::new(&mut rng, ChannelRole::Customer, 1000);

    // Initiate update (customer pays merchant 100)
    proposer.initiate_update(100).expect("should initiate update");
    assert!(proposer.pending_delta.is_some());
}

#[test]
fn test_update_insufficient_balance() {
    let mut rng = OsRng;
    let mut proposer = TestUpdateProposer::new(&mut rng, ChannelRole::Customer, 100);

    // Try to pay more than balance
    let result = proposer.initiate_update(200);
    assert!(matches!(result, Err(UpdateProtocolError::InsufficientBalance(_))));
}

#[test]
fn test_update_already_in_progress() {
    let mut rng = OsRng;
    let mut proposer = TestUpdateProposer::new(&mut rng, ChannelRole::Customer, 1000);

    proposer.initiate_update(100).expect("first update should succeed");
    let result = proposer.initiate_update(50);
    assert!(matches!(result, Err(UpdateProtocolError::UpdateInProgress)));
}

#[test]
fn test_full_update_flow() {
    let mut rng = OsRng;

    // Customer starts with 1000, merchant with 0
    let mut proposer = TestUpdateProposer::new(&mut rng, ChannelRole::Customer, 1000);
    let mut proposee = TestUpdateProposee::new(&mut rng, ChannelRole::Merchant, 0);

    // 1. Proposer initiates update (customer pays 100 to merchant)
    proposer.initiate_update(100).expect("should initiate");

    // 2. Proposer generates preprocessing
    let preprocess = proposer.generate_tx_preprocessing(&mut rng).expect("should generate preprocess");

    // 3. Proposee receives request and processes preprocessing
    proposee.receive_update_request(100).expect("should receive request");
    let _response_preprocess = proposee.process_tx_preprocessing(&preprocess).expect("should process preprocess");

    // 4. Proposer creates update package
    let package = proposer.create_update_package(&mut rng).expect("should create package");
    assert_eq!(package.update_count, 1);

    // 5. Proposee processes package and creates response
    proposee.process_update_package(&package).expect("should process package");
    let response = proposee.create_response(&mut rng).expect("should create response");

    // 6. Proposer processes response
    proposer.process_response(&response).expect("should process response");

    // 7. Both finalize
    let proposer_count = proposer.finalize_update().expect("proposer finalize");
    let proposee_count = proposee.finalize_update().expect("proposee finalize");

    assert_eq!(proposer_count, 1);
    assert_eq!(proposee_count, 1);
    assert_eq!(proposer.balance, 900); // Customer paid 100
    assert_eq!(proposee.balance, 100); // Merchant received 100
}

#[test]
fn test_update_count_mismatch() {
    let mut rng = OsRng;
    let mut proposer = TestUpdateProposer::new(&mut rng, ChannelRole::Customer, 1000);

    proposer.initiate_update(100).expect("should initiate");

    // Create a package with wrong update count
    let bad_package = UpdatePackage {
        update_count: 5, // Wrong!
        adapted_signature: AdaptedSignature::<Ed25519>::sign(
            proposer.secret_key.as_scalar(),
            &proposer.current_offset,
            "test",
            &mut rng,
        ),
        vcof_proof: vec![],
        preprocess: vec![],
    };

    let result = proposer.process_response(&bad_package);
    assert!(matches!(
        result,
        Err(UpdateProtocolError::UpdateCountMismatch { expected: 1, actual: 5 })
    ));
}

#[test]
fn test_update_abort() {
    let mut rng = OsRng;
    let mut proposer = TestUpdateProposer::new(&mut rng, ChannelRole::Customer, 1000);

    proposer.initiate_update(100).expect("should initiate");
    assert!(proposer.pending_delta.is_some());

    proposer.abort_update().expect("should abort");
    assert!(proposer.pending_delta.is_none());

    // Balance should be unchanged
    assert_eq!(proposer.balance, 1000);
}

#[test]
fn test_update_rejection() {
    let mut rng = OsRng;
    let mut proposee = TestUpdateProposee::new(&mut rng, ChannelRole::Merchant, 0);

    proposee.receive_update_request(100).expect("should receive request");
    proposee.reject_update("test rejection").expect("should reject");

    assert!(proposee.pending_delta.is_none());
    assert_eq!(proposee.rejected_reason, Some("test rejection".to_string()));
}

#[test]
fn test_multiple_updates() {
    let mut rng = OsRng;

    let mut proposer = TestUpdateProposer::new(&mut rng, ChannelRole::Customer, 1000);
    let mut proposee = TestUpdateProposee::new(&mut rng, ChannelRole::Merchant, 0);

    // First update: customer pays 100
    proposer.initiate_update(100).unwrap();
    proposee.receive_update_request(100).unwrap();
    let package = proposer.create_update_package(&mut rng).unwrap();
    proposee.process_update_package(&package).unwrap();
    let response = proposee.create_response(&mut rng).unwrap();
    proposer.process_response(&response).unwrap();
    proposer.finalize_update().unwrap();
    proposee.finalize_update().unwrap();

    assert_eq!(proposer.update_count, 1);
    assert_eq!(proposee.update_count, 1);

    // Second update: customer pays another 200
    proposer.initiate_update(200).unwrap();
    proposee.receive_update_request(200).unwrap();
    let package = proposer.create_update_package(&mut rng).unwrap();
    proposee.process_update_package(&package).unwrap();
    let response = proposee.create_response(&mut rng).unwrap();
    proposer.process_response(&response).unwrap();
    proposer.finalize_update().unwrap();
    proposee.finalize_update().unwrap();

    assert_eq!(proposer.update_count, 2);
    assert_eq!(proposee.update_count, 2);
    assert_eq!(proposer.balance, 700);
    assert_eq!(proposee.balance, 300);
}

#[test]
fn test_create_package_without_initiation() {
    let mut rng = OsRng;
    let mut proposer = TestUpdateProposer::new(&mut rng, ChannelRole::Customer, 1000);

    let result = proposer.create_update_package(&mut rng);
    assert!(matches!(result, Err(UpdateProtocolError::NoUpdateInProgress)));
}

#[test]
fn test_finalize_without_update() {
    let mut rng = OsRng;
    let mut proposer = TestUpdateProposer::new(&mut rng, ChannelRole::Customer, 1000);

    let result = proposer.finalize_update();
    assert!(matches!(result, Err(UpdateProtocolError::NoUpdateInProgress)));
}

#[tokio::test]
async fn test_async_vcof_operations() {
    let mut rng = OsRng;
    let mut proposer = TestUpdateProposer::new(&mut rng, ChannelRole::Customer, 1000);

    // Test async derive_next_witness
    proposer.derive_next_witness().await.expect("should derive witness");

    // Test async create_vcof_proof
    let proof = proposer.create_vcof_proof().await.expect("should create proof");
    assert!(!proof.is_empty());

    // Test async verify_vcof_proof
    let dummy_point = Ed25519::generator();
    proposer.verify_vcof_proof(&proof, &dummy_point, &dummy_point).await.expect("should verify proof");
}
