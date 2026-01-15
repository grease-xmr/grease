//! Tests for the ForceCloseProtocol traits (dispute resolution).
//!
//! These tests verify the force close and dispute flow between claimant and defendant.

use crate::channel_id::ChannelId;
use crate::cryptography::keys::{Curve25519PublicKey, PublicKey};
use crate::grease_protocol::force_close_channel::{
    ClaimChannelRequest, ConsensusCloseRequest, DisputeChannelState, DisputeResolution, ForceCloseProtocolClaimant,
    ForceCloseProtocolCommon, ForceCloseProtocolDefendant, ForceCloseProtocolError, ForceCloseRequest,
    ForceCloseResponse, PendingChannelClose, PendingCloseStatus,
};
use crate::monero::data_objects::TransactionId;
use crate::payment_channel::{ChannelRole, HasRole};
use crate::XmrScalar;
use rand_core::OsRng;
use std::str::FromStr;

fn test_channel_id() -> ChannelId {
    ChannelId::from_str("XGC4a7024e7fd6f5c6a2d0131d12fd91ecd17f5da61c2970d603a05053b41a383").unwrap()
}

/// Test implementation of ForceCloseProtocolClaimant
struct TestClaimant {
    role: ChannelRole,
    channel_id: ChannelId,
    public_key: Curve25519PublicKey,
    peer_public_key: Curve25519PublicKey,
    update_count: u64,
    dispute_window_secs: u64,
    dispute_window_end: Option<u64>,
    claimed_offset: Option<XmrScalar>,
}

impl TestClaimant {
    fn new(role: ChannelRole, channel_id: ChannelId, update_count: u64) -> Self {
        let mut rng = OsRng;
        let (_, public_key) = Curve25519PublicKey::keypair(&mut rng);
        let (_, peer_public_key) = Curve25519PublicKey::keypair(&mut rng);

        Self {
            role,
            channel_id,
            public_key,
            peer_public_key,
            update_count,
            dispute_window_secs: 3600, // 1 hour
            dispute_window_end: None,
            claimed_offset: None,
        }
    }
}

impl HasRole for TestClaimant {
    fn role(&self) -> ChannelRole {
        self.role
    }
}

impl ForceCloseProtocolCommon for TestClaimant {
    fn channel_id(&self) -> ChannelId {
        self.channel_id.clone()
    }

    fn public_key(&self) -> &Curve25519PublicKey {
        &self.public_key
    }

    fn peer_public_key(&self) -> &Curve25519PublicKey {
        &self.peer_public_key
    }

    fn dispute_window_secs(&self) -> u64 {
        self.dispute_window_secs
    }

    fn update_count(&self) -> u64 {
        self.update_count
    }

    fn sign_for_kes(&self, message: &[u8]) -> Result<Vec<u8>, ForceCloseProtocolError> {
        // Mock signature
        Ok([message, b"_signed_by_claimant"].concat())
    }

    fn verify_peer_signature(&self, _message: &[u8], _sig: &[u8]) -> Result<(), ForceCloseProtocolError> {
        Ok(())
    }
}

impl ForceCloseProtocolClaimant for TestClaimant {
    fn create_force_close_request(&self) -> Result<ForceCloseRequest, ForceCloseProtocolError> {
        let message = format!("force_close:{}:{}", self.channel_id, self.update_count);
        let signature = self.sign_for_kes(message.as_bytes())?;

        Ok(ForceCloseRequest {
            channel_id: self.channel_id.clone(),
            claimant: self.public_key.clone(),
            defendant: self.peer_public_key.clone(),
            update_count_claimed: self.update_count,
            signature,
        })
    }

    fn handle_force_close_response(&mut self, response: ForceCloseResponse) -> Result<(), ForceCloseProtocolError> {
        match response {
            ForceCloseResponse::Accepted { dispute_window_end } => {
                self.dispute_window_end = Some(dispute_window_end);
                Ok(())
            }
            ForceCloseResponse::Rejected { reason } => Err(ForceCloseProtocolError::KesRejected(reason)),
        }
    }

    fn create_claim_request(&self) -> Result<ClaimChannelRequest, ForceCloseProtocolError> {
        if self.dispute_window_end.is_none() {
            return Err(ForceCloseProtocolError::NoPendingForceClose);
        }

        let message = format!("claim:{}:{}", self.channel_id, self.public_key.as_hex());
        let signature = self.sign_for_kes(message.as_bytes())?;

        Ok(ClaimChannelRequest { channel_id: self.channel_id.clone(), claimant: self.public_key.clone(), signature })
    }

    fn process_claimed_offset(&mut self, _encrypted: &[u8]) -> Result<XmrScalar, ForceCloseProtocolError> {
        // Mock decryption
        let offset = XmrScalar::default();
        self.claimed_offset = Some(offset.clone());
        Ok(offset)
    }

    fn complete_closing_tx(&self, _peer_offset: &XmrScalar) -> Result<Vec<u8>, ForceCloseProtocolError> {
        if self.claimed_offset.is_none() {
            return Err(ForceCloseProtocolError::MissingInformation("offset not claimed".into()));
        }
        Ok(vec![0xDE, 0xAD, 0xBE, 0xEF]) // Mock transaction
    }

    fn broadcast_closing_tx(&self, _tx: &[u8]) -> Result<TransactionId, ForceCloseProtocolError> {
        Ok(TransactionId { id: "force_close_txid_12345".to_string() })
    }
}

/// Test implementation of ForceCloseProtocolDefendant
struct TestDefendant {
    role: ChannelRole,
    channel_id: ChannelId,
    public_key: Curve25519PublicKey,
    peer_public_key: Curve25519PublicKey,
    update_count: u64,
    dispute_window_secs: u64,
    pending_close: Option<PendingChannelClose>,
    dispute_resolution: Option<DisputeResolution>,
}

impl TestDefendant {
    fn new(role: ChannelRole, channel_id: ChannelId, update_count: u64) -> Self {
        let mut rng = OsRng;
        let (_, public_key) = Curve25519PublicKey::keypair(&mut rng);
        let (_, peer_public_key) = Curve25519PublicKey::keypair(&mut rng);

        Self {
            role,
            channel_id,
            public_key,
            peer_public_key,
            update_count,
            dispute_window_secs: 3600,
            pending_close: None,
            dispute_resolution: None,
        }
    }

    fn with_keys(mut self, claimant_key: Curve25519PublicKey) -> Self {
        self.peer_public_key = claimant_key;
        self
    }
}

impl HasRole for TestDefendant {
    fn role(&self) -> ChannelRole {
        self.role
    }
}

impl ForceCloseProtocolCommon for TestDefendant {
    fn channel_id(&self) -> ChannelId {
        self.channel_id.clone()
    }

    fn public_key(&self) -> &Curve25519PublicKey {
        &self.public_key
    }

    fn peer_public_key(&self) -> &Curve25519PublicKey {
        &self.peer_public_key
    }

    fn dispute_window_secs(&self) -> u64 {
        self.dispute_window_secs
    }

    fn update_count(&self) -> u64 {
        self.update_count
    }

    fn sign_for_kes(&self, message: &[u8]) -> Result<Vec<u8>, ForceCloseProtocolError> {
        Ok([message, b"_signed_by_defendant"].concat())
    }

    fn verify_peer_signature(&self, _message: &[u8], _sig: &[u8]) -> Result<(), ForceCloseProtocolError> {
        Ok(())
    }
}

impl ForceCloseProtocolDefendant for TestDefendant {
    fn receive_force_close_notification(&mut self, notif: PendingChannelClose) -> Result<(), ForceCloseProtocolError> {
        if self.pending_close.is_some() {
            return Err(ForceCloseProtocolError::ForceCloseAlreadyPending);
        }

        if notif.channel_id != self.channel_id {
            return Err(ForceCloseProtocolError::ChannelNotFound(notif.channel_id.to_string()));
        }

        self.pending_close = Some(notif);
        Ok(())
    }

    fn has_more_recent_state(&self, claimed_count: u64) -> bool {
        self.update_count > claimed_count
    }

    fn create_consensus_close(&self) -> Result<ConsensusCloseRequest, ForceCloseProtocolError> {
        let pending = self.pending_close.as_ref().ok_or(ForceCloseProtocolError::NoPendingForceClose)?;

        let message = format!("consensus:{}:{}", self.channel_id, pending.update_count_claimed);
        let signature = self.sign_for_kes(message.as_bytes())?;

        Ok(ConsensusCloseRequest {
            channel_id: self.channel_id.clone(),
            claimant: pending.claimant.clone(),
            defendant: self.public_key.clone(),
            update_count_claimed: pending.update_count_claimed,
            encrypted_offset: vec![0x01, 0x02, 0x03], // Mock encrypted offset
            signature,
        })
    }

    fn create_dispute(&self) -> Result<DisputeChannelState, ForceCloseProtocolError> {
        let pending = self.pending_close.as_ref().ok_or(ForceCloseProtocolError::NoPendingForceClose)?;

        if !self.has_more_recent_state(pending.update_count_claimed) {
            return Err(ForceCloseProtocolError::UpdateCountTooLow {
                claimed: pending.update_count_claimed,
                actual: self.update_count,
            });
        }

        let message = format!("dispute:{}:{}", self.channel_id, self.update_count);
        let signature = self.sign_for_kes(message.as_bytes())?;

        Ok(DisputeChannelState {
            channel_id: self.channel_id.clone(),
            claimant: pending.claimant.clone(),
            defendant: self.public_key.clone(),
            update_count: self.update_count,
            update_record: vec![0xCA, 0xFE, 0xBA, 0xBE], // Mock update record
            signature,
        })
    }

    fn handle_dispute_resolution(&mut self, resolution: DisputeResolution) -> Result<(), ForceCloseProtocolError> {
        self.dispute_resolution = Some(resolution);
        Ok(())
    }
}

#[test]
fn test_create_force_close_request() {
    let channel_id = test_channel_id();
    let claimant = TestClaimant::new(ChannelRole::Customer, channel_id.clone(), 5);

    let request = claimant.create_force_close_request().expect("should create request");

    assert_eq!(request.channel_id, channel_id);
    assert_eq!(request.update_count_claimed, 5);
    assert!(!request.signature.is_empty());
}

#[test]
fn test_handle_force_close_accepted() {
    let channel_id = test_channel_id();
    let mut claimant = TestClaimant::new(ChannelRole::Customer, channel_id, 5);

    let response = ForceCloseResponse::Accepted { dispute_window_end: 1000000 };
    claimant.handle_force_close_response(response).expect("should handle response");

    assert_eq!(claimant.dispute_window_end, Some(1000000));
}

#[test]
fn test_handle_force_close_rejected() {
    let channel_id = test_channel_id();
    let mut claimant = TestClaimant::new(ChannelRole::Customer, channel_id, 5);

    let response = ForceCloseResponse::Rejected { reason: "invalid signature".to_string() };
    let result = claimant.handle_force_close_response(response);

    assert!(matches!(result, Err(ForceCloseProtocolError::KesRejected(_))));
}

#[test]
fn test_create_claim_request() {
    let channel_id = test_channel_id();
    let mut claimant = TestClaimant::new(ChannelRole::Customer, channel_id.clone(), 5);

    // Must have pending force close first
    claimant.dispute_window_end = Some(1000000);

    let claim = claimant.create_claim_request().expect("should create claim");
    assert_eq!(claim.channel_id, channel_id);
    assert!(!claim.signature.is_empty());
}

#[test]
fn test_create_claim_without_pending_fails() {
    let channel_id = test_channel_id();
    let claimant = TestClaimant::new(ChannelRole::Customer, channel_id, 5);

    let result = claimant.create_claim_request();
    assert!(matches!(result, Err(ForceCloseProtocolError::NoPendingForceClose)));
}

#[test]
fn test_defendant_receives_notification() {
    let channel_id = test_channel_id();
    let claimant = TestClaimant::new(ChannelRole::Customer, channel_id.clone(), 5);
    let mut defendant = TestDefendant::new(ChannelRole::Merchant, channel_id.clone(), 5);

    let notif = PendingChannelClose {
        channel_id: channel_id.clone(),
        claimant: claimant.public_key.clone(),
        update_count_claimed: 5,
        dispute_window_end: 1000000,
    };

    defendant.receive_force_close_notification(notif).expect("should receive notification");
    assert!(defendant.pending_close.is_some());
}

#[test]
fn test_duplicate_notification_rejected() {
    let channel_id = test_channel_id();
    let claimant = TestClaimant::new(ChannelRole::Customer, channel_id.clone(), 5);
    let mut defendant = TestDefendant::new(ChannelRole::Merchant, channel_id.clone(), 5);

    let notif = PendingChannelClose {
        channel_id: channel_id.clone(),
        claimant: claimant.public_key.clone(),
        update_count_claimed: 5,
        dispute_window_end: 1000000,
    };

    defendant.receive_force_close_notification(notif.clone()).expect("first should succeed");
    let result = defendant.receive_force_close_notification(notif);
    assert!(matches!(result, Err(ForceCloseProtocolError::ForceCloseAlreadyPending)));
}

#[test]
fn test_consensus_close() {
    let channel_id = test_channel_id();
    let claimant = TestClaimant::new(ChannelRole::Customer, channel_id.clone(), 5);
    let mut defendant = TestDefendant::new(ChannelRole::Merchant, channel_id.clone(), 5);

    // Defendant has same update count - should agree
    let notif = PendingChannelClose {
        channel_id: channel_id.clone(),
        claimant: claimant.public_key.clone(),
        update_count_claimed: 5,
        dispute_window_end: 1000000,
    };

    defendant.receive_force_close_notification(notif).unwrap();

    // Defendant agrees (same update count)
    assert!(!defendant.has_more_recent_state(5));

    let consensus = defendant.create_consensus_close().expect("should create consensus");
    assert_eq!(consensus.update_count_claimed, 5);
    assert!(!consensus.encrypted_offset.is_empty());
}

#[test]
fn test_dispute_with_newer_state() {
    let channel_id = test_channel_id();
    let claimant = TestClaimant::new(ChannelRole::Customer, channel_id.clone(), 5);
    let mut defendant = TestDefendant::new(ChannelRole::Merchant, channel_id.clone(), 10); // Has newer state!

    let notif = PendingChannelClose {
        channel_id: channel_id.clone(),
        claimant: claimant.public_key.clone(),
        update_count_claimed: 5,
        dispute_window_end: 1000000,
    };

    defendant.receive_force_close_notification(notif).unwrap();

    // Defendant has more recent state
    assert!(defendant.has_more_recent_state(5));

    let dispute = defendant.create_dispute().expect("should create dispute");
    assert_eq!(dispute.update_count, 10);
    assert!(!dispute.update_record.is_empty());
}

#[test]
fn test_dispute_without_newer_state_fails() {
    let channel_id = test_channel_id();
    let claimant = TestClaimant::new(ChannelRole::Customer, channel_id.clone(), 10);
    let mut defendant = TestDefendant::new(ChannelRole::Merchant, channel_id.clone(), 5); // Has older state

    let notif = PendingChannelClose {
        channel_id: channel_id.clone(),
        claimant: claimant.public_key.clone(),
        update_count_claimed: 10,
        dispute_window_end: 1000000,
    };

    defendant.receive_force_close_notification(notif).unwrap();

    let result = defendant.create_dispute();
    assert!(matches!(result, Err(ForceCloseProtocolError::UpdateCountTooLow { claimed: 10, actual: 5 })));
}

#[test]
fn test_handle_dispute_resolution_claimant_wins() {
    let channel_id = test_channel_id();
    let mut defendant = TestDefendant::new(ChannelRole::Merchant, channel_id, 5);

    let resolution = DisputeResolution::ClaimantWins { encrypted_offset: vec![0x01, 0x02] };

    defendant.handle_dispute_resolution(resolution).expect("should handle resolution");
    assert!(matches!(defendant.dispute_resolution, Some(DisputeResolution::ClaimantWins { .. })));
}

#[test]
fn test_handle_dispute_resolution_defendant_wins() {
    let channel_id = test_channel_id();
    let mut defendant = TestDefendant::new(ChannelRole::Merchant, channel_id, 10);

    let resolution = DisputeResolution::DefendantWins { penalty_applied: true };

    defendant.handle_dispute_resolution(resolution).expect("should handle resolution");
    assert!(matches!(defendant.dispute_resolution, Some(DisputeResolution::DefendantWins { penalty_applied: true })));
}

#[test]
fn test_complete_closing_tx() {
    let channel_id = test_channel_id();
    let mut claimant = TestClaimant::new(ChannelRole::Customer, channel_id, 5);

    // Setup: claim offset first
    claimant.dispute_window_end = Some(1000000);
    claimant.process_claimed_offset(&[1, 2, 3]).expect("should process offset");

    let peer_offset = XmrScalar::default();
    let tx = claimant.complete_closing_tx(&peer_offset).expect("should complete tx");
    assert!(!tx.is_empty());

    let txid = claimant.broadcast_closing_tx(&tx).expect("should broadcast");
    assert!(!txid.id.is_empty());
}

#[test]
fn test_complete_tx_without_offset_fails() {
    let channel_id = test_channel_id();
    let claimant = TestClaimant::new(ChannelRole::Customer, channel_id, 5);

    let peer_offset = XmrScalar::default();
    let result = claimant.complete_closing_tx(&peer_offset);
    assert!(matches!(result, Err(ForceCloseProtocolError::MissingInformation(_))));
}

#[test]
fn test_pending_close_status_values() {
    // Verify all status variants exist and are distinct
    let statuses = vec![
        PendingCloseStatus::Pending,
        PendingCloseStatus::Claimable,
        PendingCloseStatus::Abandoned,
        PendingCloseStatus::ConsensusClosed,
        PendingCloseStatus::ForceClosed,
        PendingCloseStatus::AbandonedClaimed,
        PendingCloseStatus::DisputeSuccessful,
    ];

    assert_eq!(statuses.len(), 7);
    assert_ne!(PendingCloseStatus::Pending, PendingCloseStatus::Claimable);
}

#[test]
fn test_force_close_request_serialization() {
    let channel_id = test_channel_id();
    let mut rng = OsRng;
    let (_, claimant_key) = Curve25519PublicKey::keypair(&mut rng);
    let (_, defendant_key) = Curve25519PublicKey::keypair(&mut rng);

    let request = ForceCloseRequest {
        channel_id: channel_id.clone(),
        claimant: claimant_key,
        defendant: defendant_key,
        update_count_claimed: 42,
        signature: vec![0xDE, 0xAD],
    };

    let serialized = ron::to_string(&request).expect("should serialize");
    let deserialized: ForceCloseRequest = ron::from_str(&serialized).expect("should deserialize");

    assert_eq!(deserialized.channel_id, channel_id);
    assert_eq!(deserialized.update_count_claimed, 42);
}

#[test]
fn test_dispute_channel_state_serialization() {
    let channel_id = test_channel_id();
    let mut rng = OsRng;
    let (_, claimant_key) = Curve25519PublicKey::keypair(&mut rng);
    let (_, defendant_key) = Curve25519PublicKey::keypair(&mut rng);

    let dispute = DisputeChannelState {
        channel_id: channel_id.clone(),
        claimant: claimant_key,
        defendant: defendant_key,
        update_count: 15,
        update_record: vec![0xCA, 0xFE],
        signature: vec![0xBA, 0xBE],
    };

    let serialized = ron::to_string(&dispute).expect("should serialize");
    let deserialized: DisputeChannelState = ron::from_str(&serialized).expect("should deserialize");

    assert_eq!(deserialized.channel_id, channel_id);
    assert_eq!(deserialized.update_count, 15);
}

#[test]
fn test_sign_and_verify() {
    let channel_id = test_channel_id();
    let claimant = TestClaimant::new(ChannelRole::Customer, channel_id.clone(), 5);
    let defendant = TestDefendant::new(ChannelRole::Merchant, channel_id, 5);

    let message = b"test message";

    // Claimant signs
    let signature = claimant.sign_for_kes(message).expect("should sign");
    assert!(!signature.is_empty());

    // Defendant verifies (mock always succeeds)
    defendant.verify_peer_signature(message, &signature).expect("should verify");
}
