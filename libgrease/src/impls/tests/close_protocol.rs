//! Tests for the CloseProtocol traits (cooperative close).
//!
//! These tests verify the cooperative channel close flow between initiator and responder.

use crate::channel_id::ChannelId;
use crate::cryptography::ChannelWitness;
use crate::grease_protocol::close_channel::{
    ChannelCloseSuccess, CloseFailureReason, CloseProtocolCommon, CloseProtocolError, CloseProtocolInitiator,
    CloseProtocolResponder, RequestChannelClose, RequestCloseFailed,
};
use crate::monero::data_objects::TransactionId;
use crate::payment_channel::{ChannelRole, HasRole};
use crate::XmrScalar;
use grease_babyjubjub::BabyJubJub;
use std::str::FromStr;

/// Test implementation of CloseProtocolInitiator
struct TestCloseInitiator {
    role: ChannelRole,
    channel_id: ChannelId,
    update_count: u64,
    current_offset: ChannelWitness<BabyJubJub>,
    peer_offset: Option<ChannelWitness<BabyJubJub>>,
    close_failed: Option<CloseFailureReason>,
}

impl TestCloseInitiator {
    fn new(role: ChannelRole, channel_id: ChannelId, update_count: u64) -> Self {
        Self {
            role,
            channel_id,
            update_count,
            current_offset: ChannelWitness::<BabyJubJub>::try_from(XmrScalar::default())
                .expect("default scalar should be valid"),
            peer_offset: None,
            close_failed: None,
        }
    }
}

impl HasRole for TestCloseInitiator {
    fn role(&self) -> ChannelRole {
        self.role
    }
}

impl CloseProtocolCommon<BabyJubJub> for TestCloseInitiator {
    fn channel_id(&self) -> ChannelId {
        self.channel_id.clone()
    }

    fn update_count(&self) -> u64 {
        self.update_count
    }

    fn current_offset(&self) -> ChannelWitness<BabyJubJub> {
        self.current_offset.clone()
    }

    fn verify_offset(
        &self,
        _offset: &ChannelWitness<BabyJubJub>,
        _update_count: u64,
    ) -> Result<(), CloseProtocolError> {
        // Mock verification - always succeeds
        Ok(())
    }
}

impl CloseProtocolInitiator<BabyJubJub> for TestCloseInitiator {
    fn create_close_request(&self) -> Result<RequestChannelClose<BabyJubJub>, CloseProtocolError> {
        Ok(RequestChannelClose {
            channel_id: self.channel_id.clone(),
            offset: self.current_offset.clone(),
            update_count: self.update_count,
        })
    }

    fn handle_close_success(&mut self, response: ChannelCloseSuccess<BabyJubJub>) -> Result<(), CloseProtocolError> {
        if response.channel_id != self.channel_id {
            return Err(CloseProtocolError::InvalidChannelState("channel ID mismatch".into()));
        }
        self.peer_offset = Some(response.offset);
        Ok(())
    }

    fn handle_close_failed(&mut self, response: RequestCloseFailed) -> Result<(), CloseProtocolError> {
        if response.channel_id != self.channel_id {
            return Err(CloseProtocolError::InvalidChannelState("channel ID mismatch".into()));
        }
        self.close_failed = Some(response.reason.clone());
        Err(CloseProtocolError::CloseRejected(response.reason))
    }

    fn broadcast_closing_tx(
        &self,
        _peer_offset: &ChannelWitness<BabyJubJub>,
    ) -> Result<TransactionId, CloseProtocolError> {
        if self.peer_offset.is_none() {
            return Err(CloseProtocolError::MissingInformation("peer offset not received".into()));
        }
        Ok(TransactionId { id: "mock_txid_12345".to_string() })
    }
}

/// Test implementation of CloseProtocolResponder
struct TestCloseResponder {
    role: ChannelRole,
    channel_id: ChannelId,
    update_count: u64,
    current_offset: ChannelWitness<BabyJubJub>,
    received_request: Option<RequestChannelClose<BabyJubJub>>,
    should_broadcast: bool,
}

impl TestCloseResponder {
    fn new(role: ChannelRole, channel_id: ChannelId, update_count: u64, should_broadcast: bool) -> Self {
        Self {
            role,
            channel_id,
            update_count,
            current_offset: ChannelWitness::<BabyJubJub>::try_from(XmrScalar::default())
                .expect("default scalar should be valid"),
            received_request: None,
            should_broadcast,
        }
    }
}

impl HasRole for TestCloseResponder {
    fn role(&self) -> ChannelRole {
        self.role
    }
}

impl CloseProtocolCommon<BabyJubJub> for TestCloseResponder {
    fn channel_id(&self) -> ChannelId {
        self.channel_id.clone()
    }

    fn update_count(&self) -> u64 {
        self.update_count
    }

    fn current_offset(&self) -> ChannelWitness<BabyJubJub> {
        self.current_offset.clone()
    }

    fn verify_offset(
        &self,
        _offset: &ChannelWitness<BabyJubJub>,
        _update_count: u64,
    ) -> Result<(), CloseProtocolError> {
        Ok(())
    }
}

impl CloseProtocolResponder<BabyJubJub> for TestCloseResponder {
    fn receive_close_request(&mut self, request: RequestChannelClose<BabyJubJub>) -> Result<(), CloseProtocolError> {
        if self.received_request.is_some() {
            return Err(CloseProtocolError::CloseRequestAlreadyReceived);
        }

        if request.channel_id != self.channel_id {
            return Err(CloseProtocolError::InvalidChannelState("channel ID mismatch".into()));
        }

        if request.update_count != self.update_count {
            return Err(CloseProtocolError::UpdateCountMismatch {
                expected: self.update_count,
                actual: request.update_count,
            });
        }

        self.received_request = Some(request);
        Ok(())
    }

    fn sign_and_broadcast(
        &mut self,
        _initiator_offset: &ChannelWitness<BabyJubJub>,
    ) -> Result<Option<TransactionId>, CloseProtocolError> {
        if self.received_request.is_none() {
            return Err(CloseProtocolError::NoCloseRequestReceived);
        }

        if self.should_broadcast {
            Ok(Some(TransactionId { id: "responder_broadcast_txid".to_string() }))
        } else {
            Ok(None)
        }
    }

    fn create_success_response(&self, txid: Option<TransactionId>) -> ChannelCloseSuccess<BabyJubJub> {
        ChannelCloseSuccess { channel_id: self.channel_id.clone(), offset: self.current_offset.clone(), txid }
    }

    fn create_failure_response(&self, reason: CloseFailureReason) -> RequestCloseFailed {
        RequestCloseFailed { channel_id: self.channel_id.clone(), reason }
    }
}

fn test_channel_id() -> ChannelId {
    ChannelId::from_str("XGC4a7024e7fd6f5c6a2d0131d12fd91ecd17f5da61c2970d603a05053b41a383").unwrap()
}

fn test_witness() -> ChannelWitness<BabyJubJub> {
    ChannelWitness::<BabyJubJub>::try_from(XmrScalar::default()).expect("default scalar should be valid")
}

#[test]
fn test_create_close_request() {
    let channel_id = test_channel_id();
    let initiator = TestCloseInitiator::new(ChannelRole::Customer, channel_id.clone(), 5);

    let request = initiator.create_close_request().expect("should create request");

    assert_eq!(request.channel_id, channel_id);
    assert_eq!(request.update_count, 5);
}

#[test]
fn test_cooperative_close_success_initiator_broadcasts() {
    let channel_id = test_channel_id();

    let mut initiator = TestCloseInitiator::new(ChannelRole::Customer, channel_id.clone(), 5);
    let mut responder = TestCloseResponder::new(ChannelRole::Merchant, channel_id.clone(), 5, false);

    // 1. Initiator creates close request
    let request = initiator.create_close_request().expect("should create request");

    // 2. Responder receives and validates request
    responder.receive_close_request(request.clone()).expect("should receive request");

    // 3. Responder signs (but doesn't broadcast)
    let txid = responder.sign_and_broadcast(&request.offset).expect("should sign");
    assert!(txid.is_none()); // Responder didn't broadcast

    // 4. Responder creates success response
    let response = responder.create_success_response(txid);

    // 5. Initiator handles success
    initiator.handle_close_success(response).expect("should handle success");
    assert!(initiator.peer_offset.is_some());

    // 6. Initiator broadcasts
    let peer_offset = initiator.peer_offset.as_ref().unwrap();
    let final_txid = initiator.broadcast_closing_tx(peer_offset).expect("should broadcast");
    assert!(!final_txid.id.is_empty());
}

#[test]
fn test_cooperative_close_success_responder_broadcasts() {
    let channel_id = test_channel_id();

    let mut initiator = TestCloseInitiator::new(ChannelRole::Customer, channel_id.clone(), 5);
    let mut responder = TestCloseResponder::new(ChannelRole::Merchant, channel_id.clone(), 5, true);

    // 1. Initiator creates close request
    let request = initiator.create_close_request().expect("should create request");

    // 2. Responder receives request
    responder.receive_close_request(request.clone()).expect("should receive request");

    // 3. Responder signs AND broadcasts
    let txid = responder.sign_and_broadcast(&request.offset).expect("should sign and broadcast");
    assert!(txid.is_some());

    // 4. Responder creates success response with txid
    let response = responder.create_success_response(txid);
    assert!(response.txid.is_some());

    // 5. Initiator handles success (no need to broadcast)
    initiator.handle_close_success(response).expect("should handle success");
}

#[test]
fn test_close_update_count_mismatch() {
    let channel_id = test_channel_id();

    let initiator = TestCloseInitiator::new(ChannelRole::Customer, channel_id.clone(), 5);
    let mut responder = TestCloseResponder::new(ChannelRole::Merchant, channel_id.clone(), 10, false); // Different count!

    let request = initiator.create_close_request().expect("should create request");

    let result = responder.receive_close_request(request);
    assert!(matches!(
        result,
        Err(CloseProtocolError::UpdateCountMismatch { expected: 10, actual: 5 })
    ));
}

#[test]
fn test_close_failure_response() {
    let channel_id = test_channel_id();

    let mut initiator = TestCloseInitiator::new(ChannelRole::Customer, channel_id.clone(), 5);
    let responder = TestCloseResponder::new(ChannelRole::Merchant, channel_id.clone(), 5, false);

    // Responder creates failure response
    let reason = CloseFailureReason::InvalidChannelState("channel is disputed".into());
    let failure = responder.create_failure_response(reason);

    // Initiator handles failure
    let result = initiator.handle_close_failed(failure);
    assert!(matches!(result, Err(CloseProtocolError::CloseRejected(_))));
    assert!(initiator.close_failed.is_some());
}

#[test]
fn test_duplicate_close_request_rejected() {
    let channel_id = test_channel_id();

    let initiator = TestCloseInitiator::new(ChannelRole::Customer, channel_id.clone(), 5);
    let mut responder = TestCloseResponder::new(ChannelRole::Merchant, channel_id.clone(), 5, false);

    let request = initiator.create_close_request().expect("should create request");

    // First request succeeds
    responder.receive_close_request(request.clone()).expect("first should succeed");

    // Second request fails
    let result = responder.receive_close_request(request);
    assert!(matches!(result, Err(CloseProtocolError::CloseRequestAlreadyReceived)));
}

#[test]
fn test_sign_without_request_fails() {
    let channel_id = test_channel_id();
    let mut responder = TestCloseResponder::new(ChannelRole::Merchant, channel_id, 5, false);

    let result = responder.sign_and_broadcast(&test_witness());
    assert!(matches!(result, Err(CloseProtocolError::NoCloseRequestReceived)));
}

#[test]
fn test_broadcast_without_peer_offset_fails() {
    let channel_id = test_channel_id();
    let initiator = TestCloseInitiator::new(ChannelRole::Customer, channel_id, 5);

    let result = initiator.broadcast_closing_tx(&test_witness());
    assert!(matches!(result, Err(CloseProtocolError::MissingInformation(_))));
}

#[test]
fn test_close_failure_reason_display() {
    let reasons = vec![
        CloseFailureReason::UpdateCountMismatch { expected: 5, received: 3 },
        CloseFailureReason::InvalidChannelState("test state".into()),
        CloseFailureReason::InvalidOffset("bad offset".into()),
        CloseFailureReason::PeerUnresponsive,
        CloseFailureReason::ProtocolError("generic error".into()),
    ];

    for reason in reasons {
        let display = format!("{reason}");
        assert!(!display.is_empty());
    }
}

#[test]
fn test_close_request_serialization() {
    let channel_id = test_channel_id();
    let request =
        RequestChannelClose::<BabyJubJub> { channel_id: channel_id.clone(), offset: test_witness(), update_count: 42 };

    // Test serialization roundtrip
    let serialized = ron::to_string(&request).expect("should serialize");
    let deserialized: RequestChannelClose<BabyJubJub> = ron::from_str(&serialized).expect("should deserialize");

    assert_eq!(deserialized.channel_id, channel_id);
    assert_eq!(deserialized.update_count, 42);
}

#[test]
fn test_close_success_serialization() {
    let channel_id = test_channel_id();
    let success = ChannelCloseSuccess::<BabyJubJub> {
        channel_id: channel_id.clone(),
        offset: test_witness(),
        txid: Some(TransactionId { id: "test_txid".to_string() }),
    };

    let serialized = ron::to_string(&success).expect("should serialize");
    let deserialized: ChannelCloseSuccess<BabyJubJub> = ron::from_str(&serialized).expect("should deserialize");

    assert_eq!(deserialized.channel_id, channel_id);
    assert!(deserialized.txid.is_some());
}

#[test]
fn test_close_failed_serialization() {
    let channel_id = test_channel_id();
    let failed = RequestCloseFailed {
        channel_id: channel_id.clone(),
        reason: CloseFailureReason::UpdateCountMismatch { expected: 10, received: 5 },
    };

    let serialized = ron::to_string(&failed).expect("should serialize");
    let deserialized: RequestCloseFailed = ron::from_str(&serialized).expect("should deserialize");

    assert_eq!(deserialized.channel_id, channel_id);
    assert!(matches!(deserialized.reason, CloseFailureReason::UpdateCountMismatch { .. }));
}

#[test]
fn test_verify_offset_called() {
    let channel_id = test_channel_id();
    let initiator = TestCloseInitiator::new(ChannelRole::Customer, channel_id, 5);

    // Verify offset should succeed with mock
    let result = initiator.verify_offset(&test_witness(), 5);
    assert!(result.is_ok());
}
