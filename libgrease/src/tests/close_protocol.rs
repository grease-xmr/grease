//! Cooperative close flow tests.
//!
//! The close protocol in `grease_protocol::close_channel` is a set of traits, so these tests drive it through a
//! minimal in-memory party that stands in for the closing state machine. The stand-in models exactly the two things
//! the v2 spec (`docs/src/16_cooperative_close.typ` §coopClose) requires of a verifier: the requested `update_count`
//! must equal that of the latest cross-signed [`UpdateRecord`], and the offer's offset must *complete* the peer's
//! adapted closing signature — here, ω whose adaptor point `Q = ω·G` is the one we hold for the peer.
//!
//! Update counts in these tests deliberately skip values (17 → 41): counts are monotonic but not incremented by one.

use crate::Ed25519;
use ciphersuite::WrappedGroup;
use rand_core::OsRng;
use std::str::FromStr;
use std::sync::Arc;

use crate::channel_id::ChannelId;
use crate::cryptography::encryption_context::{with_encryption_context, AesGcmEncryption, EncryptionContext};
use crate::cryptography::keys::Curve25519Secret;
use crate::grease_protocol::close_channel::{
    ChannelCloseSuccess, CloseFailureReason, CloseProtocolCommon, CloseProtocolError, CloseProtocolInitiator,
    CloseProtocolResponder, RequestChannelClose, RequestCloseFailed,
};
use crate::grease_protocol::update_record::{CloseHash, HalfSignedUpdateRecord, UpdateRecord, CLOSE_HASH_LEN};
use crate::monero::data_objects::TransactionId;
use crate::payment_channel::{ChannelRole, HasRole};
use crate::{XmrPoint, XmrScalar};

const CHANNEL: &str = "XGC4a7024e7fd6f5c6a2d0131d12fd91ecd17f5da61c2970d603a05053b41a383";
const OTHER_CHANNEL: &str = "XGC4a7024e7fd6f5c6a2d0131d12fd91ecd17f5da61c2970d603a05053b41a384";

//--------------------------------------------------------------------------------------------------------------------
//                                          The stand-in closing party
//--------------------------------------------------------------------------------------------------------------------

struct CloseParty {
    role: ChannelRole,
    channel_id: ChannelId,
    /// The latest cross-signed record — the single source of truth for which state is being closed.
    record: UpdateRecord,
    /// Our own latest adaptor offset ω.
    offset: Curve25519Secret,
    /// The adaptor point `Q = ω_peer·G` taken from the peer's adapted closing signature.
    peer_adaptor_point: XmrPoint,
    /// Whether this party broadcasts the completed transaction itself, or leaves it to the initiator.
    broadcasts: bool,
    open: bool,
    received_request: Option<RequestChannelClose>,
    final_tx: Option<TransactionId>,
}

impl CloseParty {
    fn txid(&self) -> TransactionId {
        TransactionId::new(format!("{}-{}", self.record.update_count(), self.role))
    }

    /// The whole responder side in one call, mapping any local error onto the wire failure reason.
    fn respond(
        &mut self,
        request: RequestChannelClose,
    ) -> Result<ChannelCloseSuccess, RequestCloseFailed> {
        let offset = request.offset.clone();
        let result = self.receive_close_request(request).and_then(|()| self.sign_and_broadcast(&offset));
        match result {
            Ok(txid) => Ok(self.create_success_response(txid)),
            Err(e) => Err(self.create_failure_response(e.to_failure_reason())),
        }
    }
}

impl HasRole for CloseParty {
    fn role(&self) -> ChannelRole {
        self.role
    }
}

impl CloseProtocolCommon for CloseParty {
    fn channel_id(&self) -> ChannelId {
        self.channel_id.clone()
    }

    fn update_count(&self) -> u64 {
        self.record.update_count()
    }

    fn current_offset(&self) -> Curve25519Secret {
        self.offset.clone()
    }

    fn verify_offset(&self, offset: &Curve25519Secret, update_count: u64) -> Result<(), CloseProtocolError> {
        if !self.open {
            return Err(CloseProtocolError::InvalidChannelState("channel is no longer open".into()));
        }
        let expected = self.record.update_count();
        if update_count != expected {
            return Err(CloseProtocolError::UpdateCountMismatch { expected, actual: update_count });
        }
        // Stands in for "complete the closing-tx signature and see whether it verifies".
        if Ed25519::generator() * *offset.as_scalar() != self.peer_adaptor_point {
            return Err(CloseProtocolError::OffsetVerificationFailed(
                "offset does not complete the adapted closing signature".into(),
            ));
        }
        Ok(())
    }
}

impl CloseProtocolInitiator for CloseParty {
    fn create_close_request(&self) -> Result<RequestChannelClose, CloseProtocolError> {
        if !self.open {
            return Err(CloseProtocolError::InvalidChannelState("channel is no longer open".into()));
        }
        Ok(RequestChannelClose {
            channel_id: self.channel_id.clone(),
            offset: self.offset.clone(),
            update_count: self.record.update_count(),
        })
    }

    fn handle_close_success(&mut self, response: ChannelCloseSuccess) -> Result<(), CloseProtocolError> {
        if response.channel_id != self.channel_id {
            return Err(CloseProtocolError::ChannelNotFound(response.channel_id.to_string()));
        }
        self.verify_offset(&response.offset, self.record.update_count())?;
        // The responder broadcast, so we are done; otherwise the caller finishes with broadcast_closing_tx.
        if let Some(txid) = response.txid {
            self.final_tx = Some(txid);
        }
        Ok(())
    }

    fn handle_close_failed(&mut self, response: RequestCloseFailed) -> Result<(), CloseProtocolError> {
        Err(CloseProtocolError::CloseRejected(response.reason))
    }

    fn broadcast_closing_tx(&self, peer_offset: &Curve25519Secret) -> Result<TransactionId, CloseProtocolError> {
        self.verify_offset(peer_offset, self.record.update_count())?;
        Ok(self.txid())
    }
}

impl CloseProtocolResponder for CloseParty {
    fn receive_close_request(&mut self, request: RequestChannelClose) -> Result<(), CloseProtocolError> {
        if request.channel_id != self.channel_id {
            return Err(CloseProtocolError::ChannelNotFound(request.channel_id.to_string()));
        }
        if self.received_request.is_some() {
            return Err(CloseProtocolError::CloseRequestAlreadyReceived);
        }
        self.verify_offset(&request.offset, request.update_count)?;
        self.received_request = Some(request);
        Ok(())
    }

    fn sign_and_broadcast(&mut self, initiator_offset: &Curve25519Secret) -> Result<Option<TransactionId>, CloseProtocolError> {
        if self.received_request.is_none() {
            return Err(CloseProtocolError::NoCloseRequestReceived);
        }
        self.verify_offset(initiator_offset, self.record.update_count())?;
        self.open = false;
        if !self.broadcasts {
            return Ok(None);
        }
        let txid = self.txid();
        self.final_tx = Some(txid.clone());
        Ok(Some(txid))
    }

    fn create_success_response(&self, txid: Option<TransactionId>) -> ChannelCloseSuccess {
        ChannelCloseSuccess { channel_id: self.channel_id.clone(), offset: self.offset.clone(), txid }
    }

    fn create_failure_response(&self, reason: CloseFailureReason) -> RequestCloseFailed {
        RequestCloseFailed { channel_id: self.channel_id.clone(), reason }
    }
}

//--------------------------------------------------------------------------------------------------------------------
//                                                   Fixtures
//--------------------------------------------------------------------------------------------------------------------

fn channel_id() -> ChannelId {
    ChannelId::from_str(CHANNEL).unwrap()
}

fn cross_signed_record(update_count: u64) -> UpdateRecord {
    let customer_secret = XmrScalar::random(&mut OsRng);
    let merchant_secret = XmrScalar::random(&mut OsRng);
    let close_hash = CloseHash::new([0x5a; CLOSE_HASH_LEN]);
    let a = HalfSignedUpdateRecord::sign(
        channel_id(),
        update_count,
        close_hash,
        ChannelRole::Customer,
        &customer_secret,
        &mut OsRng,
    );
    let b = HalfSignedUpdateRecord::sign(
        channel_id(),
        update_count,
        close_hash,
        ChannelRole::Merchant,
        &merchant_secret,
        &mut OsRng,
    );
    let record = UpdateRecord::from_halves(&a, &b).unwrap();
    record
        .verify(&(Ed25519::generator() * customer_secret), &(Ed25519::generator() * merchant_secret))
        .expect("the fixture record is genuinely cross-signed");
    record
}

/// A customer/merchant pair sharing one cross-signed record, each holding the other's adaptor point.
fn open_channel(update_count: u64, responder_broadcasts: bool) -> (CloseParty, CloseParty) {
    let record = cross_signed_record(update_count);
    let customer_offset = Curve25519Secret::random(&mut OsRng);
    let merchant_offset = Curve25519Secret::random(&mut OsRng);
    let customer = CloseParty {
        role: ChannelRole::Customer,
        channel_id: channel_id(),
        record: record.clone(),
        offset: customer_offset.clone(),
        peer_adaptor_point: Ed25519::generator() * *merchant_offset.as_scalar(),
        broadcasts: false,
        open: true,
        received_request: None,
        final_tx: None,
    };
    let merchant = CloseParty {
        role: ChannelRole::Merchant,
        channel_id: channel_id(),
        record,
        offset: merchant_offset,
        peer_adaptor_point: Ed25519::generator() * *customer_offset.as_scalar(),
        broadcasts: responder_broadcasts,
        open: true,
        received_request: None,
        final_tx: None,
    };
    (customer, merchant)
}

fn encryption_context() -> Arc<dyn EncryptionContext> {
    Arc::new(AesGcmEncryption::random())
}

//--------------------------------------------------------------------------------------------------------------------
//                                                 Happy paths
//--------------------------------------------------------------------------------------------------------------------

#[test]
fn close_round_trip_responder_broadcasts() {
    let (mut customer, mut merchant) = open_channel(41, true);
    let request = customer.create_close_request().unwrap();
    assert_eq!(request.update_count, 41);
    assert_eq!(request.channel_id, channel_id());

    let success = merchant.respond(request).expect("merchant should accept the close");
    let txid = success.txid.clone().expect("merchant broadcast, so it reports a txid");
    customer.handle_close_success(success).unwrap();

    assert_eq!(customer.final_tx, Some(txid.clone()));
    assert_eq!(merchant.final_tx, Some(txid));
    assert!(!merchant.open, "the responder marks the channel closed once it has broadcast");
}

#[test]
fn close_round_trip_initiator_broadcasts_when_no_txid() {
    let (mut customer, mut merchant) = open_channel(41, false);
    let request = customer.create_close_request().unwrap();
    let success = merchant.respond(request).expect("merchant should accept the close");
    assert!(success.txid.is_none(), "this merchant signs but leaves the broadcast to the customer");

    let peer_offset = success.offset.clone();
    customer.handle_close_success(success).unwrap();
    assert!(customer.final_tx.is_none(), "nothing is broadcast yet");

    // With the merchant's offset in hand the customer reconstructs and broadcasts the closing transaction itself.
    let txid = customer.broadcast_closing_tx(&peer_offset).unwrap();
    customer.final_tx = Some(txid.clone());
    assert_eq!(customer.final_tx, Some(txid));
}

#[test]
fn either_party_may_initiate() {
    // The spec illustrates the flow with the customer initiating, but it is symmetric.
    let (mut customer, mut merchant) = open_channel(17, false);
    merchant.broadcasts = true;
    customer.broadcasts = true;
    let request = merchant.create_close_request().unwrap();
    let success = customer.respond(request).expect("customer should accept the close");
    assert!(success.txid.is_some());
    merchant.handle_close_success(success).unwrap();
    assert!(merchant.final_tx.is_some());
}

#[test]
fn update_counts_need_not_step_by_one() {
    // A channel whose latest record jumped 17 → 41 closes exactly as one that counted up.
    let (customer, mut merchant) = open_channel(41, true);
    let request = customer.create_close_request().unwrap();
    assert_eq!(request.update_count, 41);
    merchant.respond(request).expect("count 41 matches the latest record");

    // ...while the immediately preceding count is just as invalid as any other stale one.
    let (customer, mut merchant) = open_channel(41, true);
    let mut request = customer.create_close_request().unwrap();
    request.update_count = 40;
    let failure = merchant.respond(request).expect_err("a stale count is rejected");
    assert_eq!(failure.reason, CloseFailureReason::UpdateCountMismatch { expected: 41, received: 40 });
}

//--------------------------------------------------------------------------------------------------------------------
//                                            One per failure reason
//--------------------------------------------------------------------------------------------------------------------

#[test]
fn failure_update_count_mismatch() {
    let (customer, mut merchant) = open_channel(41, true);
    let mut request = customer.create_close_request().unwrap();
    request.update_count = 17;
    let failure = merchant.respond(request).expect_err("a stale update count must be rejected");
    assert_eq!(failure.channel_id, channel_id());
    assert_eq!(failure.reason, CloseFailureReason::UpdateCountMismatch { expected: 41, received: 17 });
    assert!(merchant.open, "the channel stays open after a failed close");
}

#[test]
fn failure_invalid_offset() {
    let (customer, mut merchant) = open_channel(41, true);
    let mut request = customer.create_close_request().unwrap();
    // An offset that does not complete the adapted closing signature.
    request.offset = Curve25519Secret::random(&mut OsRng);
    let failure = merchant.respond(request).expect_err("an offset that does not complete the signature is rejected");
    assert!(matches!(failure.reason, CloseFailureReason::InvalidOffset(_)));
    assert!(merchant.open);
}

#[test]
fn failure_invalid_channel_state() {
    let (customer, mut merchant) = open_channel(41, true);
    let request = customer.create_close_request().unwrap();
    merchant.open = false;
    let failure = merchant.respond(request).expect_err("a closed channel cannot be closed again");
    assert!(matches!(failure.reason, CloseFailureReason::InvalidChannelState(_)));
    // And the initiator side refuses to even build a request.
    let mut customer = customer;
    customer.open = false;
    assert!(matches!(customer.create_close_request(), Err(CloseProtocolError::InvalidChannelState(_))));
}

#[test]
fn failure_unknown_channel_maps_to_invalid_state() {
    let (customer, mut merchant) = open_channel(41, true);
    let mut request = customer.create_close_request().unwrap();
    request.channel_id = ChannelId::from_str(OTHER_CHANNEL).unwrap();
    let failure = merchant.respond(request).expect_err("a request for another channel is rejected");
    assert!(matches!(failure.reason, CloseFailureReason::InvalidChannelState(_)));
}

#[test]
fn failure_protocol_error() {
    let (customer, mut merchant) = open_channel(41, true);
    // Signing without having received a request is a protocol error, not an offset or state problem.
    let err = merchant.sign_and_broadcast(&customer.offset).expect_err("no request has been received");
    assert!(matches!(err, CloseProtocolError::NoCloseRequestReceived));
    assert_eq!(err.to_failure_reason(), CloseFailureReason::ProtocolError(err.to_string()));

    // A second request for an already-closing channel is likewise a protocol error.
    let request = customer.create_close_request().unwrap();
    merchant.receive_close_request(request.clone()).unwrap();
    let err = merchant.receive_close_request(request).expect_err("a duplicate request is rejected");
    assert!(matches!(err, CloseProtocolError::CloseRequestAlreadyReceived));
    assert!(matches!(err.to_failure_reason(), CloseFailureReason::ProtocolError(_)));
}

#[test]
fn failure_peer_unresponsive() {
    // A network failure during the exchange is reported against the peer, and reaches the initiator as a rejection.
    let err = CloseProtocolError::NetworkError("no response within the timeout".into());
    assert_eq!(err.to_failure_reason(), CloseFailureReason::PeerUnresponsive);

    let (mut customer, merchant) = open_channel(41, true);
    let failure = merchant.create_failure_response(err.to_failure_reason());
    let rejected = customer.handle_close_failed(failure).expect_err("a failure response aborts the close");
    assert!(matches!(rejected, CloseProtocolError::CloseRejected(CloseFailureReason::PeerUnresponsive)));
    assert!(customer.open, "the channel remains open after a rejected close");
    assert!(customer.final_tx.is_none());
}

#[test]
fn initiator_rejects_success_for_another_channel() {
    let (mut customer, merchant) = open_channel(41, true);
    let mut success = merchant.create_success_response(Some(TransactionId::new("deadbeef")));
    success.channel_id = ChannelId::from_str(OTHER_CHANNEL).unwrap();
    assert!(matches!(customer.handle_close_success(success), Err(CloseProtocolError::ChannelNotFound(_))));
    assert!(customer.final_tx.is_none());
}

#[test]
fn initiator_rejects_success_with_a_bogus_offset() {
    let (mut customer, merchant) = open_channel(41, true);
    let mut success = merchant.create_success_response(Some(TransactionId::new("deadbeef")));
    success.offset = Curve25519Secret::random(&mut OsRng);
    assert!(matches!(customer.handle_close_success(success), Err(CloseProtocolError::OffsetVerificationFailed(_))));
    assert!(customer.final_tx.is_none(), "a txid from a response we could not verify is not recorded");
}

#[test]
fn failure_reasons_render() {
    let reasons = [
        CloseFailureReason::UpdateCountMismatch { expected: 41, received: 17 },
        CloseFailureReason::InvalidChannelState("closed".into()),
        CloseFailureReason::InvalidOffset("does not complete the signature".into()),
        CloseFailureReason::PeerUnresponsive,
        CloseFailureReason::ProtocolError("boom".into()),
    ];
    assert!(reasons.iter().all(|r| !r.to_string().is_empty()));
}

//--------------------------------------------------------------------------------------------------------------------
//                                            Wire message round-trips
//--------------------------------------------------------------------------------------------------------------------

#[test]
fn request_channel_close_serde_round_trip() {
    let (customer, _) = open_channel(41, true);
    let request = customer.create_close_request().unwrap();
    let ctx = encryption_context();
    let json = with_encryption_context(ctx.clone(), || serde_json::to_string(&request).unwrap());
    let restored: RequestChannelClose =
        with_encryption_context(ctx, || serde_json::from_str(&json).unwrap());
    assert_eq!(restored.channel_id, request.channel_id);
    assert_eq!(restored.update_count, 41);
    assert_eq!(restored.offset, request.offset);
}

#[test]
fn channel_close_success_serde_round_trip() {
    let (_, merchant) = open_channel(41, true);
    let ctx = encryption_context();
    // Both shapes travel the wire: with a txid, and without one.
    let with_txid = merchant.create_success_response(Some(TransactionId::new("f00dcafe")));
    let without_txid = merchant.create_success_response(None);
    let round_trip = |msg: &ChannelCloseSuccess| -> ChannelCloseSuccess {
        let json = with_encryption_context(ctx.clone(), || serde_json::to_string(msg).unwrap());
        with_encryption_context(ctx.clone(), || serde_json::from_str(&json).unwrap())
    };
    let restored = round_trip(&with_txid);
    assert_eq!(restored.channel_id, with_txid.channel_id);
    assert_eq!(restored.offset, with_txid.offset);
    assert_eq!(restored.txid.map(|t| t.id), Some("f00dcafe".to_string()));

    let restored = round_trip(&without_txid);
    assert!(restored.txid.is_none());
    assert_eq!(restored.offset, without_txid.offset);
}

#[test]
fn request_close_failed_serde_round_trip() {
    let (_, merchant) = open_channel(41, true);
    let reasons = [
        CloseFailureReason::UpdateCountMismatch { expected: 41, received: 17 },
        CloseFailureReason::InvalidChannelState("channel is no longer open".into()),
        CloseFailureReason::InvalidOffset("offset does not complete the adapted closing signature".into()),
        CloseFailureReason::PeerUnresponsive,
        CloseFailureReason::ProtocolError("boom".into()),
    ];
    reasons.into_iter().for_each(|reason| {
        let msg = merchant.create_failure_response(reason.clone());
        let json = serde_json::to_string(&msg).unwrap();
        let restored: RequestCloseFailed = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.channel_id, msg.channel_id);
        assert_eq!(restored.reason, reason);
    });
}
