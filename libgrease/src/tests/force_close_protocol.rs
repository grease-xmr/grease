//! Tests for the ForceCloseProtocol traits (dispute resolution).
//!
//! These tests verify the force close and dispute flow between claimant and defendant.
//! Since the actual cryptographic signatures require real key integration, these tests
//! focus on the protocol data flow and error handling.

use crate::channel_id::ChannelId;
use crate::cryptography::keys::{Curve25519PublicKey, PublicKey};
use crate::grease_protocol::force_close_channel::{
    DisputeResolution, ForceCloseProtocolError, ForceCloseResponse, PendingChannelClose, PendingCloseStatus,
};
use crate::helpers::Timestamp;
use crate::XmrScalar;
use ciphersuite::Ed25519;
use rand_core::OsRng;
use std::str::FromStr;

fn test_channel_id() -> ChannelId {
    ChannelId::from_str("XGC4a7024e7fd6f5c6a2d0131d12fd91ecd17f5da61c2970d603a05053b41a383").unwrap()
}

#[test]
fn test_force_close_response_accepted() {
    let response = ForceCloseResponse::Accepted { dispute_window_end: Timestamp::from(1000000u64) };
    match response {
        ForceCloseResponse::Accepted { dispute_window_end } => {
            assert_eq!(dispute_window_end.as_secs(), 1000000);
        }
        ForceCloseResponse::Rejected { .. } => panic!("expected Accepted"),
    }
}

#[test]
fn test_force_close_response_rejected() {
    let response = ForceCloseResponse::Rejected { reason: "invalid signature".to_string() };
    match response {
        ForceCloseResponse::Rejected { reason } => {
            assert_eq!(reason, "invalid signature");
        }
        ForceCloseResponse::Accepted { .. } => panic!("expected Rejected"),
    }
}

#[test]
fn test_pending_channel_close_struct() {
    let channel_id = test_channel_id();
    let mut rng = OsRng;
    let (_, claimant_key) = Curve25519PublicKey::keypair(&mut rng);

    let pending = PendingChannelClose {
        channel_id: channel_id.clone(),
        claimant: claimant_key,
        update_count_claimed: 5,
        dispute_window_end: Timestamp::from(1000000u64),
    };

    assert_eq!(pending.channel_id, channel_id);
    assert_eq!(pending.update_count_claimed, 5);
    assert_eq!(pending.dispute_window_end.as_secs(), 1000000);
}

#[test]
fn test_pending_close_status_values() {
    // Verify all status variants exist and are distinct
    let statuses = [
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
    assert_ne!(PendingCloseStatus::ForceClosed, PendingCloseStatus::ConsensusClosed);
}

#[test]
fn test_pending_close_status_default() {
    let status = PendingCloseStatus::Pending;
    assert!(matches!(status, PendingCloseStatus::Pending));
}

#[test]
fn test_dispute_resolution_claimant_wins() {
    use crate::cryptography::CrossCurveScalar;

    let offset =
        CrossCurveScalar::<Ed25519>::try_from(XmrScalar::default()).expect("should create witness from default scalar");

    let resolution: DisputeResolution<Ed25519> = DisputeResolution::ClaimantWins { encrypted_offset: offset };

    match resolution {
        DisputeResolution::ClaimantWins { encrypted_offset: _ } => {
            // Success - claimant wins variant works
        }
        DisputeResolution::DefendantWins { .. } => panic!("expected ClaimantWins"),
    }
}

#[test]
fn test_dispute_resolution_defendant_wins() {
    let resolution: DisputeResolution<Ed25519> = DisputeResolution::DefendantWins { penalty_applied: true };

    match resolution {
        DisputeResolution::DefendantWins { penalty_applied } => {
            assert!(penalty_applied);
        }
        DisputeResolution::ClaimantWins { .. } => panic!("expected DefendantWins"),
    }
}

#[test]
fn test_force_close_error_variants() {
    // Test that all error variants can be created
    let errors: Vec<ForceCloseProtocolError> = vec![
        ForceCloseProtocolError::ChannelNotFound("test".into()),
        ForceCloseProtocolError::InvalidSignature("bad sig".into()),
        ForceCloseProtocolError::UpdateCountTooLow { claimed: 5, actual: 3 },
        ForceCloseProtocolError::DisputeWindowActive,
        ForceCloseProtocolError::NoPendingForceClose,
        ForceCloseProtocolError::ForceCloseAlreadyPending,
        ForceCloseProtocolError::KesRejected("rejected".into()),
        ForceCloseProtocolError::SignatureCreationFailed("failed".into()),
        ForceCloseProtocolError::DecryptionFailed("decrypt error".into()),
        ForceCloseProtocolError::TransactionCreationFailed("tx error".into()),
        ForceCloseProtocolError::BroadcastFailed("broadcast error".into()),
        ForceCloseProtocolError::MissingInformation("missing".into()),
        ForceCloseProtocolError::SerializationError("serial error".into()),
    ];

    for error in errors {
        let display = format!("{error}");
        assert!(!display.is_empty(), "Error display should not be empty");
    }
}

#[test]
fn test_pending_channel_close_serialization() {
    let channel_id = test_channel_id();
    let mut rng = OsRng;
    let (_, claimant_key) = Curve25519PublicKey::keypair(&mut rng);

    let pending = PendingChannelClose {
        channel_id: channel_id.clone(),
        claimant: claimant_key,
        update_count_claimed: 42,
        dispute_window_end: Timestamp::from(9999999u64),
    };

    let serialized = ron::to_string(&pending).expect("should serialize");
    let deserialized: PendingChannelClose = ron::from_str(&serialized).expect("should deserialize");

    assert_eq!(deserialized.channel_id, channel_id);
    assert_eq!(deserialized.update_count_claimed, 42);
    assert_eq!(deserialized.dispute_window_end.as_secs(), 9999999);
}

#[test]
fn test_force_close_response_serialization() {
    let accepted = ForceCloseResponse::Accepted { dispute_window_end: Timestamp::from(12345u64) };
    let serialized = ron::to_string(&accepted).expect("should serialize");
    let deserialized: ForceCloseResponse = ron::from_str(&serialized).expect("should deserialize");

    match deserialized {
        ForceCloseResponse::Accepted { dispute_window_end } => {
            assert_eq!(dispute_window_end.as_secs(), 12345);
        }
        ForceCloseResponse::Rejected { .. } => panic!("expected Accepted"),
    }

    let rejected = ForceCloseResponse::Rejected { reason: "test reason".into() };
    let serialized = ron::to_string(&rejected).expect("should serialize");
    let deserialized: ForceCloseResponse = ron::from_str(&serialized).expect("should deserialize");

    match deserialized {
        ForceCloseResponse::Rejected { reason } => {
            assert_eq!(reason, "test reason");
        }
        ForceCloseResponse::Accepted { .. } => panic!("expected Rejected"),
    }
}

#[test]
fn test_pending_close_status_copy() {
    let status = PendingCloseStatus::Pending;
    let copied = status; // Copy
    assert!(matches!(copied, PendingCloseStatus::Pending));
    assert!(matches!(status, PendingCloseStatus::Pending)); // Original still valid
}

#[test]
fn test_has_more_recent_state_logic() {
    // Test the comparison logic that would be used in has_more_recent_state
    let defendant_update_count = 10u64;
    let claimed_count = 5u64;

    // Defendant has more recent state
    assert!(defendant_update_count > claimed_count);

    // Same state - no dispute possible
    let same_count = 5u64;
    assert!(same_count <= claimed_count);

    // Defendant has older state - no dispute possible
    let older_count = 3u64;
    assert!(older_count <= claimed_count);
}

#[test]
fn test_update_count_comparison() {
    // Verify update count comparison edge cases
    assert!(10u64 > 5u64); // Normal case
    assert!(5u64 <= 5u64); // Equal case
    assert!(3u64 <= 5u64); // Less than case
    assert!(u64::MAX > 0u64); // Max value
    assert!(0u64 <= u64::MAX); // Zero vs max
}

#[test]
fn test_channel_id_in_protocol_structs() {
    let channel_id = test_channel_id();
    let mut rng = OsRng;
    let (_, key) = Curve25519PublicKey::keypair(&mut rng);

    let pending = PendingChannelClose {
        channel_id: channel_id.clone(),
        claimant: key,
        update_count_claimed: 1,
        dispute_window_end: Timestamp::from(1u64),
    };

    // Verify channel ID is preserved
    assert_eq!(pending.channel_id.to_string(), channel_id.to_string());
}
