//! Proposal protocol messages.
//!
//! The proposal phase handles channel negotiation between customer (initiator) and merchant (responder).
//!
//! # Flow
//! 1. Customer sends `ProposeChannel` with channel parameters
//! 2. Merchant validates and responds with `Accepted` or `Rejected`

use libgrease::channel_id::ChannelId;
use libgrease::state_machine::error::InvalidProposal;
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};

use crate::grease::NewChannelMessage;

/// Request messages for the proposal protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProposalRequest {
    /// Customer proposes a new channel to the merchant.
    ProposeChannel(NewChannelMessage),
}

impl ProposalRequest {
    /// Returns the channel ID for this request.
    pub fn channel_id(&self) -> ChannelId {
        match self {
            ProposalRequest::ProposeChannel(msg) => msg.channel_id(),
        }
    }
}

/// Response messages for the proposal protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProposalResponse {
    /// Merchant accepts the channel proposal.
    Accepted(ChannelAccepted),
    /// Merchant rejects the channel proposal.
    Rejected(ChannelRejected),
    /// Internal error occurred.
    Error(ProposalError),
}

impl Display for ProposalResponse {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ProposalResponse::Accepted(a) => write!(f, "Accepted(channel={})", a.channel_id),
            ProposalResponse::Rejected(r) => write!(f, "Rejected({})", r.reason),
            ProposalResponse::Error(e) => write!(f, "Error({})", e),
        }
    }
}

/// Successful channel acceptance response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelAccepted {
    /// The accepted channel ID.
    pub channel_id: ChannelId,
    /// The merchant's counter-proposal (may have adjusted parameters).
    pub proposal: NewChannelMessage,
}

impl ChannelAccepted {
    pub fn new(channel_id: ChannelId, proposal: NewChannelMessage) -> Self {
        Self { channel_id, proposal }
    }
}

/// Channel rejection response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelRejected {
    /// The rejected channel ID.
    pub channel_id: ChannelId,
    /// Reason for rejection.
    pub reason: RejectReason,
    /// Whether the customer can retry with modified parameters.
    pub can_retry: bool,
}

impl ChannelRejected {
    pub fn new(channel_id: ChannelId, reason: RejectReason, can_retry: bool) -> Self {
        Self { channel_id, reason, can_retry }
    }

    pub fn invalid_proposal(channel_id: ChannelId, invalid: InvalidProposal) -> Self {
        Self::new(channel_id, RejectReason::InvalidProposal(invalid), false)
    }

    pub fn peer_unavailable(channel_id: ChannelId) -> Self {
        Self::new(channel_id, RejectReason::PeerUnavailable, false)
    }

    pub fn at_capacity(channel_id: ChannelId) -> Self {
        Self::new(channel_id, RejectReason::AtCapacity, true)
    }
}

/// Reason for rejecting a channel proposal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RejectReason {
    /// The proposal contained invalid parameters.
    InvalidProposal(InvalidProposal),
    /// Merchant is unavailable to open channels.
    PeerUnavailable,
    /// Merchant is at maximum channel capacity.
    AtCapacity,
    /// Channel already exists and is not in New state.
    NotANewChannel,
    /// Internal error on the merchant side.
    Internal(String),
}

impl Display for RejectReason {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            RejectReason::InvalidProposal(err) => write!(f, "Invalid proposal: {err}"),
            RejectReason::PeerUnavailable => write!(f, "Peer unavailable"),
            RejectReason::AtCapacity => write!(f, "At capacity"),
            RejectReason::NotANewChannel => write!(f, "Channel already exists"),
            RejectReason::Internal(msg) => write!(f, "Internal: {msg}"),
        }
    }
}

/// Errors that can occur during proposal handling.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProposalError {
    /// Channel not found.
    ChannelNotFound(ChannelId),
    /// Internal processing error.
    Internal(String),
}

impl Display for ProposalError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ProposalError::ChannelNotFound(id) => write!(f, "Channel not found: {id}"),
            ProposalError::Internal(msg) => write!(f, "Internal error: {msg}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reject_reason_display() {
        let reason = RejectReason::AtCapacity;
        assert_eq!(reason.to_string(), "At capacity");

        let reason = RejectReason::Internal("test error".into());
        assert_eq!(reason.to_string(), "Internal: test error");
    }
}
