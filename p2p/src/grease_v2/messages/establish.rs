//! Establish protocol messages.
//!
//! The establish phase handles wallet setup, KES initialization, and funding between
//! customer (initiator) and merchant (responder).
//!
//! # Flow
//! 1. Key exchange: Exchange multisig wallet keys
//! 2. Address confirmation: Verify both parties computed the same wallet address
//! 3. Split secrets: Exchange KES secrets (adapted signatures, DLEQ proofs)
//! 4. Proof0: Exchange initial witness proofs
//! 5. Funding: Watch for and confirm funding transaction

use libgrease::channel_id::ChannelId;
use libgrease::cryptography::zk_objects::PublicProof0;
use libgrease::monero::data_objects::{MultisigKeyInfo, MultisigSplitSecrets, MultisigSplitSecretsResponse};
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};

/// Request messages for the establish protocol.
///
/// Each variant represents a step in the channel establishment sequence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EstablishRequest {
    /// Exchange multisig wallet public keys.
    /// Customer sends their key and expects merchant's key in response.
    KeyExchange(KeyExchangePayload),

    /// Confirm that both parties computed the same multisig wallet address.
    ConfirmAddress(ConfirmAddressPayload),

    /// Exchange KES split secrets (adapted signatures, DLEQ proofs, encrypted secrets).
    SplitSecretExchange(SplitSecretPayload),

    /// Exchange initial witness proofs (proof0).
    ExchangeProof0(Proof0Payload),
}

impl EstablishRequest {
    /// Returns the channel ID for this request.
    pub fn channel_id(&self) -> &ChannelId {
        match self {
            EstablishRequest::KeyExchange(p) => &p.channel_id,
            EstablishRequest::ConfirmAddress(p) => &p.channel_id,
            EstablishRequest::SplitSecretExchange(p) => &p.channel_id,
            EstablishRequest::ExchangeProof0(p) => &p.channel_id,
        }
    }

    /// Creates a key exchange request.
    pub fn key_exchange(channel_id: ChannelId, key_info: MultisigKeyInfo) -> Self {
        EstablishRequest::KeyExchange(KeyExchangePayload { channel_id, key_info })
    }

    /// Creates an address confirmation request.
    pub fn confirm_address(channel_id: ChannelId, address: String) -> Self {
        EstablishRequest::ConfirmAddress(ConfirmAddressPayload { channel_id, address })
    }

    /// Creates a split secret exchange request.
    pub fn split_secrets(channel_id: ChannelId, secrets: MultisigSplitSecrets) -> Self {
        EstablishRequest::SplitSecretExchange(SplitSecretPayload { channel_id, secrets })
    }

    /// Creates a proof0 exchange request.
    pub fn proof0(channel_id: ChannelId, proof: PublicProof0) -> Self {
        EstablishRequest::ExchangeProof0(Proof0Payload { channel_id, proof })
    }
}

/// Response messages for the establish protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EstablishResponse {
    /// Response to key exchange with merchant's key info.
    KeyExchange(KeyExchangePayload),

    /// Response to address confirmation.
    AddressConfirmed(AddressConfirmedPayload),

    /// Response to split secret exchange with merchant's secrets.
    SplitSecrets(SplitSecretResponsePayload),

    /// Response to proof0 exchange with merchant's proof.
    Proof0(Proof0Payload),

    /// Error during establishment.
    Error(EstablishError),
}

impl Display for EstablishResponse {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            EstablishResponse::KeyExchange(p) => write!(f, "KeyExchange(channel={})", p.channel_id),
            EstablishResponse::AddressConfirmed(p) => {
                write!(f, "AddressConfirmed(channel={}, confirmed={})", p.channel_id, p.confirmed)
            }
            EstablishResponse::SplitSecrets(p) => write!(f, "SplitSecrets(channel={})", p.channel_id),
            EstablishResponse::Proof0(p) => write!(f, "Proof0(channel={})", p.channel_id),
            EstablishResponse::Error(e) => write!(f, "Error({e})"),
        }
    }
}

// ============================================================================
// Payload types
// ============================================================================

/// Payload for key exchange messages.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyExchangePayload {
    pub channel_id: ChannelId,
    pub key_info: MultisigKeyInfo,
}

/// Payload for address confirmation request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfirmAddressPayload {
    pub channel_id: ChannelId,
    pub address: String,
}

/// Payload for address confirmation response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressConfirmedPayload {
    pub channel_id: ChannelId,
    pub confirmed: bool,
}

impl AddressConfirmedPayload {
    pub fn confirmed(channel_id: ChannelId) -> Self {
        Self { channel_id, confirmed: true }
    }

    pub fn mismatch(channel_id: ChannelId) -> Self {
        Self { channel_id, confirmed: false }
    }
}

/// Payload for split secret exchange request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SplitSecretPayload {
    pub channel_id: ChannelId,
    pub secrets: MultisigSplitSecrets,
}

/// Payload for split secret exchange response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SplitSecretResponsePayload {
    pub channel_id: ChannelId,
    pub secrets: MultisigSplitSecretsResponse,
}

/// Payload for proof0 exchange.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proof0Payload {
    pub channel_id: ChannelId,
    pub proof: PublicProof0,
}

// ============================================================================
// Error types
// ============================================================================

/// Errors that can occur during channel establishment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EstablishError {
    /// Channel not found.
    ChannelNotFound(ChannelId),

    /// Channel is not in the expected state for this operation.
    InvalidState { channel_id: ChannelId, expected: String, actual: String },

    /// Address mismatch during confirmation.
    AddressMismatch { channel_id: ChannelId, expected: String, received: String },

    /// Key exchange failed.
    KeyExchangeFailed { channel_id: ChannelId, reason: String },

    /// Split secret verification failed.
    SplitSecretVerificationFailed { channel_id: ChannelId, reason: String },

    /// Proof0 verification failed.
    Proof0VerificationFailed { channel_id: ChannelId, reason: String },

    /// Internal error.
    Internal { channel_id: ChannelId, reason: String },
}

impl Display for EstablishError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            EstablishError::ChannelNotFound(id) => write!(f, "Channel not found: {id}"),
            EstablishError::InvalidState { channel_id, expected, actual } => {
                write!(f, "Channel {channel_id}: expected state {expected}, got {actual}")
            }
            EstablishError::AddressMismatch { channel_id, expected, received } => {
                write!(
                    f,
                    "Channel {channel_id}: address mismatch (expected {expected}, got {received})"
                )
            }
            EstablishError::KeyExchangeFailed { channel_id, reason } => {
                write!(f, "Channel {channel_id}: key exchange failed: {reason}")
            }
            EstablishError::SplitSecretVerificationFailed { channel_id, reason } => {
                write!(f, "Channel {channel_id}: split secret verification failed: {reason}")
            }
            EstablishError::Proof0VerificationFailed { channel_id, reason } => {
                write!(f, "Channel {channel_id}: proof0 verification failed: {reason}")
            }
            EstablishError::Internal { channel_id, reason } => {
                write!(f, "Channel {channel_id}: internal error: {reason}")
            }
        }
    }
}

impl EstablishError {
    pub fn channel_id(&self) -> &ChannelId {
        match self {
            EstablishError::ChannelNotFound(id) => id,
            EstablishError::InvalidState { channel_id, .. } => channel_id,
            EstablishError::AddressMismatch { channel_id, .. } => channel_id,
            EstablishError::KeyExchangeFailed { channel_id, .. } => channel_id,
            EstablishError::SplitSecretVerificationFailed { channel_id, .. } => channel_id,
            EstablishError::Proof0VerificationFailed { channel_id, .. } => channel_id,
            EstablishError::Internal { channel_id, .. } => channel_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn test_channel_id() -> ChannelId {
        ChannelId::from_str("XGC4a7024e7fd6f5c6a2d0131d12fd91ecd17f5da61c2970d603a05053b41a383").unwrap()
    }

    #[test]
    fn establish_error_display() {
        let err = EstablishError::AddressMismatch {
            channel_id: test_channel_id(),
            expected: "addr1".into(),
            received: "addr2".into(),
        };
        assert!(err.to_string().contains("address mismatch"));
    }
}
