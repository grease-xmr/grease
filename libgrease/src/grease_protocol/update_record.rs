//! The cross-signed state receipt exchanged on every channel update — and the only object the arbiter adjudicates on.
//!
//! On each update both parties sign the triple `(channel_id, update_count, close_hash)` over a canonical,
//! domain-separated serialization ([`update_record_message`]). The customer's signature is `signature_a`, the
//! merchant's `signature_b`. The arbiter's entire check is two Schnorr verifications plus well-formedness (see
//! `docs/src/40_arbiter.typ` §stateMachine), so the byte layout defined here *is* the protocol: any change to
//! [`update_record_message`] is a protocol version bump.
//!
//! The exchange is half-signed → countersigned: each party constructs and signs its own half
//! ([`HalfSignedUpdateRecord`]), sends it, and countersigns the peer's half after verifying it
//! ([`UpdateRecord::countersign`]).
//!
//! Supersession follows the whitepaper's monotonicity rule: a record supersedes another iff its `update_count` is
//! *strictly greater*. Update counts need only increase — gaps are deliberately legal (the privacy hardening in
//! §arbiterPrivacy relies on parties being able to skip counts).

use ciphersuite::Ed25519;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt::{Debug, Display};
use std::str::FromStr;
use thiserror::Error;

use crate::channel_id::{ChannelId, ChannelIdParseError};
use crate::cryptography::adapter_signature::SchnorrSignature;
use crate::payment_channel::ChannelRole;
use crate::{XmrPoint, XmrScalar};

/// Domain-separation tag for the update-record signing message. Versioned: a layout change gets a new tag.
pub const UPDATE_RECORD_DST: &[u8] = b"Grease UpdateRecord v1";

/// The length of a [`CloseHash`]: the closing-transaction message is a Blake2b-512 transcript challenge
/// (see [`crate::wallet::multisig_wallet::commitment_tx_message`]).
pub const CLOSE_HASH_LEN: usize = 64;

//--------------------------------------------------------------------------------------------------------------------
//                                                    CloseHash
//--------------------------------------------------------------------------------------------------------------------

/// The canonical signable hash of a state's closing transaction.
///
/// Sourced from the wallet layer's [`commitment_tx_message`][crate::wallet::multisig_wallet::commitment_tx_message]
/// so the record commits to exactly the message the adapted closing signature signs — both parties can compute it
/// independently before the transaction is built.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CloseHash([u8; CLOSE_HASH_LEN]);

impl CloseHash {
    /// Wrap a precomputed closing-transaction hash.
    pub fn new(bytes: [u8; CLOSE_HASH_LEN]) -> Self {
        CloseHash(bytes)
    }

    /// The raw hash bytes.
    pub fn as_bytes(&self) -> &[u8; CLOSE_HASH_LEN] {
        &self.0
    }
}

impl TryFrom<&[u8]> for CloseHash {
    type Error = UpdateRecordError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let arr: [u8; CLOSE_HASH_LEN] =
            bytes.try_into().map_err(|_| UpdateRecordError::InvalidCloseHashLength(bytes.len()))?;
        Ok(CloseHash(arr))
    }
}

impl TryFrom<Vec<u8>> for CloseHash {
    type Error = UpdateRecordError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        CloseHash::try_from(bytes.as_slice())
    }
}

impl Debug for CloseHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CloseHash({})", hex::encode(self.0))
    }
}

impl Display for CloseHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl Serialize for CloseHash {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(self.0))
    }
}

impl<'de> Deserialize<'de> for CloseHash {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        CloseHash::try_from(bytes.as_slice()).map_err(serde::de::Error::custom)
    }
}

//--------------------------------------------------------------------------------------------------------------------
//                                                Canonical message
//--------------------------------------------------------------------------------------------------------------------

/// The canonical, domain-separated serialization both parties sign — the identity the arbiter verifies.
///
/// Frozen layout (length prefixes on the variable-length fields only, following the house style of
/// `cryptography/attestation.rs`):
///
/// ```text
/// u64-LE(len(DST)) ‖ DST ‖ u32-LE(len(channel_id)) ‖ channel_id ‖ u64-LE(update_count) ‖ close_hash (64 bytes)
/// ```
pub fn update_record_message(channel_id: &ChannelId, update_count: u64, close_hash: &CloseHash) -> Vec<u8> {
    let id = channel_id.as_str().as_bytes();
    let mut msg = Vec::with_capacity(8 + UPDATE_RECORD_DST.len() + 4 + id.len() + 8 + CLOSE_HASH_LEN);
    msg.extend_from_slice(&(UPDATE_RECORD_DST.len() as u64).to_le_bytes());
    msg.extend_from_slice(UPDATE_RECORD_DST);
    msg.extend_from_slice(&(id.len() as u32).to_le_bytes());
    msg.extend_from_slice(id);
    msg.extend_from_slice(&update_count.to_le_bytes());
    msg.extend_from_slice(close_hash.as_bytes());
    msg
}

//--------------------------------------------------------------------------------------------------------------------
//                                                     Errors
//--------------------------------------------------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum UpdateRecordError {
    #[error("malformed channel id: {0}")]
    InvalidChannelId(#[from] ChannelIdParseError),
    #[error("close hash must be {CLOSE_HASH_LEN} bytes, got {0}")]
    InvalidCloseHashLength(usize),
    #[error("expected a record half signed by the {expected}, got one signed by the {actual}")]
    RoleMismatch { expected: ChannelRole, actual: ChannelRole },
    #[error("the {0}'s signature over the record does not verify")]
    InvalidSignature(ChannelRole),
    #[error("record halves disagree on the signed fields (channel id, update count, or close hash)")]
    MismatchedHalves,
}

//--------------------------------------------------------------------------------------------------------------------
//                                              Half-signed record
//--------------------------------------------------------------------------------------------------------------------

/// One party's half of an [`UpdateRecord`]: the signed fields plus that party's Schnorr signature over
/// [`update_record_message`]. The update protocol exchanges these; the counterparty verifies and countersigns.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct HalfSignedUpdateRecord {
    channel_id: ChannelId,
    update_count: u64,
    close_hash: CloseHash,
    signer_role: ChannelRole,
    signature: SchnorrSignature<Ed25519>,
}

impl HalfSignedUpdateRecord {
    /// Construct and sign our half of the record for state `update_count`.
    pub fn sign<R: RngCore + CryptoRng>(
        channel_id: ChannelId,
        update_count: u64,
        close_hash: CloseHash,
        signer_role: ChannelRole,
        secret: &XmrScalar,
        rng: &mut R,
    ) -> Self {
        let msg = update_record_message(&channel_id, update_count, &close_hash);
        let signature = SchnorrSignature::<Ed25519>::sign(secret, msg, rng);
        HalfSignedUpdateRecord { channel_id, update_count, close_hash, signer_role, signature }
    }

    /// Verify this half: well-formedness of the channel id plus the signer's Schnorr signature.
    pub fn verify(&self, signer_pubkey: &XmrPoint) -> Result<(), UpdateRecordError> {
        ChannelId::from_str(self.channel_id.as_str())?;
        let msg = update_record_message(&self.channel_id, self.update_count, &self.close_hash);
        self.signature
            .verify(signer_pubkey, msg)
            .then_some(())
            .ok_or(UpdateRecordError::InvalidSignature(self.signer_role))
    }

    pub fn channel_id(&self) -> &ChannelId {
        &self.channel_id
    }

    pub fn update_count(&self) -> u64 {
        self.update_count
    }

    pub fn close_hash(&self) -> &CloseHash {
        &self.close_hash
    }

    pub fn signer_role(&self) -> ChannelRole {
        self.signer_role
    }
}

//--------------------------------------------------------------------------------------------------------------------
//                                                   UpdateRecord
//--------------------------------------------------------------------------------------------------------------------

/// The cross-signed state receipt for one channel state — the object a party presents to the arbiter in a dispute.
///
/// `signature_a` is the customer's (P_A) signature and `signature_b` the merchant's (P_B), both over
/// [`update_record_message`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UpdateRecord {
    channel_id: ChannelId,
    update_count: u64,
    close_hash: CloseHash,
    signature_a: SchnorrSignature<Ed25519>,
    signature_b: SchnorrSignature<Ed25519>,
}

impl UpdateRecord {
    /// Verify the peer's half and countersign it with our own key, producing the full cross-signed record.
    ///
    /// `own_role` is *our* role; the peer half must be signed by the opposite role and verify under
    /// `peer_pubkey` before we add our signature.
    pub fn countersign<R: RngCore + CryptoRng>(
        peer_half: &HalfSignedUpdateRecord,
        peer_pubkey: &XmrPoint,
        own_role: ChannelRole,
        own_secret: &XmrScalar,
        rng: &mut R,
    ) -> Result<Self, UpdateRecordError> {
        let expected = own_role.other();
        if peer_half.signer_role != expected {
            return Err(UpdateRecordError::RoleMismatch { expected, actual: peer_half.signer_role });
        }
        peer_half.verify(peer_pubkey)?;
        let msg = update_record_message(&peer_half.channel_id, peer_half.update_count, &peer_half.close_hash);
        let own_signature = SchnorrSignature::<Ed25519>::sign(own_secret, msg, rng);
        let (signature_a, signature_b) = match own_role {
            ChannelRole::Customer => (own_signature, peer_half.signature.clone()),
            ChannelRole::Merchant => (peer_half.signature.clone(), own_signature),
        };
        Ok(UpdateRecord {
            channel_id: peer_half.channel_id.clone(),
            update_count: peer_half.update_count,
            close_hash: peer_half.close_hash,
            signature_a,
            signature_b,
        })
    }

    /// Assemble a record from two verified halves — the path where both parties signed and exchanged halves
    /// independently. Fails if the halves disagree on the signed fields or are not one of each role.
    pub fn from_halves(a: &HalfSignedUpdateRecord, b: &HalfSignedUpdateRecord) -> Result<Self, UpdateRecordError> {
        if a.channel_id != b.channel_id || a.update_count != b.update_count || a.close_hash != b.close_hash {
            return Err(UpdateRecordError::MismatchedHalves);
        }
        let (customer, merchant) = match (a.signer_role, b.signer_role) {
            (ChannelRole::Customer, ChannelRole::Merchant) => (a, b),
            (ChannelRole::Merchant, ChannelRole::Customer) => (b, a),
            (_, actual) => return Err(UpdateRecordError::RoleMismatch { expected: a.signer_role.other(), actual }),
        };
        Ok(UpdateRecord {
            channel_id: a.channel_id.clone(),
            update_count: a.update_count,
            close_hash: a.close_hash,
            signature_a: customer.signature.clone(),
            signature_b: merchant.signature.clone(),
        })
    }

    /// The arbiter's entire check: well-formedness (a valid channel id) plus the two Schnorr verifications —
    /// `signature_a` under the customer key `pubkey_a`, `signature_b` under the merchant key `pubkey_b`.
    pub fn verify(&self, pubkey_a: &XmrPoint, pubkey_b: &XmrPoint) -> Result<(), UpdateRecordError> {
        ChannelId::from_str(self.channel_id.as_str())?;
        let msg = update_record_message(&self.channel_id, self.update_count, &self.close_hash);
        if !self.signature_a.verify(pubkey_a, &msg) {
            return Err(UpdateRecordError::InvalidSignature(ChannelRole::Customer));
        }
        if !self.signature_b.verify(pubkey_b, &msg) {
            return Err(UpdateRecordError::InvalidSignature(ChannelRole::Merchant));
        }
        Ok(())
    }

    /// The whitepaper's monotonicity rule: this record supersedes `other` iff they speak about the same channel
    /// and this `update_count` is *strictly* greater. Counts need only increase — gaps are legal, so a record at
    /// count 100 supersedes one at count 5.
    pub fn supersedes(&self, other: &UpdateRecord) -> bool {
        self.channel_id == other.channel_id && self.update_count > other.update_count
    }

    pub fn channel_id(&self) -> &ChannelId {
        &self.channel_id
    }

    pub fn update_count(&self) -> u64 {
        self.update_count
    }

    pub fn close_hash(&self) -> &CloseHash {
        &self.close_hash
    }

    pub fn signature_a(&self) -> &SchnorrSignature<Ed25519> {
        &self.signature_a
    }

    pub fn signature_b(&self) -> &SchnorrSignature<Ed25519> {
        &self.signature_b
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciphersuite::group::ff::Field;
    use ciphersuite::Ciphersuite;
    use rand_core::OsRng;

    fn channel_id() -> ChannelId {
        ChannelId::from_str("XGC4a7024e7fd6f5c6a2d0131d12fd91ecd17f5da61c2970d603a05053b41a383").unwrap()
    }

    fn other_channel_id() -> ChannelId {
        ChannelId::from_str("XGC4a7024e7fd6f5c6a2d0131d12fd91ecd17f5da61c2970d603a05053b41a384").unwrap()
    }

    fn close_hash(fill: u8) -> CloseHash {
        CloseHash::new([fill; CLOSE_HASH_LEN])
    }

    struct Party {
        role: ChannelRole,
        secret: XmrScalar,
        pubkey: XmrPoint,
    }

    fn party(role: ChannelRole) -> Party {
        let secret = XmrScalar::random(&mut OsRng);
        let pubkey = Ed25519::generator() * secret;
        Party { role, secret, pubkey }
    }

    fn signed_record(update_count: u64) -> (UpdateRecord, Party, Party) {
        let customer = party(ChannelRole::Customer);
        let merchant = party(ChannelRole::Merchant);
        let half = HalfSignedUpdateRecord::sign(
            channel_id(),
            update_count,
            close_hash(7),
            ChannelRole::Customer,
            &customer.secret,
            &mut OsRng,
        );
        let record =
            UpdateRecord::countersign(&half, &customer.pubkey, ChannelRole::Merchant, &merchant.secret, &mut OsRng).unwrap();
        (record, customer, merchant)
    }

    #[test]
    fn sign_verify_round_trip() {
        let (record, customer, merchant) = signed_record(3);
        record.verify(&customer.pubkey, &merchant.pubkey).unwrap();
    }

    #[test]
    fn from_halves_round_trip() {
        let customer = party(ChannelRole::Customer);
        let merchant = party(ChannelRole::Merchant);
        let ha = HalfSignedUpdateRecord::sign(channel_id(), 9, close_hash(1), customer.role, &customer.secret, &mut OsRng);
        let hb = HalfSignedUpdateRecord::sign(channel_id(), 9, close_hash(1), merchant.role, &merchant.secret, &mut OsRng);
        // Argument order must not matter
        let r1 = UpdateRecord::from_halves(&ha, &hb).unwrap();
        let r2 = UpdateRecord::from_halves(&hb, &ha).unwrap();
        r1.verify(&customer.pubkey, &merchant.pubkey).unwrap();
        assert_eq!(r1, r2);
    }

    #[test]
    fn from_halves_rejects_mismatched_fields_and_roles() {
        let customer = party(ChannelRole::Customer);
        let merchant = party(ChannelRole::Merchant);
        let ha = HalfSignedUpdateRecord::sign(channel_id(), 9, close_hash(1), customer.role, &customer.secret, &mut OsRng);
        let hb = HalfSignedUpdateRecord::sign(channel_id(), 10, close_hash(1), merchant.role, &merchant.secret, &mut OsRng);
        assert!(matches!(UpdateRecord::from_halves(&ha, &hb), Err(UpdateRecordError::MismatchedHalves)));
        // Two halves signed by the same role
        let ha2 = HalfSignedUpdateRecord::sign(channel_id(), 9, close_hash(1), customer.role, &customer.secret, &mut OsRng);
        assert!(matches!(UpdateRecord::from_halves(&ha, &ha2), Err(UpdateRecordError::RoleMismatch { .. })));
    }

    #[test]
    fn countersign_rejects_wrong_role_half() {
        let customer = party(ChannelRole::Customer);
        let merchant = party(ChannelRole::Merchant);
        // A merchant-signed half presented to the merchant for countersigning
        let half = HalfSignedUpdateRecord::sign(channel_id(), 1, close_hash(7), merchant.role, &merchant.secret, &mut OsRng);
        let err = UpdateRecord::countersign(&half, &merchant.pubkey, ChannelRole::Merchant, &merchant.secret, &mut OsRng);
        assert!(matches!(err, Err(UpdateRecordError::RoleMismatch { .. })));
        // And a half that does not verify under the claimed pubkey
        let half = HalfSignedUpdateRecord::sign(channel_id(), 1, close_hash(7), customer.role, &customer.secret, &mut OsRng);
        let err = UpdateRecord::countersign(&half, &merchant.pubkey, ChannelRole::Merchant, &merchant.secret, &mut OsRng);
        assert!(matches!(err, Err(UpdateRecordError::InvalidSignature(ChannelRole::Customer))));
    }

    #[test]
    fn tampered_channel_id_fails() {
        let (mut record, customer, merchant) = signed_record(3);
        record.channel_id = other_channel_id();
        assert!(matches!(
            record.verify(&customer.pubkey, &merchant.pubkey),
            Err(UpdateRecordError::InvalidSignature(ChannelRole::Customer))
        ));
    }

    #[test]
    fn tampered_update_count_fails() {
        let (mut record, customer, merchant) = signed_record(3);
        record.update_count = 4;
        assert!(record.verify(&customer.pubkey, &merchant.pubkey).is_err());
    }

    #[test]
    fn tampered_close_hash_fails() {
        let (mut record, customer, merchant) = signed_record(3);
        record.close_hash = close_hash(8);
        assert!(record.verify(&customer.pubkey, &merchant.pubkey).is_err());
    }

    #[test]
    fn tampered_customer_signature_fails() {
        let (mut record, customer, merchant) = signed_record(3);
        let mallory = party(ChannelRole::Customer);
        let msg = update_record_message(&record.channel_id, record.update_count, &record.close_hash);
        record.signature_a = SchnorrSignature::<Ed25519>::sign(&mallory.secret, msg, &mut OsRng);
        assert!(matches!(
            record.verify(&customer.pubkey, &merchant.pubkey),
            Err(UpdateRecordError::InvalidSignature(ChannelRole::Customer))
        ));
    }

    #[test]
    fn tampered_merchant_signature_fails() {
        let (mut record, customer, merchant) = signed_record(3);
        let mallory = party(ChannelRole::Merchant);
        let msg = update_record_message(&record.channel_id, record.update_count, &record.close_hash);
        record.signature_b = SchnorrSignature::<Ed25519>::sign(&mallory.secret, msg, &mut OsRng);
        assert!(matches!(
            record.verify(&customer.pubkey, &merchant.pubkey),
            Err(UpdateRecordError::InvalidSignature(ChannelRole::Merchant))
        ));
    }

    #[test]
    fn swapped_signatures_fail() {
        let (mut record, customer, merchant) = signed_record(3);
        std::mem::swap(&mut record.signature_a, &mut record.signature_b);
        assert!(record.verify(&customer.pubkey, &merchant.pubkey).is_err());
    }

    #[test]
    fn swapped_pubkeys_fail() {
        let (record, customer, merchant) = signed_record(3);
        assert!(record.verify(&merchant.pubkey, &customer.pubkey).is_err());
    }

    #[test]
    fn serde_round_trip() {
        let (record, customer, merchant) = signed_record(42);
        let json = serde_json::to_string(&record).unwrap();
        let restored: UpdateRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(record, restored);
        restored.verify(&customer.pubkey, &merchant.pubkey).unwrap();
        // The half-signed wire message round-trips too
        let half = HalfSignedUpdateRecord::sign(channel_id(), 42, close_hash(7), customer.role, &customer.secret, &mut OsRng);
        let json = serde_json::to_string(&half).unwrap();
        let restored: HalfSignedUpdateRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(half, restored);
        restored.verify(&customer.pubkey).unwrap();
    }

    #[test]
    fn close_hash_length_is_enforced() {
        assert!(matches!(CloseHash::try_from(vec![0u8; 63]), Err(UpdateRecordError::InvalidCloseHashLength(63))));
        assert!(CloseHash::try_from(vec![0u8; 64]).is_ok());
        // Deserialization enforces it too
        let short = format!("\"{}\"", "ab".repeat(63));
        assert!(serde_json::from_str::<CloseHash>(&short).is_err());
    }

    #[test]
    fn supersession_is_strict_monotonicity() {
        let (r3, ..) = signed_record(3);
        let (r4, ..) = signed_record(4);
        let (r100, ..) = signed_record(100);
        assert!(r4.supersedes(&r3));
        assert!(!r3.supersedes(&r4));
        // Gap counts are legal: 100 supersedes 3 directly, no +1 increments required
        assert!(r100.supersedes(&r3));
        assert!(r100.supersedes(&r4));
        // Strictly greater: equal counts never supersede, in either direction
        let (r3b, ..) = signed_record(3);
        assert!(!r3.supersedes(&r3b));
        assert!(!r3b.supersedes(&r3));
        assert!(!r3.supersedes(&r3));
    }

    #[test]
    fn supersession_requires_same_channel() {
        let (r3, ..) = signed_record(3);
        let (mut r9, ..) = signed_record(9);
        r9.channel_id = other_channel_id();
        assert!(!r9.supersedes(&r3));
    }

    #[test]
    fn message_layout_is_frozen() {
        // Known-answer freeze of the canonical serialization: if this vector changes, the protocol changed.
        let id = channel_id();
        let msg = update_record_message(&id, 0x0102030405060708, &close_hash(0xaa));
        let mut expected = Vec::new();
        expected.extend_from_slice(&(UPDATE_RECORD_DST.len() as u64).to_le_bytes());
        expected.extend_from_slice(b"Grease UpdateRecord v1");
        expected.extend_from_slice(&65u32.to_le_bytes());
        expected.extend_from_slice(id.as_str().as_bytes());
        expected.extend_from_slice(&[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]);
        expected.extend_from_slice(&[0xaa; 64]);
        assert_eq!(msg, expected);
    }
}
