use crate::balance::Balances;
use crate::cryptography::keys::Curve25519PublicKey;
use crate::helpers::group_element_to_hex;
use crate::key_escrow_services::KesConfiguration;
use crate::monero::data_objects::ClosingAddresses;
use blake2::Blake2b512;
use ciphersuite::group::GroupEncoding;
use ciphersuite::{Ciphersuite, Ed25519};
use digest::consts::U32;
use digest::typenum::{IsGreaterOrEqual, True};
use digest::OutputSizeUser;
use flexible_transcript::{DigestTranscript, SecureDigest, Transcript};
use serde::{Deserialize, Serialize};
use std::borrow::Borrow;
use std::fmt::{Debug, Display};
use std::hash::Hash;
use std::marker::PhantomData;
use std::str::FromStr;
use thiserror::Error;

/// Error returned when parsing a [`ChannelId`] from a string fails.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ChannelIdParseError {
    #[error("Invalid channel ID format: expected 65 characters starting with 'XGC', got {0} characters")]
    InvalidLength(usize),
    #[error("Invalid channel ID format: must start with 'XGC' prefix")]
    InvalidPrefix,
    #[error("Invalid channel ID format: contains non-hexadecimal characters after prefix")]
    InvalidHex,
}

/// A 65-character string uniquely identifying a payment channel.
///
/// Format: "XGC" prefix (3 chars) + first 31 bytes of channel hash as hex (62 chars).
///
/// This is the human-readable representation of a [`ChannelId`]. It can be used as a key
/// in maps, displayed to users, and transmitted over the network.
///
/// # Example
///
/// ```
/// use libgrease::channel_id::ChannelId;
/// use std::str::FromStr;
///
/// let id = ChannelId::from_str("XGC4a7024e7fd6f5c6a2d0131d12fd91ecd17f5da61c2970d603a05053b41a383").unwrap();
/// assert_eq!(id.as_str(), "XGC4a7024e7fd6f5c6a2d0131d12fd91ecd17f5da61c2970d603a05053b41a383");
/// ```
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ChannelId(String);

impl ChannelId {
    /// The prefix for all channel ID strings.
    pub const PREFIX: &'static str = "XGC";

    /// The total length of a channel ID string (3 char prefix + 62 hex chars).
    pub const LENGTH: usize = 65;

    /// Create a new `ChannelId` from a [`ChannelIdMetadata`].
    pub fn from_channel_id_metadata<C, D>(id: &ChannelIdMetadata<C, D>) -> Self
    where
        C: Ciphersuite,
        D: Send + Clone + SecureDigest,
        <D as OutputSizeUser>::OutputSize: IsGreaterOrEqual<U32, Output = True>,
    {
        Self(id.as_hex())
    }

    /// Returns the channel ID as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes self and returns the inner String.
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl Debug for ChannelId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ChannelId({})", self.0)
    }
}

impl Display for ChannelId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for ChannelId {
    type Err = ChannelIdParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != Self::LENGTH {
            return Err(ChannelIdParseError::InvalidLength(s.len()));
        }
        if !s.starts_with(Self::PREFIX) {
            return Err(ChannelIdParseError::InvalidPrefix);
        }
        // Validate that the hex portion is valid
        hex::decode(&s[3..]).map_err(|_| ChannelIdParseError::InvalidHex)?;
        Ok(Self(s.to_string()))
    }
}

impl AsRef<str> for ChannelId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Borrow<str> for ChannelId {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl From<ChannelId> for String {
    fn from(id: ChannelId) -> Self {
        id.0
    }
}

impl TryFrom<&str> for ChannelId {
    type Error = ChannelIdParseError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::from_str(s)
    }
}

impl TryFrom<String> for ChannelId {
    type Error = ChannelIdParseError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::from_str(&s)
    }
}

/// The unique identifier for a payment channel.
///
/// The channel ID is derived from a digest transcript hash (domain separator: `"Grease ChannelId v1"`)
/// over the following fields, in order:
/// - `merchant_key`: The merchant's Curve25519 public key (32 bytes, compressed)
/// - `customer_key`: The customer's Curve25519 public key (32 bytes, compressed)
/// - `merchant_balance`: The merchant's initial balance in piconero (u64, little-endian)
/// - `customer_balance`: The customer's initial balance in piconero (u64, little-endian)
/// - `merchant_closing_address`: The merchant's Monero closing address
/// - `customer_closing_address`: The customer's Monero closing address
/// - `merchant_nonce`: The merchant's channel nonce (u64, little-endian)
/// - `customer_nonce`: The customer's channel nonce (u64, little-endian)
///
/// The digest type `D` must produce at least 32 bytes of output. The default (`Blake2b512`)
/// produces a 64-byte hash. The human-readable channel ID format is `XGC` followed by the
/// first 31 bytes of the hash encoded as hex (65 characters total).
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct ChannelIdMetadata<C: Ciphersuite = Ed25519, D = Blake2b512> {
    /// The key the customer uses to derive a shared channel secret.
    #[serde(serialize_with = "crate::helpers::serialize_ge", deserialize_with = "crate::helpers::deserialize_ge")]
    merchant_key: C::G,
    /// The key the merchant uses to derive a shared channel secret.
    #[serde(serialize_with = "crate::helpers::serialize_ge", deserialize_with = "crate::helpers::deserialize_ge")]
    customer_key: C::G,
    initial_balance: Balances,
    closing_addresses: ClosingAddresses,
    /// The KES configuration committed to in this channel ID.
    kes_config: KesConfiguration<C>,
    /// The merchant's contribution to the channel nonce
    merchant_nonce: u64,
    /// The customer's contribution to the channel nonce
    customer_nonce: u64,
    #[serde(serialize_with = "crate::helpers::to_hex", deserialize_with = "crate::helpers::from_hex")]
    hashed_id: Vec<u8>,
    _phantom: PhantomData<D>,
}

impl<C: Ciphersuite, D> ChannelIdMetadata<C, D>
where
    D: Send + Clone + SecureDigest,
    <D as OutputSizeUser>::OutputSize: IsGreaterOrEqual<U32, Output = True>,
{
    /// Create a new channel ID from the given parameters.
    ///
    /// See [`ChannelIdMetadata`] for the full specification of the hash computation.
    ///
    /// The generic parameter `D` controls the digest algorithm and output size.
    /// The digest must produce at least 32 bytes of output (enforced at compile time).
    ///
    /// # Compile-time safety
    ///
    /// Using a digest with fewer than 32 bytes of output will fail to compile:
    ///
    /// ```compile_fail
    /// use libgrease::channel_id::ChannelId;
    /// #use libgrease::cryptography::keys::{Curve25519PublicKey, PublicKey};
    /// #use libgrease::balance::Balances;
    /// #use libgrease::monero::data_objects::ClosingAddresses;
    /// #use blake2::Blake2b;
    /// #use digest::consts::U16;
    ///
    /// // This fails to compile because Blake2b<U16> only produces 16 bytes
    /// fn wont_compile(
    ///     merchant_key: C::G,
    ///     customer_key: C::G,
    ///     balance: Balances,
    ///     closing: ClosingAddresses,
    /// ) {
    ///     let _ = ChannelId::<Blake2b<U16>>::new(
    ///         merchant_key, customer_key, balance, closing, 0, 0
    ///     );
    /// }
    /// ```
    pub fn new(
        merchant_key: C::G,
        customer_key: C::G,
        initial_balance: Balances,
        closing_addresses: ClosingAddresses,
        kes_config: KesConfiguration<C>,
        merchant_nonce: u64,
        customer_nonce: u64,
    ) -> Self {
        let amount_mer = initial_balance.merchant.to_piconero().to_le_bytes();
        let amount_cust = initial_balance.customer.to_piconero().to_le_bytes();

        let mut transcript = DigestTranscript::<D>::new(b"Grease ChannelId v1");
        transcript.append_message(b"merchant_key", merchant_key.to_bytes());
        transcript.append_message(b"customer_key", customer_key.to_bytes());
        transcript.append_message(b"merchant_balance", amount_mer);
        transcript.append_message(b"customer_balance", amount_cust);
        transcript.append_message(b"merchant_closing_address", closing_addresses.merchant().as_bytes());
        transcript.append_message(b"customer_closing_address", closing_addresses.customer().as_bytes());
        transcript.append_message(b"kes_public_key", kes_config.kes_public_key.to_bytes());
        transcript.append_message(b"kes_peer_public_key", kes_config.peer_public_key.to_bytes());
        transcript.append_message(b"dispute_window", kes_config.dispute_window.as_secs().to_le_bytes());
        transcript.append_message(b"merchant_nonce", merchant_nonce.to_le_bytes());
        transcript.append_message(b"customer_nonce", customer_nonce.to_le_bytes());

        let challenge = transcript.challenge(b"channel_id");
        let output_size = <D as OutputSizeUser>::output_size();
        let hashed_id = challenge[..output_size].to_vec();

        ChannelIdMetadata {
            merchant_key,
            customer_key,
            initial_balance,
            closing_addresses,
            kes_config,
            hashed_id,
            merchant_nonce,
            customer_nonce,
            _phantom: PhantomData,
        }
    }

    pub fn merchant_key(&self) -> &C::G {
        &self.merchant_key
    }

    pub fn customer_key(&self) -> &C::G {
        &self.customer_key
    }

    pub fn initial_balance(&self) -> Balances {
        self.initial_balance
    }

    pub fn closing_addresses(&self) -> &ClosingAddresses {
        &self.closing_addresses
    }

    pub fn kes_config(&self) -> &KesConfiguration<C> {
        &self.kes_config
    }

    pub fn merchant_nonce(&self) -> u64 {
        self.merchant_nonce
    }

    pub fn customer_nonce(&self) -> u64 {
        self.customer_nonce
    }

    pub fn hash(&self) -> &[u8] {
        &self.hashed_id
    }

    /// Returns the channel ID as a hex string in the format `XGC<first 31 bytes of hash in hex>`.
    /// This produces a 65-character string: "XGC" prefix + 62 hex characters.
    pub fn as_hex(&self) -> String {
        let hash = self.hash();
        format!("XGC{}", hex::encode(&hash[..31]))
    }

    /// Returns the channel ID as a [`ChannelId`].
    ///
    /// This is the preferred way to get the channel identifier for use as a key or display.
    pub fn name(&self) -> ChannelId {
        ChannelId::from_channel_id_metadata(self)
    }
}

impl<C: Ciphersuite, D> Debug for ChannelIdMetadata<C, D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChannelId")
            .field("merchant_key", &group_element_to_hex::<C>(&self.merchant_key))
            .field("customer_key", &group_element_to_hex::<C>(&self.customer_key))
            .field("initial balance (merchant)", &self.initial_balance.merchant)
            .field("initial balance (customer)", &self.initial_balance.customer)
            .field("merchant_nonce", &self.merchant_nonce)
            .field("customer_nonce", &self.customer_nonce)
            .field("hashed_id", &hex::encode(&self.hashed_id))
            .finish()
    }
}

impl<C: Ciphersuite, D> Display for ChannelIdMetadata<C, D>
where
    D: Send + Clone + SecureDigest,
    <D as OutputSizeUser>::OutputSize: IsGreaterOrEqual<U32, Output = True>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_hex())
    }
}

impl<C: Ciphersuite, D> PartialEq for ChannelIdMetadata<C, D> {
    fn eq(&self, other: &Self) -> bool {
        self.hashed_id == other.hashed_id
    }
}

impl<C: Ciphersuite, D> Eq for ChannelIdMetadata<C, D> {}

#[cfg(test)]
mod test {
    use super::*;
    use crate::amount::MoneroAmount;
    use crate::balance::Balances;
    use crate::key_escrow_services::KesConfiguration;
    use crate::monero::data_objects::ClosingAddresses;
    use crate::XmrPoint;
    use blake2::Blake2b;
    use ciphersuite::group::ff::Field;
    use ciphersuite::group::Group;
    use ciphersuite::Ed25519;
    use digest::consts::U32;

    const ALICE_ADDRESS: &str =
        "43i4pVer2tNFELvfFEEXxmbxpwEAAFkmgN2wdBiaRNcvYcgrzJzVyJmHtnh2PWR42JPeDVjE8SnyK3kPBEjSixMsRz8TncK";
    const BOB_ADDRESS: &str =
        "4BH2vFAir1iQCwi2RxgQmsL1qXmnTR9athNhpK31DoMwJgkpFUp2NykFCo4dXJnMhU7w9UZx7uC6qbNGuePkRLYcFo4N7p3";

    fn merchant_key() -> XmrPoint {
        XmrPoint::generator()
    }

    fn customer_key() -> XmrPoint {
        XmrPoint::generator() + XmrPoint::generator()
    }

    fn other_key() -> XmrPoint {
        XmrPoint::generator() * <Ed25519 as Ciphersuite>::F::random(&mut rand_core::OsRng)
    }

    fn test_kes_config() -> KesConfiguration<Ed25519> {
        let kes_pk = customer_key();
        let peer_pk = merchant_key();
        KesConfiguration::new_with_defaults(kes_pk, peer_pk)
    }

    #[test]
    fn channel_id() {
        let balance = Balances::new(MoneroAmount::from_xmr("1.25").unwrap(), MoneroAmount::from_xmr("0.75").unwrap());
        let closing = ClosingAddresses::new(ALICE_ADDRESS, BOB_ADDRESS).expect("should be valid closing addresses");
        let id: ChannelIdMetadata<Ed25519> =
            ChannelIdMetadata::new(merchant_key(), customer_key(), balance, closing, test_kes_config(), 100, 200);
        assert_eq!(id.merchant_key(), &merchant_key());
        assert_eq!(id.customer_key(), &customer_key());
        assert_eq!(id.initial_balance().merchant.to_piconero(), 1_250_000_000_000);
        assert_eq!(id.initial_balance().customer.to_piconero(), 750_000_000_000);
        assert_eq!(id.merchant_nonce(), 100);
        assert_eq!(id.customer_nonce(), 200);
        assert_eq!(id.closing_addresses().customer().to_string(), ALICE_ADDRESS);
        assert_eq!(id.closing_addresses().merchant().to_string(), BOB_ADDRESS);
        assert_eq!(id.hash().len(), 64);
        assert_eq!(id.as_hex().len(), 65);
        assert!(id.as_hex().starts_with("XGC"));
    }

    #[test]
    fn id_equality() {
        let amt = Balances::new(MoneroAmount::from_xmr("1.25").unwrap(), MoneroAmount::from_xmr("0.75").unwrap());
        let amt2 = Balances::new(MoneroAmount::from_xmr("0.0").unwrap(), MoneroAmount::from_xmr("0.5").unwrap());
        let closing1 = ClosingAddresses::new(ALICE_ADDRESS, BOB_ADDRESS).expect("should be valid closing addresses");
        let closing2 = ClosingAddresses::new(BOB_ADDRESS, ALICE_ADDRESS).expect("should be valid closing addresses");
        let kes = test_kes_config();

        // Same parameters -> same ID
        let id1: ChannelIdMetadata<Ed25519> =
            ChannelIdMetadata::new(merchant_key(), customer_key(), amt, closing1, kes.clone(), 100, 200);
        let id2: ChannelIdMetadata<Ed25519> =
            ChannelIdMetadata::new(merchant_key(), customer_key(), amt, closing1, kes.clone(), 100, 200);
        assert_eq!(id1, id2);

        // Different merchant key -> different ID
        let id3 = ChannelIdMetadata::new(other_key(), customer_key(), amt, closing1, kes.clone(), 100, 200);
        assert_ne!(id1, id3);

        // Different customer key -> different ID
        let id4 = ChannelIdMetadata::new(merchant_key(), other_key(), amt, closing1, kes.clone(), 100, 200);
        assert_ne!(id1, id4);

        // Different balance -> different ID
        let id5 = ChannelIdMetadata::new(merchant_key(), customer_key(), amt2, closing1, kes.clone(), 100, 200);
        assert_ne!(id1, id5);

        // Different nonce -> different ID
        let id6 = ChannelIdMetadata::new(merchant_key(), customer_key(), amt, closing1, kes.clone(), 999, 200);
        assert_ne!(id1, id6);

        // Different output size -> different ID
        let id7 = ChannelIdMetadata::<Ed25519, Blake2b<U32>>::new(
            merchant_key(),
            customer_key(),
            amt,
            closing1,
            kes.clone(),
            100,
            200,
        );
        assert_ne!(id1.as_hex(), id7.as_hex());

        // Different closing addresses -> different ID
        let id8 = ChannelIdMetadata::new(merchant_key(), customer_key(), amt, closing2, kes.clone(), 100, 200);
        assert_ne!(id1, id8);

        // Different KES config -> different ID
        let other_kes = KesConfiguration::new_with_defaults(other_key(), merchant_key());
        let id9 = ChannelIdMetadata::new(merchant_key(), customer_key(), amt, closing1, other_kes, 100, 200);
        assert_ne!(id1, id9);
    }

    #[test]
    fn serialize_deserialize_roundtrip() {
        let balance = Balances::new(MoneroAmount::from_xmr("1.25").unwrap(), MoneroAmount::from_xmr("0.75").unwrap());
        let closing = ClosingAddresses::new(ALICE_ADDRESS, BOB_ADDRESS).expect("should be valid closing addresses");
        let id: ChannelIdMetadata<Ed25519> = ChannelIdMetadata::new(
            merchant_key(),
            customer_key(),
            balance,
            closing,
            test_kes_config(),
            12345,
            67890,
        );

        let serialized = ron::to_string(&id).unwrap();
        let deserialized: ChannelIdMetadata<Ed25519> = ron::from_str(&serialized).unwrap();

        assert_eq!(id.merchant_key(), deserialized.merchant_key());
        assert_eq!(id.customer_key(), deserialized.customer_key());
        assert_eq!(id.initial_balance(), deserialized.initial_balance());
        assert_eq!(id.merchant_nonce(), deserialized.merchant_nonce());
        assert_eq!(id.customer_nonce(), deserialized.customer_nonce());
        assert_eq!(id.hash(), deserialized.hash());
        assert_eq!(
            id.closing_addresses().merchant().to_string(),
            deserialized.closing_addresses().merchant().to_string()
        );
        assert_eq!(
            id.closing_addresses().customer().to_string(),
            deserialized.closing_addresses().customer().to_string()
        );
    }

    #[test]
    fn channel_id_string_from_channel_id() {
        let balance = Balances::new(MoneroAmount::from_xmr("1.25").unwrap(), MoneroAmount::from_xmr("0.75").unwrap());
        let closing = ClosingAddresses::new(ALICE_ADDRESS, BOB_ADDRESS).expect("should be valid closing addresses");
        let id: ChannelIdMetadata<Ed25519> =
            ChannelIdMetadata::new(merchant_key(), customer_key(), balance, closing, test_kes_config(), 100, 200);

        let id_string = ChannelId::from_channel_id_metadata(&id);
        assert!(id_string.as_str().starts_with("XGC"));
        assert_eq!(id_string.as_str().len(), 65);
    }

    #[test]
    fn channel_id_string_from_str() {
        // Valid channel ID
        let valid = "XGC4a7024e7fd6f5c6a2d0131d12fd91ecd17f5da61c2970d603a05053b41a383";
        let id = ChannelId::from_str(valid).unwrap();
        assert_eq!(id.as_str(), valid);

        // Invalid: wrong length
        let too_short = "XGC4a7024e7fd6f5c6a2d0131d12fd91ecd17f5da61c2970d603a05053b41a38";
        assert!(matches!(
            ChannelId::from_str(too_short),
            Err(ChannelIdParseError::InvalidLength(64))
        ));

        // Invalid: wrong prefix
        let wrong_prefix = "ABC4a7024e7fd6f5c6a2d0131d12fd91ecd17f5da61c2970d603a05053b41a383";
        assert!(matches!(
            ChannelId::from_str(wrong_prefix),
            Err(ChannelIdParseError::InvalidPrefix)
        ));

        // Invalid: non-hex characters - 'z' is not valid hex (62 z's after XGC = 65 chars total)
        let invalid_hex = "XGCzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
        assert_eq!(invalid_hex.len(), 65, "Test setup error: invalid_hex should be 65 chars");
        assert!(matches!(ChannelId::from_str(invalid_hex), Err(ChannelIdParseError::InvalidHex)));
    }

    #[test]
    fn channel_id_string_display() {
        let valid = "XGC4a7024e7fd6f5c6a2d0131d12fd91ecd17f5da61c2970d603a05053b41a383";
        let id = ChannelId::from_str(valid).unwrap();
        assert_eq!(format!("{id}"), valid);
        assert_eq!(format!("{id:?}"), format!("ChannelId({valid})"));
    }

    #[test]
    fn channel_id_string_equality_and_hash() {
        use std::collections::HashSet;

        let a = ChannelId::from_str("XGC4a7024e7fd6f5c6a2d0131d12fd91ecd17f5da61c2970d603a05053b41a383").unwrap();
        let b = ChannelId::from_str("XGC4a7024e7fd6f5c6a2d0131d12fd91ecd17f5da61c2970d603a05053b41a383").unwrap();
        // Different ID - 62 zeros after XGC = 65 chars total
        let c = ChannelId::from_str("XGC00000000000000000000000000000000000000000000000000000000000000").unwrap();

        assert_eq!(a, b);
        assert_ne!(a, c);

        // Test hash works correctly
        let mut set = HashSet::new();
        set.insert(a.clone());
        assert!(set.contains(&b));
        assert!(!set.contains(&c));
    }

    #[test]
    fn channel_id_string_serialize_deserialize() {
        let original =
            ChannelId::from_str("XGC4a7024e7fd6f5c6a2d0131d12fd91ecd17f5da61c2970d603a05053b41a383").unwrap();

        let serialized = ron::to_string(&original).unwrap();
        let deserialized: ChannelId = ron::from_str(&serialized).unwrap();

        assert_eq!(original, deserialized);
    }
}
