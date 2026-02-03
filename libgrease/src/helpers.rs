use crate::XmrScalar;
use chrono::{DateTime, TimeZone, Utc};
use ciphersuite::group::ff::PrimeField;
use ciphersuite::group::GroupEncoding;
use ciphersuite::Ciphersuite;
use serde::{Deserialize, Deserializer, Serialize};
use std::time::Duration;

pub fn to_hex<S>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    hex::encode(bytes).serialize(s)
}

pub fn option_to_hex<S>(opt: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match opt {
        Some(bytes) => hex::encode(bytes).serialize(s),
        None => panic!(r#"Put skip_serializing_if = "Option::is_none" in front of the attibute to serialize"#),
    }
}

pub fn from_hex<'de, D>(de: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let hex_str = String::deserialize(de)?;
    hex::decode(hex_str).map_err(|e| serde::de::Error::custom(format!("Invalid hex string: {e}")))
}

pub fn option_from_hex<'de, D>(de: D) -> Result<Option<Vec<u8>>, D::Error>
where
    D: Deserializer<'de>,
{
    let hex_str = String::deserialize(de)?;
    let bytes = hex::decode(hex_str).map_err(|e| serde::de::Error::custom(format!("Invalid hex string: {e}")))?;
    Ok(Some(bytes))
}

pub fn array_from_hex<'de, D>(de: D) -> Result<[u8; 32], D::Error>
where
    D: Deserializer<'de>,
{
    let hex_str = String::deserialize(de)?;
    let mut result = [0u8; 32];
    hex::decode_to_slice(hex_str, &mut result)
        .map_err(|e| serde::de::Error::custom(format!("Invalid hex string: {e}")))?;
    Ok(result)
}

/// Convert an XmrScalar (Ed25519 scalar) to a hex string.
pub fn xmr_scalar_as_hex(s: &XmrScalar) -> String {
    hex::encode(s.to_repr())
}

/// Convert an XmrScalar (Ed25519 scalar) to a BIG-endian hex string.
/// This output can be used in Prover.toml files for Noir circuits.
pub fn xmr_scalar_as_be_hex(s: &XmrScalar) -> String {
    let mut bytes = s.to_repr();
    bytes.reverse();
    hex::encode(bytes)
}

/// Serialize an XmrScalar (Ed25519 scalar) as a hex string.
pub fn xmr_scalar_to_hex<S>(scalar: &XmrScalar, s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    hex::encode(scalar.to_repr()).serialize(s)
}

/// Deserialize an XmrScalar (Ed25519 scalar) from a hex string.
pub fn xmr_scalar_from_hex<'de, D>(de: D) -> Result<XmrScalar, D::Error>
where
    D: Deserializer<'de>,
{
    let hex_str = String::deserialize(de)?;
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(&hex_str, &mut bytes)
        .map_err(|e| serde::de::Error::custom(format!("Invalid hex string: {e}")))?;
    let scalar = Option::<XmrScalar>::from(XmrScalar::from_repr(bytes.into()))
        .ok_or_else(|| serde::de::Error::custom("Invalid scalar value"))?;
    Ok(scalar)
}

/// Serialize a Zeroizing<XmrScalar> as a hex string.
pub fn zeroizing_scalar_to_hex<S>(scalar: &zeroize::Zeroizing<XmrScalar>, s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    xmr_scalar_to_hex(scalar, s)
}

/// Deserialize a Zeroizing<XmrScalar> from a hex string.
pub fn zeroizing_scalar_from_hex<'de, D>(de: D) -> Result<zeroize::Zeroizing<XmrScalar>, D::Error>
where
    D: Deserializer<'de>,
{
    xmr_scalar_from_hex(de).map(zeroize::Zeroizing::new)
}

/// Convert a group element to a hex string.
pub fn group_element_to_hex<C: Ciphersuite>(element: &C::G) -> String {
    hex::encode(element.to_bytes().as_ref())
}

/// Parse a group element from a hex string.
pub fn group_element_from_hex<C: Ciphersuite>(hex_str: &str) -> Result<C::G, String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("Invalid hex string: {e}"))?;
    let mut repr = <C::G as GroupEncoding>::Repr::default();
    let repr_len = repr.as_ref().len();
    if bytes.len() != repr_len {
        return Err(format!("Invalid length: expected {repr_len} bytes, got {}", bytes.len()));
    }
    repr.as_mut().copy_from_slice(&bytes);
    C::G::from_bytes(&repr).into_option().ok_or_else(|| "Invalid group element".to_string())
}

/// Serialize a group element as a hex string using serde.
pub fn serialize_group_element<C: Ciphersuite, S>(element: &C::G, s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    group_element_to_hex::<C>(element).serialize(s)
}

/// Deserialize a group element from a hex string using serde.
pub fn deserialize_group_element<'de, C: Ciphersuite, D>(de: D) -> Result<C::G, D::Error>
where
    D: Deserializer<'de>,
{
    let hex_str = String::deserialize(de)?;
    group_element_from_hex::<C>(&hex_str).map_err(serde::de::Error::custom)
}

/// Serialize a group element as hex using only the `GroupEncoding` bound.
///
/// Unlike [`serialize_group_element`], this function is parameterized over `G` directly (not `C: Ciphersuite`),
/// which allows Rust's type inference to resolve the generic from the field type `C::G`.
pub fn serialize_ge<G: GroupEncoding, S: serde::Serializer>(element: &G, s: S) -> Result<S::Ok, S::Error> {
    hex::encode(element.to_bytes().as_ref()).serialize(s)
}

/// Deserialize a group element from hex using only the `GroupEncoding` bound.
///
/// Unlike [`deserialize_group_element`], this function is parameterized over `G` directly (not `C: Ciphersuite`),
/// which allows Rust's type inference to resolve the generic from the field type `C::G`.
pub fn deserialize_ge<'de, G, D>(de: D) -> Result<G, D::Error>
where
    G: GroupEncoding,
    D: Deserializer<'de>,
{
    let hex_str = String::deserialize(de)?;
    let bytes = hex::decode(&hex_str).map_err(|e| serde::de::Error::custom(format!("Invalid hex string: {e}")))?;
    let mut repr = G::Repr::default();
    let repr_slice = repr.as_ref().len();
    if bytes.len() != repr_slice {
        return Err(serde::de::Error::custom(format!(
            "Invalid group element length: expected {repr_slice} bytes, got {}",
            bytes.len()
        )));
    }
    repr.as_mut().copy_from_slice(&bytes);
    Option::from(G::from_bytes(&repr)).ok_or_else(|| serde::de::Error::custom("Invalid group element encoding"))
}

/// Serialize a `HashMap<TransactionId, TransactionRecord>` as a sequence of `(key, value)` pairs.
///
/// JSON requires map keys to be strings, but `TransactionId` serializes as an object.
/// This helper serializes the map as a list of pairs instead.
pub fn serialize_tx_map<S>(
    map: &std::collections::HashMap<
        crate::monero::data_objects::TransactionId,
        crate::monero::data_objects::TransactionRecord,
    >,
    s: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    use serde::ser::SerializeSeq;
    let mut seq = s.serialize_seq(Some(map.len()))?;
    for (k, v) in map {
        seq.serialize_element(&(k, v))?;
    }
    seq.end()
}

/// Deserialize a `HashMap<TransactionId, TransactionRecord>` from a sequence of `(key, value)` pairs.
pub fn deserialize_tx_map<'de, D>(
    de: D,
) -> Result<
    std::collections::HashMap<
        crate::monero::data_objects::TransactionId,
        crate::monero::data_objects::TransactionRecord,
    >,
    D::Error,
>
where
    D: Deserializer<'de>,
{
    let pairs: Vec<(
        crate::monero::data_objects::TransactionId,
        crate::monero::data_objects::TransactionRecord,
    )> = Vec::deserialize(de)?;
    Ok(pairs.into_iter().collect())
}

/// A UTC Unix timestamp representing seconds since January 1, 1970.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Timestamp(u64);

impl Timestamp {
    /// Creates a new Timestamp from seconds since Unix epoch.
    pub fn new(seconds: u64) -> Self {
        Self(seconds)
    }

    /// Returns the current UTC time as a Timestamp.
    pub fn now() -> Self {
        Self(Utc::now().timestamp() as u64)
    }

    /// Creates a Timestamp that is `duration` time from now.
    pub fn from_now(duration: Duration) -> Self {
        Self(Utc::now().timestamp() as u64 + duration.as_secs())
    }

    /// Returns the underlying seconds value.
    pub fn as_secs(&self) -> u64 {
        self.0
    }

    /// Converts this Timestamp to a chrono DateTime<Utc>.
    /// In odd corners cases where the timestamp is invalid (exactly coinciding with a leap-second,
    /// or out-of-range values), this will return None.
    pub fn to_datetime(&self) -> Option<DateTime<Utc>> {
        let t = i64::try_from(self.0).ok()?;
        Utc.timestamp_opt(t, 0).single()
    }
}

impl From<u64> for Timestamp {
    fn from(secs: u64) -> Self {
        Self(secs)
    }
}

impl From<Timestamp> for u64 {
    fn from(ts: Timestamp) -> Self {
        ts.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::FixedOffset;

    #[test]
    fn test_new() {
        let ts = Timestamp::new(1234567890);
        assert_eq!(ts.0, 1234567890);
    }

    #[test]
    fn test_now_returns_current_time() {
        let before = Utc::now().timestamp() as u64;
        let ts = Timestamp::now();
        let after = Utc::now().timestamp() as u64;

        assert!(ts.0 >= before && ts.0 <= after);
    }

    #[test]
    fn test_from_now() {
        let duration = Duration::from_secs(60);
        let before = Utc::now().timestamp() as u64 + 60;
        let ts = Timestamp::from_now(duration);
        let after = Utc::now().timestamp() as u64 + 60;

        assert!(ts.0 >= before && ts.0 <= after);
    }

    #[test]
    fn test_as_secs() {
        let ts = Timestamp::new(42);
        assert_eq!(ts.as_secs(), 42);
    }

    #[test]
    fn test_to_datetime() {
        let ts = Timestamp::new(0);
        let dt = ts.to_datetime().unwrap();
        assert_eq!(dt, Utc.timestamp_opt(0, 0).single().unwrap());

        let ts = Timestamp::new(1234567890);
        let dt = ts.to_datetime().unwrap();
        assert_eq!(dt.timestamp(), 1234567890);
    }

    #[test]
    fn test_from_u64() {
        let ts: Timestamp = 100u64.into();
        assert_eq!(ts.0, 100);
    }

    #[test]
    fn test_into_u64() {
        let ts = Timestamp::new(200);
        let secs: u64 = ts.into();
        assert_eq!(secs, 200);
    }

    #[test]
    fn test_ordering() {
        let ts1 = Timestamp::new(100);
        let ts2 = Timestamp::new(200);
        let ts3 = Timestamp::new(100);

        assert!(ts1 < ts2);
        assert!(ts2 > ts1);
        assert_eq!(ts1, ts3);
    }

    #[test]
    fn test_serde_serialize() {
        let ts = Timestamp::new(1234567890);
        let json = serde_json::to_string(&ts).unwrap();
        assert_eq!(json, "1234567890");
    }

    #[test]
    fn test_serde_deserialize() {
        let ts: Timestamp = serde_json::from_str("1234567890").unwrap();
        assert_eq!(ts.0, 1234567890);
    }

    #[test]
    fn test_serde_roundtrip() {
        let original = Timestamp::new(9876543210);
        let json = serde_json::to_string(&original).unwrap();
        let deserialized: Timestamp = serde_json::from_str(&json).unwrap();
        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_clone_and_copy() {
        let ts1 = Timestamp::new(42);
        let ts2 = ts1;
        let ts3 = ts1.clone();

        assert_eq!(ts1, ts2);
        assert_eq!(ts1, ts3);
    }

    #[test]
    fn test_hash() {
        use std::collections::HashSet;

        let mut set = HashSet::new();
        set.insert(Timestamp::new(100));
        set.insert(Timestamp::new(200));
        set.insert(Timestamp::new(100));

        assert_eq!(set.len(), 2);
    }

    #[test]
    fn test_group_element_hex_roundtrip() {
        use ciphersuite::group::ff::Field;
        use ciphersuite::group::Group;
        use ciphersuite::{Ciphersuite, Ed25519};
        use rand_core::OsRng;

        let mut rng = OsRng;

        // Generate a random group element
        let scalar = <Ed25519 as Ciphersuite>::F::random(&mut rng);
        let element = <Ed25519 as Ciphersuite>::G::generator() * scalar;

        // Convert to hex and back
        let hex_str = group_element_to_hex::<Ed25519>(&element);
        let recovered = group_element_from_hex::<Ed25519>(&hex_str).unwrap();

        assert_eq!(element, recovered);
    }

    #[test]
    fn test_group_element_hex_generator() {
        use ciphersuite::group::Group;
        use ciphersuite::{Ciphersuite, Ed25519};

        let generator = <Ed25519 as Ciphersuite>::G::generator();
        let hex_str = group_element_to_hex::<Ed25519>(&generator);
        let recovered = group_element_from_hex::<Ed25519>(&hex_str).unwrap();

        assert_eq!(generator, recovered);
    }

    #[test]
    fn test_group_element_hex_invalid_length() {
        use ciphersuite::Ed25519;

        // Too short
        let result = group_element_from_hex::<Ed25519>("abcd");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid length"));
    }

    #[test]
    fn test_group_element_hex_invalid_hex() {
        use ciphersuite::Ed25519;

        // Invalid hex characters
        let result = group_element_from_hex::<Ed25519>("xyz123");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid hex string"));
    }
}
