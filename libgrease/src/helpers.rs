use std::time::Duration;

use chrono::{DateTime, TimeZone, Utc};
use serde::{Deserialize, Deserializer, Serialize};

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
    pub fn to_datetime(&self) -> DateTime<Utc> {
        Utc.timestamp_opt(self.0 as i64, 0)
            .single()
            .expect("valid timestamp")
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

impl<Tz: TimeZone> From<DateTime<Tz>> for Timestamp {
    fn from(dt: DateTime<Tz>) -> Self {
        Self(dt.timestamp() as u64)
    }
}

impl From<Timestamp> for DateTime<Utc> {
    fn from(ts: Timestamp) -> Self {
        ts.to_datetime()
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
        let dt = ts.to_datetime();
        assert_eq!(dt, Utc.timestamp_opt(0, 0).single().unwrap());

        let ts = Timestamp::new(1234567890);
        let dt = ts.to_datetime();
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
    fn test_from_datetime_utc() {
        let dt = Utc.timestamp_opt(1234567890, 0).single().unwrap();
        let ts: Timestamp = dt.into();
        assert_eq!(ts.0, 1234567890);
    }

    #[test]
    fn test_from_datetime_fixed_offset() {
        let offset = FixedOffset::east_opt(3600).unwrap();
        let dt = offset.timestamp_opt(1234567890, 0).single().unwrap();
        let ts: Timestamp = dt.into();
        assert_eq!(ts.0, 1234567890);
    }

    #[test]
    fn test_into_datetime_utc() {
        let ts = Timestamp::new(1234567890);
        let dt: DateTime<Utc> = ts.into();
        assert_eq!(dt.timestamp(), 1234567890);
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
}
