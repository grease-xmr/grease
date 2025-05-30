use curve25519_dalek::Scalar;
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
