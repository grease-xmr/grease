use serde::{Deserialize, Deserializer, Serialize};

pub fn proof_to_hex<S>(opt: &Option<Box<[u8; 14080]>>, s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match opt {
        Some(bytes) => hex::encode(**bytes).serialize(s),
        None => "".serialize(s), // Serialize as an empty string if the proof is None,
    }
}

pub fn proof_from_hex<'de, D>(de: D) -> Result<Option<Box<[u8; 14080]>>, D::Error>
where
    D: Deserializer<'de>,
{
    let hex_str = String::deserialize(de)?;
    if hex_str.is_empty() {
        return Ok(None);
    }
    if hex_str.len() != 28160 {
        return Err(serde::de::Error::custom("Invalid hex string length for proof"));
    }
    // Ensure the hex string can be decoded into a 14080-byte array
    if hex_str.len() % 2 != 0 {
        return Err(serde::de::Error::custom("Hex string must have an even length"));
    }
    // Create an array to hold the decoded bytes
    let mut result = [0u8; 14080];
    hex::decode_to_slice(hex_str, &mut result)
        .map_err(|e| serde::de::Error::custom(format!("Invalid hex string: {e}")))?;
    Ok(Some(Box::new(result)))
}
