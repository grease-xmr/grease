use monero_wallet::WalletOutput;
use serde::ser::SerializeSeq;
use serde::{Deserialize, Deserializer, Serializer};

/// Serialize `Vec<WalletOutput>` as a sequence of byte arrays.
/// Uses `WalletOutput::write` to serialize each output.
pub fn serialize_outputs<S>(outputs: &Vec<WalletOutput>, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut seq = s.serialize_seq(Some(outputs.len()))?;
    for output in outputs {
        let buf = output.serialize();
        seq.serialize_element(&buf)?;
    }
    seq.end()
}

/// Deserialize `Vec<WalletOutput>` from a sequence of byte arrays.
/// Uses `WalletOutput::read` to deserialize each output.
pub fn deserialize_outputs<'de, D>(de: D) -> Result<Vec<WalletOutput>, D::Error>
where
    D: Deserializer<'de>,
{
    let byte_vec: Vec<Vec<u8>> = Vec::deserialize(de)?;
    byte_vec.into_iter().map(|b| WalletOutput::read(&mut b.as_slice()).map_err(serde::de::Error::custom)).collect()
}
