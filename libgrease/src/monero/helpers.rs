use monero::{KeyPair, Network, PrivateKey};
use serde::{Deserialize, Deserializer};

pub fn deserialize_keypair<'de, D>(de: D) -> Result<KeyPair, D::Error>
where
    D: Deserializer<'de>,
{
    let encoded = String::deserialize(de)?;
    if encoded.len() != 128 {
        return Err(serde::de::Error::custom("Invalid length"));
    }
    let bytes = hex::decode(encoded).map_err(serde::de::Error::custom)?;
    let spend =
        PrivateKey::from_slice(&bytes[0..32]).map_err(|_| serde::de::Error::custom("Invalid spend key encoding"))?;
    let view =
        PrivateKey::from_slice(&bytes[32..64]).map_err(|_| serde::de::Error::custom("Invalid view key encoding"))?;
    Ok(KeyPair { spend, view })
}

pub fn serialize_keypair<S>(key: &KeyPair, s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let mut bytes = [0u8; 64];
    bytes[0..32].copy_from_slice(key.spend.as_bytes());
    bytes[32..64].copy_from_slice(key.view.as_bytes());
    let encoded = hex::encode(bytes);
    s.serialize_str(&encoded)
}

pub fn serialize_network<S>(network: &monero::Network, s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let network_str = network_to_str(*network);
    s.serialize_str(network_str)
}

pub fn network_to_str(network: Network) -> &'static str {
    match network {
        Network::Mainnet => "mainnet",
        Network::Stagenet => "stagenet",
        Network::Testnet => "testnet",
    }
}

pub fn deserialize_network<'de, D>(de: D) -> Result<monero::Network, D::Error>
where
    D: Deserializer<'de>,
{
    let network_str = String::deserialize(de)?;
    match network_str.as_str() {
        "mainnet" => Ok(monero::Network::Mainnet),
        "stagenet" => Ok(monero::Network::Stagenet),
        "testnet" => Ok(monero::Network::Testnet),
        _ => Err(serde::de::Error::custom("Invalid network type")),
    }
}
