use libp2p::identity::Keypair;
use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Display};
use std::path::Path;
use thiserror::Error;

#[derive(Serialize, Deserialize)]
pub struct ChannelIdentity {
    id: String,
    #[serde(serialize_with = "serialize_key", deserialize_with = "deserialize_key")]
    keypair: Keypair,
    #[serde(
        serialize_with = "serialize_peer",
        deserialize_with = "deserialize_peer"
    )]
    peer_id: PeerId,
}

impl ChannelIdentity {
    /// Create a new identity with the given id and keypair.
    /// The peer id is derived from the public key.
    pub fn random_with_id<S: Into<String>>(id: S) -> Self {
        let keypair = Keypair::generate_ed25519();
        let peer_id = keypair.public().to_peer_id();
        ChannelIdentity {
            id: id.into(),
            keypair,
            peer_id,
        }
    }

    /// Create a new identity with a random id and keypair.
    pub fn random() -> Self {
        Self::random_with_id(random_name())
    }

    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<(), IdentityError> {
        let text = self.to_yml()?;
        std::fs::write(path, text)?;
        Ok(())
    }

    pub fn to_yml(&self) -> Result<String, IdentityError> {
        let s = serde_yml::to_string(self)?;
        Ok(s)
    }

    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, IdentityError> {
        let text = std::fs::read_to_string(path)?;
        let identity: ChannelIdentity = serde_yml::from_str(&text)?;
        Ok(identity)
    }

    /// Return an internal consistency check, that the Peer Id corresponds to the public key.
    pub fn check(&self) -> bool {
        self.peer_id == self.keypair.public().to_peer_id()
    }
}

impl Display for ChannelIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.id, self.peer_id)
    }
}

impl Debug for ChannelIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ChannelIdentity({self})")
    }
}

impl PartialEq for ChannelIdentity {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
            && self.keypair.public() == other.keypair.public()
            && self.peer_id.to_base58() == self.peer_id.to_base58()
    }
}

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("Error reading/writing identity: {0}")]
    Io(#[from] std::io::Error),
    #[error("Error de/encoding identity: {0}")]
    Serde(#[from] serde_yml::Error),
}

const FUNNY_ADJECTIVES: [&str; 35] = [
    "Wacky",
    "Zany",
    "Quirky",
    "Goofy",
    "Silly",
    "Bizarre",
    "Nutty",
    "Loony",
    "Whimsical",
    "Absurd",
    "Red",
    "Hilarious",
    "Comical",
    "Farcical",
    "Ludicrous",
    "Sexy",
    "Fishy",
    "Eccentric",
    "Freaky",
    "Kooky",
    "Peculiar",
    "Odd",
    "Strange",
    "Unusual",
    "Stretchy",
    "Droll",
    "Jocular",
    "Jovial",
    "Mirthful",
    "Playful",
    "Sour",
    "Sad",
    "Spicy",
    "Witty",
    "Zesty",
];

const AMUSING_NOUNS: [&str; 40] = [
    "Banana",
    "Noodle",
    "Pickle",
    "Wombat",
    "Giraffe",
    "Penguin",
    "Platypus",
    "Unicorn",
    "Dinosaur",
    "Marshmallow",
    "Cupcake",
    "Pancake",
    "Muffin",
    "Sausage",
    "Meatball",
    "Taco",
    "Burrito",
    "Nacho",
    "Pudding",
    "Jellybean",
    "Lollipop",
    "Bubblegum",
    "Cheeseburger",
    "Hotdog",
    "Pizza",
    "Spaghetti",
    "Meatloaf",
    "Cucumber",
    "Tomato",
    "Potato",
    "Pumpkin",
    "Zucchini",
    "Broccoli",
    "Cauliflower",
    "Cabbage",
    "Radish",
    "Turnip",
    "Beetroot",
    "Carrot",
    "Parsnip",
];

fn random_name() -> String {
    let i = rand::random_range(0..FUNNY_ADJECTIVES.len());
    let j = rand::random_range(0..AMUSING_NOUNS.len());
    format!("{}{}", FUNNY_ADJECTIVES[i], AMUSING_NOUNS[j])
}

fn serialize_key<S>(key: &Keypair, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let ed25519pair = key
        .clone()
        .try_into_ed25519()
        .map_err(serde::ser::Error::custom)?;
    let encoded = hex::encode(ed25519pair.to_bytes());
    serializer.serialize_str(&encoded)
}

fn deserialize_key<'de, D>(deserializer: D) -> Result<Keypair, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let encoded = String::deserialize(deserializer)?;
    let mut bytes = hex::decode(encoded).map_err(serde::de::Error::custom)?;
    let result =
        Keypair::ed25519_from_bytes(&mut bytes[0..32]).map_err(serde::de::Error::custom)?;
    let derived_pubkey = result
        .public()
        .try_into_ed25519()
        .map_err(serde::de::Error::custom)?
        .to_bytes();
    if derived_pubkey[..] != bytes[32..] {
        return Err(serde::de::Error::custom("public key mismatch"));
    }
    Ok(result)
}

fn serialize_peer<S>(id: &PeerId, s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let bytes = id.to_bytes();
    let encoded = hex::encode(&bytes);
    s.serialize_str(&encoded)
}

fn deserialize_peer<'de, D>(d: D) -> Result<PeerId, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let encoded = String::deserialize(d)?;
    let bytes = hex::decode(encoded).map_err(serde::de::Error::custom)?;
    PeerId::from_bytes(&bytes).map_err(serde::de::Error::custom)
}

#[cfg(test)]
mod test {
    use super::*;
    use tempfile::TempPath;

    #[test]
    fn test_identity_save_load() {
        let identity = ChannelIdentity::random();
        let tmp = TempPath::from_path("test_id.yml");
        let s = identity.to_yml().expect("serialize identity");
        println!("serialized identity:\n{s}");
        identity.save(&tmp).expect("save identity");
        let loaded = ChannelIdentity::load(&tmp).expect("load identity");
        assert_eq!(identity, loaded);
        assert!(identity.check(), "identity check failed");
    }
}
