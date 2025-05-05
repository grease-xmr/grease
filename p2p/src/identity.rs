use futures::TryStreamExt;
use libp2p::identity::Keypair;
use libp2p::{Multiaddr, PeerId};
use ron::ser::PrettyConfig;
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Display};
use std::path::Path;
use thiserror::Error;

/// `ConversationIdentity` represents a unique identity for a communications channel in libp2p. The
/// word 'channel' is heavily overloaded in this application, so we use the term 'conversation' to refer to a P2P channel.
#[derive(Clone, Serialize, Deserialize)]
pub struct ConversationIdentity {
    /// A name for this identity to help you disambiguate between multiple identities stored on the same local device.
    /// It is not used in communications.
    id: String,
    /// The keypair used for signing and verifying messages in network communications. The secret key is only used to
    /// sign messages, and is not used in payment channels.
    #[serde(serialize_with = "serialize_key", deserialize_with = "deserialize_key")]
    keypair: Keypair,
    /// The peer id derived from the public key. This is used to identify this identity in network communications.
    #[serde(serialize_with = "serialize_peer", deserialize_with = "deserialize_peer")]
    peer_id: PeerId,
    /// If given, is the address other parties can use to dial this identity.
    address: Option<Multiaddr>,
}

impl ConversationIdentity {
    /// Create a new identity with the given id and keypair.
    /// The peer id is derived from the public key.
    pub fn random_with_id<S: Into<String>>(id: S) -> Self {
        let keypair = Keypair::generate_ed25519();
        let peer_id = keypair.public().to_peer_id();
        ConversationIdentity { id: id.into(), keypair, peer_id, address: None }
    }

    /// Create a new identity with a random id and keypair.
    pub fn random() -> Self {
        Self::random_with_id(random_name())
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn keypair(&self) -> &Keypair {
        &self.keypair
    }

    pub fn peer_id(&self) -> &PeerId {
        &self.peer_id
    }

    pub fn set_address(&mut self, address: Multiaddr) {
        self.address = Some(address);
    }

    pub fn address(&self) -> Option<&Multiaddr> {
        self.address.as_ref()
    }

    pub fn take_keypair(self) -> Keypair {
        self.keypair
    }

    pub fn save_yml<P: AsRef<Path>>(&self, path: P) -> Result<(), IdentityError> {
        let text = self.to_yml()?;
        std::fs::write(path, text)?;
        Ok(())
    }

    pub fn save_ron<P: AsRef<Path>>(&self, path: P) -> Result<(), IdentityError> {
        let text = self.to_ron()?;
        std::fs::write(path, text)?;
        Ok(())
    }

    pub fn to_yml(&self) -> Result<String, IdentityError> {
        let s = serde_yml::to_string(self)?;
        Ok(s)
    }

    pub fn to_ron(&self) -> Result<String, IdentityError> {
        let config = PrettyConfig::new().compact_arrays(true).compact_maps(true);
        let val = ron::ser::to_string_pretty(self, config)?;
        Ok(val)
    }

    pub fn load_yml<P: AsRef<Path>>(path: P) -> Result<Self, IdentityError> {
        let text = std::fs::read_to_string(path)?;
        let identity: ConversationIdentity = serde_yml::from_str(&text)?;
        Ok(identity)
    }

    pub fn load_ron<P: AsRef<Path>>(path: P) -> Result<Self, IdentityError> {
        let text = std::fs::read_to_string(path)?;
        let identity: ConversationIdentity = ron::from_str(&text).map_err(ron::Error::from)?;
        Ok(identity)
    }

    /// Return this identity as a contact info sheet. Other parties can use this to contact you.
    ///
    /// The address must be set for this to return a contact sheet.
    pub fn contact_info(&self) -> Option<ContactInfo> {
        self.address.as_ref().map(|addr| ContactInfo {
            name: self.id.clone(),
            peer_id: self.peer_id.clone(),
            address: addr.clone(),
        })
    }

    /// Return an internal consistency check, that the Peer Id corresponds to the public key.
    pub fn check(&self) -> bool {
        self.peer_id == self.keypair.public().to_peer_id()
    }
}

impl Display for ConversationIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.id, self.peer_id)
    }
}

impl Debug for ConversationIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ConversationIdentity({self})")
    }
}

impl PartialEq for ConversationIdentity {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
            && self.keypair.public() == other.keypair.public()
            && self.peer_id.to_base58() == other.peer_id.to_base58()
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ContactInfo {
    pub name: String,
    #[serde(serialize_with = "serialize_peer", deserialize_with = "deserialize_peer")]
    pub peer_id: PeerId,
    pub address: Multiaddr,
}

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("Error reading/writing identity: {0}")]
    Io(#[from] std::io::Error),
    #[error("Error de/encoding identity in YAML: {0}")]
    SerdeYaml(#[from] serde_yml::Error),
    #[error("Error decoding identity in RON: {0}")]
    SerdeRon(#[from] ron::Error),
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
    let ed25519pair = key.clone().try_into_ed25519().map_err(serde::ser::Error::custom)?;
    let encoded = hex::encode(ed25519pair.to_bytes());
    serializer.serialize_str(&encoded)
}

fn deserialize_key<'de, D>(deserializer: D) -> Result<Keypair, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let encoded = String::deserialize(deserializer)?;
    let mut bytes = hex::decode(encoded).map_err(serde::de::Error::custom)?;
    let result = Keypair::ed25519_from_bytes(&mut bytes[0..32]).map_err(serde::de::Error::custom)?;
    let derived_pubkey = result.public().try_into_ed25519().map_err(serde::de::Error::custom)?.to_bytes();
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
    use log::info;
    use tempfile::TempPath;

    #[test]
    fn test_identity_save_load_yml() {
        env_logger::try_init().ok();
        let identity = ConversationIdentity::random();
        let tmp = TempPath::from_path("test_id.yml");
        let s = identity.to_yml().expect("serialize identity");
        info!("serialized YAML identity:\n{s}");
        identity.save_yml(&tmp).expect("save identity");
        let loaded = ConversationIdentity::load_yml(&tmp).expect("load identity");
        assert_eq!(identity, loaded);
        assert!(identity.check(), "identity check failed");
    }

    #[test]
    fn test_identity_save_load_ron() {
        env_logger::try_init().ok();
        let identity = ConversationIdentity::random();
        let tmp = TempPath::from_path("test_id.ron");
        let s = identity.to_ron().expect("serialize identity");
        info!("serialized RON identity:\n{s}");
        identity.save_ron(&tmp).expect("save identity");
        let loaded = ConversationIdentity::load_ron(&tmp).expect("load identity");
        assert_eq!(identity, loaded);
        assert!(identity.check(), "identity check failed");
    }
}
