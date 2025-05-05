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
    /// Generates a new `ConversationIdentity` with the specified ID and a random Ed25519 keypair.
    ///
    /// The resulting identity uses the provided string as its local identifier, generates a new Ed25519 keypair for signing, and derives the peer ID from the public key. The network address is unset.
    ///
    /// # Examples
    ///
    /// ```
    /// let identity = ConversationIdentity::random_with_id("alice");
    /// assert_eq!(identity.id(), "alice");
    /// assert!(identity.address().is_none());
    /// ```    pub fn random_with_id<S: Into<String>>(id: S) -> Self {
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

    /// Returns a reference to the libp2p `PeerId` associated with this identity.
    ///
    /// # Examples
    ///
    /// ```
    /// let identity = ConversationIdentity::random();
    /// let peer_id = identity.peer_id();
    /// println!("Peer ID: {}", peer_id);
    /// ```
    pub fn peer_id(&self) -> &PeerId {
        &self.peer_id
    }

    /// Sets the network address for this identity.
    ///
    /// # Examples
    ///
    /// ```
    /// use libp2p::multiaddr::Multiaddr;
    /// let mut identity = ConversationIdentity::random();
    /// let addr: Multiaddr = "/ip4/127.0.0.1/tcp/4001".parse().unwrap();
    /// identity.set_address(addr.clone());
    /// assert_eq!(identity.address(), Some(&addr));
    /// ```
    pub fn set_address(&mut self, address: Multiaddr) {
        self.address = Some(address);
    }

    /// Returns the network address associated with this identity, if set.
    ///
    /// # Examples
    ///
    /// ```
    /// let mut identity = ConversationIdentity::random();
    /// assert!(identity.address().is_none());
    /// identity.set_address("/ip4/127.0.0.1/tcp/4001".parse().unwrap());
    /// assert_eq!(
    ///     identity.address().unwrap().to_string(),
    ///     "/ip4/127.0.0.1/tcp/4001"
    /// );
    /// ```
    pub fn address(&self) -> Option<&Multiaddr> {
        self.address.as_ref()
    }

    /// ```
    pub fn take_keypair(self) -> Keypair {
        self.keypair
    }

    /// Saves the identity to a YAML file at the specified path.
    ///
    /// # Errors
    ///
    /// Returns an `IdentityError` if serialization fails or if the file cannot be written.
    ///
    /// # Examples
    ///
    /// ```
    /// let identity = ConversationIdentity::random();
    /// identity.save_yml("identity.yml").unwrap();
    /// ```
    pub fn save_yml<P: AsRef<Path>>(&self, path: P) -> Result<(), IdentityError> {
        let text = self.to_yml()?;
        std::fs::write(path, text)?;
        Ok(())
    }

    /// Saves the identity to a file in RON format.
    ///
    /// Writes the serialized RON representation of this `ConversationIdentity` to the specified file path.
    ///
    /// # Errors
    ///
    /// Returns an `IdentityError` if serialization or file writing fails.
    ///
    /// # Examples
    ///
    /// ```
    /// let identity = ConversationIdentity::random();
    /// identity.save_ron("identity.ron")?;
    /// ```
    pub fn save_ron<P: AsRef<Path>>(&self, path: P) -> Result<(), IdentityError> {
        let text = self.to_ron()?;
        std::fs::write(path, text)?;
        Ok(())
    }

    /// Serializes the identity to a YAML string.
    ///
    /// # Returns
    ///
    /// A YAML-formatted string representing the identity, or an `IdentityError` if serialization fails.
    ///
    /// # Examples
    ///
    /// ```
    /// let identity = ConversationIdentity::random();
    /// let yaml = identity.to_yml().unwrap();
    /// assert!(yaml.contains(&identity.id()));
    /// ```
    pub fn to_yml(&self) -> Result<String, IdentityError> {
        let s = serde_yml::to_string(self)?;
        Ok(s)
    }

    /// Serializes the identity to a pretty-printed RON string with compact arrays and maps.
    ///
    /// # Returns
    ///
    /// A `Result` containing the RON-formatted string on success, or an `IdentityError` if serialization fails.
    ///
    /// # Examples
    ///
    /// ```
    /// let identity = ConversationIdentity::random();
    /// let ron_str = identity.to_ron().unwrap();
    /// assert!(ron_str.contains("id"));
    /// ```
    pub fn to_ron(&self) -> Result<String, IdentityError> {
        let config = PrettyConfig::new().compact_arrays(true).compact_maps(true);
        let val = ron::ser::to_string_pretty(self, config)?;
        Ok(val)
    }

    /// Loads a `ConversationIdentity` from a YAML file.
    ///
    /// Returns an error if the file cannot be read or if deserialization fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use your_crate::ConversationIdentity;
    /// let identity = ConversationIdentity::load_yml("identity.yml").unwrap();
    /// ```
    pub fn load_yml<P: AsRef<Path>>(path: P) -> Result<Self, IdentityError> {
        let text = std::fs::read_to_string(path)?;
        let identity: ConversationIdentity = serde_yml::from_str(&text)?;
        Ok(identity)
    }

    /// Loads a `ConversationIdentity` from a RON-encoded file.
    ///
    /// Returns an error if the file cannot be read or if deserialization fails.
    ///
    /// # Examples
    ///
    /// ```
    /// let identity = ConversationIdentity::random();
    /// identity.save_ron("identity.ron").unwrap();
    /// let loaded = ConversationIdentity::load_ron("identity.ron").unwrap();
    /// assert_eq!(identity, loaded);
    /// ```
    pub fn load_ron<P: AsRef<Path>>(path: P) -> Result<Self, IdentityError> {
        let text = std::fs::read_to_string(path)?;
        let identity: ConversationIdentity = ron::from_str(&text).map_err(ron::Error::from)?;
        Ok(identity)
    }

    /// Return this identity as a contact info sheet. Other parties can use this to contact you.
    ///
    /// Returns the contact information for this identity if a network address is set.
    ///
    /// If the identity has an associated address, returns a `ContactInfo` struct containing the name, peer ID, and address. Otherwise, returns `None`.
    ///
    /// # Examples
    ///
    /// ```
    /// let mut identity = ConversationIdentity::random();
    /// assert!(identity.contact_info().is_none());
    ///
    /// let addr: Multiaddr = "/ip4/127.0.0.1/tcp/4001".parse().unwrap();
    /// identity.set_address(addr.clone());
    /// let info = identity.contact_info().unwrap();
    /// assert_eq!(info.address, addr);
    /// ```    pub fn contact_info(&self) -> Option<ContactInfo> {
        self.address.as_ref().map(|addr| ContactInfo {
            name: self.id.clone(),
            peer_id: self.peer_id.clone(),
            address: addr.clone(),
        })
    }

    /// Checks if the stored peer ID matches the peer ID derived from the public key.
    ///
    /// Returns `true` if the internal peer ID is consistent with the keypair's public key, otherwise `false`.
    ///
    /// # Examples
    ///
    /// ```
    /// let identity = ConversationIdentity::random();
    /// assert!(identity.check());
    /// ```    pub fn check(&self) -> bool {
        self.peer_id == self.keypair.public().to_peer_id()
    }
}

impl Display for ConversationIdentity {
    /// Formats the conversation identity as a string in the form "id:peer_id".
    ///
    /// # Examples
    ///
    /// ```
    /// let identity = ConversationIdentity::random_with_id("alice");
    /// assert_eq!(
    ///     format!("{}", identity),
    ///     format!("{}:{}", identity.id(), identity.peer_id())
    /// );
    /// ```
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.id, self.peer_id)
    }
}

impl Debug for ConversationIdentity {
    /// Formats the `ConversationIdentity` for debugging as `ChannelIdentity({Display})`.
    ///
    /// # Examples
    ///
    /// ```
    /// let identity = ConversationIdentity::random();
    /// println!("{:?}", identity); // Output: ChannelIdentity(funnynoun:peerid)
    /// ```
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ChannelIdentity({self})")
    }
}

impl PartialEq for ConversationIdentity {
    /// Checks if two `ConversationIdentity` instances are equal by comparing their IDs, public keys, and peer IDs.
    ///
    /// Returns `true` if the IDs and public keys are identical and the peer IDs match; otherwise, returns `false`.
    ///
    /// # Examples
    ///
    /// ```
    /// let id1 = ConversationIdentity::random_with_id("alice");
    /// let id2 = id1.clone();
    /// assert!(id1 == id2);
    /// ```
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
            && self.keypair.public() == other.keypair.public()
            && self.peer_id.to_base58() == self.peer_id.to_base58()
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
