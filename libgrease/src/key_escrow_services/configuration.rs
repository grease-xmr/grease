use ciphersuite::Ciphersuite;
use serde::{Deserialize, Serialize};
use std::time::Duration;

pub const DEFAULT_DISPUTE_WINDOW: Duration = Duration::from_hours(24);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(bound = "")]
pub struct KesConfiguration<KC: Ciphersuite> {
    /// The global public key for the KES.
    #[serde(serialize_with = "crate::helpers::serialize_ge", deserialize_with = "crate::helpers::deserialize_ge")]
    pub kes_public_key: KC::G,
    /// The public key corresponding to the peer's nonce for this channel.
    #[serde(serialize_with = "crate::helpers::serialize_ge", deserialize_with = "crate::helpers::deserialize_ge")]
    pub peer_public_key: KC::G,
    /// The duration of the dispute window for this KES configuration. This is the amount of time that a defendant has to respond to
    /// a forced channel closure before the KES can be used to claim the channel funds.
    pub dispute_window: Duration,
}

impl<KC: Ciphersuite> KesConfiguration<KC> {
    pub fn new(kes: KC::G, peer: KC::G, dispute_window: Duration) -> Self {
        Self { kes_public_key: kes, peer_public_key: peer, dispute_window }
    }

    pub fn new_with_defaults(kes: KC::G, peer: KC::G) -> Self {
        Self::new(kes, peer, DEFAULT_DISPUTE_WINDOW)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum KesImplementation {
    StandaloneEd25519,
}

impl KesImplementation {
    pub fn name(&self) -> &'static str {
        match self {
            KesImplementation::StandaloneEd25519 => "StandaloneEd25519",
        }
    }
}

impl TryFrom<&str> for KesImplementation {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "StandaloneEd25519" => Ok(KesImplementation::StandaloneEd25519),
            _ => Err(format!("Unsupported KES implementation: {value}")),
        }
    }
}
