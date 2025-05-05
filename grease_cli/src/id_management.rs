use crate::config::{GlobalOptions, IdCommand};
use crate::error::ServerError;
use anyhow::anyhow;
use grease_p2p::ConversationIdentity;
use libgrease::crypto::hashes::{Blake512, HashToScalar};
use libgrease::crypto::keys::{Curve25519PublicKey, Curve25519Secret};
use libgrease::crypto::traits::PublicKey;
use log::{debug, info};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

pub struct KeyManager {
    initial_key: Curve25519Secret,
    initial_public_key: Curve25519PublicKey,
}

impl KeyManager {
    pub fn new(initial_key: Curve25519Secret) -> Self {
        let initial_public_key = Curve25519PublicKey::from_secret(&initial_key);
        KeyManager { initial_key, initial_public_key }
    }

    pub fn new_keypair(&self, index: u64) -> (Curve25519Secret, Curve25519PublicKey) {
        let secret = self.initial_key.as_scalar().as_bytes();
        let mut buf = [0u8; 40];
        buf[0..32].copy_from_slice(secret);
        buf[32..40].copy_from_slice(&index.to_le_bytes());
        let scalar = Blake512::default().hash_to_scalar(&buf);
        let next_key = Curve25519Secret::from(scalar);
        let next_public_key = Curve25519PublicKey::from_secret(&next_key);
        (next_key, next_public_key)
    }
}

pub fn exec_id_command(cmd: IdCommand, config: GlobalOptions) -> Result<(), anyhow::Error> {
    match cmd {
        IdCommand::Create { name } => {
            let id = create_identity(&config, name)?;
            println!("Identity saved: {id}");
        }
        IdCommand::List => {
            let ids = list_identities(&config)?;
            println!("{}", ids.join("\n"));
        }
        IdCommand::Delete { id } => {
            if delete_identity(&config, &id)? {
                println!("Identity deleted: {id}");
            } else {
                println!("Identity not found: {id}");
            }
        }
    }
    Ok(())
}

pub fn delete_identity(config: &GlobalOptions, id: &String) -> Result<bool, anyhow::Error> {
    let path = config.identities_file.as_ref().cloned().unwrap_or_else(default_config_path);
    let mut local_identities = load_or_create_identities(&path)?;
    match local_identities.remove(&id) {
        Some(identity) => {
            info!("Identity deleted: {identity}");
            local_identities.save(&path)?;
            Ok(true)
        }
        None => {
            info!("Cannot delete identity with id {id}. It is not in the database.");
            Ok(false)
        }
    }
}

pub fn create_identity(config: &GlobalOptions, name: Option<String>) -> Result<ConversationIdentity, anyhow::Error> {
    let path = config.identities_file.as_ref().cloned().unwrap_or_else(default_config_path);
    let mut local_identities = load_or_create_identities(&path)?;
    let identity = match name {
        Some(name) => ConversationIdentity::random_with_id(name.clone()),
        None => ConversationIdentity::random(),
    };
    if local_identities.contains(identity.id()) {
        return Err(anyhow!("Identity with id {} already exists.", identity.id()));
    }
    local_identities.insert(identity.id().to_string(), identity.clone());
    info!("Saving identities to {}", path.to_str().unwrap_or("[invalid utf-8 path]"));
    local_identities.save(&path)?;
    Ok(identity)
}

pub fn list_identities(config: &GlobalOptions) -> Result<Vec<String>, anyhow::Error> {
    let path = config.identities_file.as_ref().cloned().unwrap_or_else(default_config_path);
    let local_identities = load_or_create_identities(&path)?;
    debug!("{} Local identities found.", local_identities.identities.len());
    let ids = local_identities.identities.iter().map(|(_, id)| id.to_string()).collect::<Vec<String>>();
    Ok(ids)
}

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct LocalIdentitySet {
    pub identities: HashMap<String, ConversationIdentity>,
}

impl LocalIdentitySet {
    pub fn try_load<P: AsRef<Path>>(path: P) -> Result<Self, ServerError> {
        let ids = load_identities_file(path)?;
        Ok(ids)
    }

    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<(), ServerError> {
        save_config_file(path, self)
    }

    pub fn is_empty(&self) -> bool {
        self.identities.is_empty()
    }

    pub fn contains(&self, id: &str) -> bool {
        self.identities.contains_key(id)
    }

    pub fn get(&self, id: &str) -> Option<&ConversationIdentity> {
        self.identities.get(id)
    }

    pub fn insert(&mut self, id: String, identity: ConversationIdentity) -> Option<ConversationIdentity> {
        self.identities.insert(id, identity)
    }

    pub fn ids(&self) -> impl Iterator<Item = &String> {
        self.identities.keys()
    }

    pub fn identities(&self) -> impl Iterator<Item = &ConversationIdentity> {
        self.identities.values()
    }

    pub fn remove<S: AsRef<str>>(&mut self, id: S) -> Option<ConversationIdentity> {
        self.identities.remove(id.as_ref())
    }
}

pub fn default_config_path() -> PathBuf {
    let mut home = std::env::home_dir().unwrap_or_else(|| PathBuf::from("."));
    home.push(".grease");
    home.push("config.yml");
    home
}

pub fn load_identities_file<P: AsRef<Path>>(path: P) -> Result<LocalIdentitySet, ServerError> {
    let file = std::fs::File::open(path)?;
    let reader = std::io::BufReader::new(file);
    let local_peer_set = serde_yml::from_reader(reader)?;
    Ok(local_peer_set)
}

pub fn save_config_file<P: AsRef<Path>>(path: P, ids: &LocalIdentitySet) -> Result<(), ServerError> {
    // Create directory path if required
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let file = std::fs::File::create(path)?;
    let writer = std::io::BufWriter::new(file);
    serde_yml::to_writer(writer, ids)?;
    Ok(())
}

pub fn load_or_create_identities(path: &PathBuf) -> Result<LocalIdentitySet, anyhow::Error> {
    match LocalIdentitySet::try_load(path) {
        Ok(local_identities) => Ok(local_identities),
        Err(ServerError::IoError(err)) => {
            if err.kind() == std::io::ErrorKind::NotFound {
                println!(
                    "No configuration file found at {}",
                    path.to_str().unwrap_or("[invalid utf-8 path]")
                );
                Ok(LocalIdentitySet::default())
            } else {
                Err(anyhow!("Error reading configuration file: {err}"))
            }
        }
        Err(err) => Err(anyhow!("Server error: {err}")),
    }
}

pub fn assign_identity(path: PathBuf, id_name: Option<&String>) -> Result<ConversationIdentity, anyhow::Error> {
    info!("Loading identities from {}", path.to_str().unwrap_or("[invalid utf-8 path]"));
    let mut local_identities = load_or_create_identities(&path)?;
    if local_identities.is_empty() {
        return Err(anyhow!("No identities found. Use `grease id new` to create one."));
    }
    // Get the specified identity or the first one.
    let identity = match id_name {
        Some(id_name) => local_identities.remove(id_name).ok_or_else(|| anyhow!("Identity not found: {id_name}"))?,
        None => local_identities.identities.into_values().next().unwrap(),
    };
    Ok(identity)
}
