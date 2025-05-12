use crate::config::{default_config_path, GlobalOptions, IdCommand};
use crate::error::ServerError;
use anyhow::anyhow;
use grease_p2p::{ConversationIdentity, KeyManager};
use libgrease::crypto::hashes::{Blake512, HashToScalar};
use libgrease::crypto::keys::{Curve25519PublicKey, Curve25519Secret};
use libgrease::crypto::traits::PublicKey;
use log::{debug, info};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

#[derive(Clone)]
pub struct MoneroKeyManager {
    initial_key: Curve25519Secret,
    initial_public_key: Curve25519PublicKey,
}

impl KeyManager for MoneroKeyManager {
    type PublicKey = Curve25519PublicKey;
    /// Creates a new `KeyManager` from the given Curve25519 secret key, deriving its corresponding public key.
    fn new(initial_key: Curve25519Secret) -> Self {
        let initial_public_key = Curve25519PublicKey::from_secret(&initial_key);
        MoneroKeyManager { initial_key, initial_public_key }
    }

    /// Deterministically generates a Curve25519 keypair based on the initial secret key and a given index.
    ///
    /// The resulting keypair is derived by hashing the initial secret scalar and the provided index,
    /// ensuring that the same inputs always produce the same keypair. This is useful for generating
    /// multiple related keys from a single root secret.
    ///
    /// # Parameters
    /// - `index`: The index used to derive a unique keypair from the initial secret.
    ///
    /// # Returns
    /// A tuple containing the derived secret key and its corresponding public key.
    fn new_keypair(&self, index: u64) -> (Curve25519Secret, Curve25519PublicKey) {
        let secret = self.initial_key.as_scalar().as_bytes();
        let mut buf = [0u8; 40];
        buf[0..32].copy_from_slice(secret);
        buf[32..40].copy_from_slice(&index.to_le_bytes());
        let scalar = Blake512::default().hash_to_scalar(&buf);
        let next_key = Curve25519Secret::from(scalar);
        let next_public_key = Curve25519PublicKey::from_secret(&next_key);
        (next_key, next_public_key)
    }

    fn initial_public_key(&self) -> &Curve25519PublicKey {
        &self.initial_public_key
    }

    fn validate_keypair(&self, secret: &Curve25519Secret, public: &Curve25519PublicKey) -> bool {
        let pub2 = Curve25519PublicKey::from_secret(secret);
        &pub2 == public
    }
}

/// Executes an identity management command, handling creation, listing, or deletion of conversation identities.
///
/// Depending on the provided `IdCommand` variant, this function creates a new identity, lists all existing identity IDs, or deletes a specified identity. Output is printed to standard output for user feedback.
///
/// # Returns
///
/// Returns `Ok(())` if the command completes successfully, or an error if any operation fails.
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

/// Deletes a conversation identity by ID from the local identities file.
///
/// Returns `Ok(true)` if the identity was found and deleted, or `Ok(false)` if no such identity exists. Updates the identities file on successful deletion.
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

/// Creates and saves a new conversation identity, optionally with a specified ID.
///
/// If a name is provided, generates a random identity using that name as its ID; otherwise, generates a random identity with an automatically assigned ID. Fails if an identity with the same ID already exists. The new identity is persisted to the configured identities file.
///
/// # Errors
///
/// Returns an error if the identity ID already exists or if there is a failure loading or saving the identities file.
pub fn create_identity(config: &GlobalOptions, name: Option<String>) -> Result<ConversationIdentity, anyhow::Error> {
    let path = config.identities_file.as_ref().cloned().unwrap_or_else(default_config_path);
    let mut local_identities = load_or_create_identities(&path)?;
    let addr = config.server_address.as_ref().ok_or_else(|| anyhow!("The config file needs a listener address."))?;
    let identity = match name {
        Some(name) => ConversationIdentity::random_with_id(name.clone(), addr.clone()),
        None => ConversationIdentity::random(addr.clone()),
    };
    if local_identities.contains(identity.id()) {
        return Err(anyhow!("Identity with id {} already exists.", identity.id()));
    }
    local_identities.insert(identity.id().to_string(), identity.clone());
    info!("Saving identities to {}", path.to_str().unwrap_or("[invalid utf-8 path]"));
    local_identities.save(&path)?;
    Ok(identity)
}

/// Returns a list of all stored conversation identity IDs.
///
/// Loads the local identities from the configured file path and collects their IDs as strings.
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
    /// Loads a `LocalIdentitySet` from the specified file path.
    ///
    /// Returns an error if the file cannot be read or deserialized.
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

    /// Checks whether an identity with the specified ID exists in the set.
    pub fn contains(&self, id: &str) -> bool {
        self.identities.contains_key(id)
    }

    /// Retrieves a reference to a conversation identity by its ID, if it exists.
    pub fn get(&self, id: &str) -> Option<&ConversationIdentity> {
        self.identities.get(id)
    }

    /// Inserts a conversation identity with the specified ID, replacing any existing identity with the same ID.
    ///
    /// Returns the previous identity associated with the ID if it existed, or `None` if the ID was not present.
    pub fn insert(&mut self, id: String, identity: ConversationIdentity) -> Option<ConversationIdentity> {
        self.identities.insert(id, identity)
    }

    /// Returns an iterator over the IDs of all stored conversation identities.
    pub fn ids(&self) -> impl Iterator<Item = &String> {
        self.identities.keys()
    }

    /// Returns an iterator over all stored conversation identities.
    pub fn identities(&self) -> impl Iterator<Item = &ConversationIdentity> {
        self.identities.values()
    }

    /// Removes and returns the identity associated with the given ID, if it exists.
    pub fn remove<S: AsRef<str>>(&mut self, id: S) -> Option<ConversationIdentity> {
        self.identities.remove(id.as_ref())
    }
}

/// Loads a set of conversation identities from a YAML file.
///
/// Attempts to open and deserialize the specified file into a `LocalIdentitySet`.
pub fn load_identities_file<P: AsRef<Path>>(path: P) -> Result<LocalIdentitySet, ServerError> {
    let file = std::fs::File::open(path)?;
    let reader = std::io::BufReader::new(file);
    let local_peer_set = serde_yml::from_reader(reader)?;
    Ok(local_peer_set)
}

/// Saves the provided set of conversation identities to a YAML file at the specified path.
///
/// Creates any necessary parent directories if they do not exist. Overwrites the file if it already exists.
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

/// Loads a set of local conversation identities from the specified path, or creates an empty set if the file does not exist.
///
/// If the file at the given path is missing, returns a new, empty `LocalIdentitySet`. Other I/O or server errors are returned as `anyhow::Error`.
pub fn load_or_create_identities<P: AsRef<Path>>(path: P) -> Result<LocalIdentitySet, anyhow::Error> {
    match LocalIdentitySet::try_load(&path) {
        Ok(local_identities) => Ok(local_identities),
        Err(ServerError::IoError(err)) => {
            if err.kind() == std::io::ErrorKind::NotFound {
                println!("No configuration file found at {}", path.as_ref().display());
                Ok(LocalIdentitySet::default())
            } else {
                Err(anyhow!("Error reading configuration file: {err}"))
            }
        }
        Err(err) => Err(anyhow!("Server error: {err}")),
    }
}

/// Selects and removes a conversation identity from the local identity set.
///
/// Loads identities from the specified path and returns the identity matching the given name, or the first available identity if no name is provided. Returns an error if no identities exist or if the specified identity is not found.
pub fn assign_identity<P: AsRef<Path>>(
    path: P,
    id_name: Option<&String>,
) -> Result<ConversationIdentity, anyhow::Error> {
    let path = path.as_ref();
    info!("Loading identities from {}", path.display());
    let mut local_identities = load_or_create_identities(path)?;
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
