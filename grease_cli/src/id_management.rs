use crate::config::{GlobalOptions, IdCommand};
use crate::error::ServerError;
use anyhow::anyhow;
use grease_p2p::ChannelIdentity;
use log::info;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

pub fn exec_id_command(cmd: IdCommand, config: GlobalOptions) -> Result<(), anyhow::Error> {
    match cmd {
        IdCommand::Create { name } => {
            let path = config.config_file.as_ref().cloned().unwrap_or_else(default_id_path);
            let mut local_identities = load_or_create_identities(&path)?;
            let identity = match name {
                Some(name) => ChannelIdentity::random_with_id(name.clone()),
                None => ChannelIdentity::random(),
            };
            if local_identities.contains(identity.id()) {
                return Err(anyhow!("Identity with id {} already exists.", identity.id()));
            }
            println!("Identity created: {identity}");
            local_identities.insert(identity.id().to_string(), identity);
            println!("Saving identities to {}", path.to_str().unwrap_or("[invalid utf-8 path]"));
            local_identities.save(&path)?;
        }
        IdCommand::List => {
            let path = config.config_file.as_ref().cloned().unwrap_or_else(default_id_path);
            let local_identities = load_or_create_identities(&path)?;
            println!("{} Local identities found.", local_identities.identities.len());
            for (_, id) in local_identities.identities {
                println!("{id}");
            }
        }
        IdCommand::Delete { id } => {
            let path = config.config_file.as_ref().cloned().unwrap_or_else(default_id_path);
            let mut local_identities = load_or_create_identities(&path)?;
            match local_identities.remove(&id) {
                Some(identity) => {
                    println!("Identity deleted: {identity}");
                    local_identities.save(&path)?;
                }
                None => {
                    return Err(anyhow!("Identity with id {} not found.", id));
                }
            }
        }
    }
    Ok(())
}
#[derive(Debug, Default, Deserialize, Serialize)]
pub struct LocalIdentitySet {
    pub identities: HashMap<String, ChannelIdentity>,
}

impl LocalIdentitySet {
    pub fn try_load<P: AsRef<Path>>(path: Option<P>) -> Result<Self, ServerError> {
        let ids = load_config_file(path)?;
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

    pub fn get(&self, id: &str) -> Option<&ChannelIdentity> {
        self.identities.get(id)
    }

    pub fn insert(&mut self, id: String, identity: ChannelIdentity) -> Option<ChannelIdentity> {
        self.identities.insert(id, identity)
    }

    pub fn remove<S: AsRef<str>>(&mut self, id: S) -> Option<ChannelIdentity> {
        self.identities.remove(id.as_ref())
    }
}

pub fn default_id_path() -> PathBuf {
    let mut home = std::env::home_dir().unwrap_or_else(|| PathBuf::from("."));
    home.push(".grease");
    home.push("config.yml");
    home
}

pub fn load_config_file<P: AsRef<Path>>(path: Option<P>) -> Result<LocalIdentitySet, ServerError> {
    let path = path.map(|p| p.as_ref().to_path_buf()).unwrap_or_else(default_id_path);
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
    match LocalIdentitySet::try_load(Some(&path)) {
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

pub fn assign_identity(path: PathBuf, id_name: Option<&String>) -> Result<ChannelIdentity, anyhow::Error> {
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
