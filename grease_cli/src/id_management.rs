use crate::error::ServerError;
use grease_p2p::ChannelIdentity;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

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
