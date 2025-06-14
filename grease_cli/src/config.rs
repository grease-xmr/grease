#![doc = include_str!("../README.md")]

use anyhow::anyhow;
use clap::{Parser, Subcommand};
use libgrease::crypto::keys::Curve25519Secret;
use libgrease::crypto::zk_objects::GenericPoint;
use libp2p::Multiaddr;
use monero::Address;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::str::FromStr;

const DEFAULT_LISTEN_ADDRESS: &str = "/ip4/127.0.0.1/tcp/";

//------------------------------------  DEFAULTS ------------------------------------
pub fn default_listen_address(index: u8) -> Multiaddr {
    Multiaddr::from_str(&format!("{DEFAULT_LISTEN_ADDRESS}{}", 21_000 + index as u16))
        .expect("Invalid default listen address")
}

/// Grease Monero Payment Channels.
///
/// Payment channel management and command-line client for grease.
#[derive(Parser, Debug)]
#[command(version, about)]
pub struct CliOptions {
    /// Path to the configuration file. The default is `$HOME/.grease/config.yml`.
    #[arg(long = "config-file", short = 'c')]
    pub config_file: Option<PathBuf>,
    /// P2P identity to use. If omitted, the first record in the identity database is used.
    #[arg(long = "id")]
    pub id_name: Option<String>,
    #[command(subcommand)]
    pub command: CliCommand,
}

#[derive(Debug, Subcommand)]
pub enum CliCommand {
    /// Add, list or delete local peer identities.
    #[command(subcommand, name = "id")]
    Id(IdCommand),
    /// Print a random keypair and quit. The secret key can be used in the `initial_secret` field of the config file.
    #[command(name = "keypair")]
    Keypair,
    /// Run the server.
    #[command(name = "serve", alias = "start")]
    Serve,
}

#[derive(Debug, Subcommand)]
pub enum IdCommand {
    /// Create a new peer identity.
    #[command(name = "new", alias = "create")]
    Create {
        /// The name of the new peer identity. If omitted, a random name is generated.
        name: Option<String>,
    },
    /// List all peer identities.
    #[command(name = "list", alias = "ls")]
    List,
    /// Delete a peer identity.
    #[command(name = "delete", alias = "del", alias = "rm")]
    Delete {
        /// The id of the peer identity to delete.
        id: String,
    },
}

#[derive(Debug, Deserialize, Serialize)]
pub struct GlobalOptions {
    /// The path to the configuration file. If not set, defaults to `$HOME/.grease/config.yml`.
    pub base_path: Option<PathBuf>,
    /// The path to the identity database. If not set, defaults to `$HOME/.grease/identities.yml`.
    pub identities_file: Option<PathBuf>,
    /// The default identity to use when creating new channels.
    pub preferred_identity: Option<String>,
    /// The address other parties can use to contact this identity on the internet.
    pub server_address: Option<Multiaddr>,
    /// The public key of the Key Escrow Service (KES).
    pub kes_public_key: Option<GenericPoint>,
    /// A name, or label that will be inserted into every channel you are part of.
    /// Make it descriptive and unique.
    pub user_label: Option<String>,
    pub initial_secret: Option<Curve25519Secret>,
    /// The folder where channels are stored.
    /// `channel_storage_directory` can be a relative or absolute path. If relative, it is a subdirectory of the
    /// `base_path`.
    pub channel_storage_directory: Option<PathBuf>,
    /// The address of the wallet that will receive funds on channel closures.
    pub refund_address: Option<Address>,
}

impl GlobalOptions {
    /// Loads global configuration options from a YAML file.
    ///
    /// If a path is provided, attempts to load the configuration from that file; otherwise, uses the default configuration path.
    /// Returns an error if the file does not exist or cannot be parsed.
    pub fn load_config<F: AsRef<Path>>(path: Option<F>) -> Result<Self, anyhow::Error> {
        let path = path.map(|p| p.as_ref().to_path_buf()).unwrap_or_else(default_config_path);
        if !path.exists() {
            return Err(anyhow!("Configuration file not found: {}", path.display()));
        }
        let file = std::fs::File::open(path)?;
        let reader = std::io::BufReader::new(file);
        let config = serde_yml::from_reader(reader)?;
        Ok(config)
    }

    /// Returns a clone of the configured server listening address, if set.
    pub fn server_address(&self) -> Option<Multiaddr> {
        self.server_address.clone()
    }

    /// Returns a clone of the configured Curve25519 public key, if set.
    pub fn kes_public_key(&self) -> Option<GenericPoint> {
        self.kes_public_key.clone()
    }

    /// Returns the address to which channel refunds will be sent.
    pub fn refund_address(&self) -> Option<Address> {
        self.refund_address
    }

    /// Returns the optional user label configured for channels.
    pub fn user_label(&self) -> Option<String> {
        self.user_label.clone()
    }

    /// The base path for grease configuration files and stored state, such as identities and channels.
    pub fn base_path(&self) -> PathBuf {
        self.base_path.clone().unwrap_or_else(|| {
            let mut path = std::env::home_dir().unwrap_or_else(|| PathBuf::from("."));
            path.push(".grease");
            path
        })
    }

    /// Returns the absolute path to the channel storage directory.
    ///
    /// It is derived from `base_path` and `channel_storage_directory`.
    /// If `channel_storage_directory` is relative, it is joined with `base_path`.
    /// If `channel_storage_directory` is absolute, it is returned as is.
    ///
    /// If `channel_storage_directory` is not set, it defaults to `{base_path}/channels`.
    pub fn channel_directory(&self) -> PathBuf {
        let channel_dir = self.channel_storage_directory.as_ref().cloned().unwrap_or_else(|| "channels".into());
        if channel_dir.is_relative() {
            self.base_path().join(channel_dir)
        } else {
            channel_dir
        }
    }

    /// Returns a clone of the initial Curve25519 secret key, if set in the configuration.
    pub fn initial_secret(&self) -> Option<Curve25519Secret> {
        self.initial_secret.clone()
    }
}

/// Returns the default path to the configuration file, typically `$HOME/.grease/config.yml`.
///
/// If the home directory cannot be determined, the path defaults to `./.grease/config.yml`.
pub fn default_config_path() -> PathBuf {
    let mut home = std::env::home_dir().unwrap_or_else(|| PathBuf::from("."));
    home.push(".grease");
    home.push("config.yml");
    home
}
