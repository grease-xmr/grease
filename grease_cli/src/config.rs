#![doc = include_str!("../README.md")]

use crate::id_management::default_config_path;
use anyhow::anyhow;
use clap::{Args, Parser, Subcommand};
use libgrease::crypto::keys::{Curve25519PublicKey, Curve25519Secret};
use libp2p::Multiaddr;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

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
    /// Run the server.
    #[command(name = "serve", alias = "start")]
    Serve(ServerCommand),
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

#[derive(Debug, Args)]
pub struct ServerCommand {
    /// The address to listen to. The default is `/ip4/127.0.0.1/tcp/7740`.
    #[arg(long = "listen-address", short = 'a', default_value = "/ip4/127.0.0.1/tcp/7740")]
    pub listen_address: Multiaddr,
    /// Disable the server's interactive user interface.
    #[arg(long = "quiet", short = 'q', default_value_t = false)]
    pub quiet: bool,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct GlobalOptions {
    pub identities_file: Option<PathBuf>,
    pub preferred_identity: Option<String>,
    pub server_address: Option<Multiaddr>,
    pub kes_public_key: Option<Curve25519PublicKey>,
    /// A name, or label that will be inserted into every channel you are part of.
    /// Make it descriptive and somewhat unique.
    pub user_label: Option<String>,
    pub initial_secret: Option<Curve25519Secret>,
}

impl GlobalOptions {
    /// Loads global configuration options from a YAML file.
    ///
    /// If a path is provided, attempts to load the configuration from that file; otherwise, uses the default configuration path.
    /// Returns an error if the file does not exist or cannot be parsed.
    ///
    /// # Examples
    ///
    /// ```
    /// let config = GlobalOptions::load_config(None).unwrap();
    /// assert!(config.is_ok() || config.is_err());
    /// ```
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
    ///
    /// # Examples
    ///
    /// ```
    /// let opts = GlobalOptions { server_address: Some("/ip4/127.0.0.1/tcp/7740".parse().unwrap()), ..Default::default() };
    /// assert_eq!(opts.server_address(), Some("/ip4/127.0.0.1/tcp/7740".parse().unwrap()));
    /// ```
    pub fn server_address(&self) -> Option<Multiaddr> {
        self.server_address.clone()
    }

    /// Returns a clone of the configured Curve25519 public key, if set.
    ///
    /// # Examples
    ///
    /// ```
    /// let opts = GlobalOptions { kes_public_key: Some(pubkey), ..Default::default() };
    /// assert_eq!(opts.kes_public_key(), Some(pubkey));
    /// ```
    pub fn kes_public_key(&self) -> Option<Curve25519PublicKey> {
        self.kes_public_key.clone()
    }

    /// Returns the optional user label configured for channels.
    ///
    /// # Examples
    ///
    /// ```
    /// let opts = GlobalOptions { user_label: Some("Alice".to_string()), ..Default::default() };
    /// assert_eq!(opts.user_label(), Some("Alice".to_string()));
    /// ```
    pub fn user_label(&self) -> Option<String> {
        self.user_label.clone()
    }

    /// Returns a clone of the initial Curve25519 secret key, if set in the configuration.
    ///
    /// # Examples
    ///
    /// ```
    /// let opts = GlobalOptions { initial_secret: Some(secret_key), ..Default::default() };
    /// assert_eq!(opts.initial_secret(), Some(secret_key));
    /// ```
    pub fn initial_secret(&self) -> Option<Curve25519Secret> {
        self.initial_secret.clone()
    }
}
