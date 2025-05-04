#![doc = include_str!("../README.md")]

use clap::{Args, Parser, Subcommand};
use grease_p2p::message_types::NewChannelProposal;
use libgrease::amount::MoneroAmount;
use libgrease::payment_channel::ChannelRole;
use libgrease::state_machine::Balances;
use libp2p::Multiaddr;
use std::path::PathBuf;

/// Grease Monero Payment Channels.
///
/// Payment channel management and command-line client for grease.
#[derive(Parser, Debug)]
#[command(version, about)]
pub struct Config {
    /// Path to the configuration file. The default is `$HOME/.grease/config.yml`.
    #[arg(long = "config-file", short = 'c')]
    pub config_file: Option<PathBuf>,
    /// Peer id name to use. If omitted, the first peer record in `$HOME/.grease/config.yml` is used.
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

pub struct GlobalOptions {
    pub config_file: Option<PathBuf>,
    pub id_name: Option<String>,
}

impl Config {
    pub fn to_parts(self) -> (GlobalOptions, CliCommand) {
        let global = GlobalOptions { config_file: self.config_file, id_name: self.id_name };
        (global, self.command)
    }
}
