use anyhow::anyhow;
use clap::Parser;
use futures::StreamExt;
use grease_cli::config::{ChannelAction, ChannelCommand, CliCommand, Config, GlobalOptions, IdCommand, ServerCommand};
use grease_cli::error::ServerError;
use grease_cli::id_management::{default_id_path, LocalIdentitySet};
use grease_p2p::{new_connection, ChannelIdentity, PeerConnectionEvent};
use log::*;
use std::path::PathBuf;

#[tokio::main]
async fn main() {
    env_logger::init();
    let config: Config = Config::parse();
    let (global_options, command) = config.to_parts();

    let result = match command {
        CliCommand::Id(id_command) => exec_id_command(id_command, global_options),
        CliCommand::Serve(serve_command) => start_server(serve_command, global_options).await,
        CliCommand::Channel(channel_cmd) => exec_channel_command(channel_cmd, global_options).await,
    };

    match result {
        Ok(()) => {
            println!("Bye :)")
        }
        Err(err) => {
            eprintln!("** Error ** \n {err}");
            std::process::exit(1);
        }
    }
}

fn exec_id_command(cmd: IdCommand, config: GlobalOptions) -> Result<(), anyhow::Error> {
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

fn load_or_create_identities(path: &PathBuf) -> Result<LocalIdentitySet, anyhow::Error> {
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

async fn start_server(cmd: ServerCommand, config: GlobalOptions) -> Result<(), anyhow::Error> {
    info!("Starting server");
    let path = config.config_file.unwrap_or_else(default_id_path);
    let identity = assign_identity(path, config.id_name.as_ref())?;
    let (mut network_client, mut network_events, network_event_loop) = new_connection(identity.take_keypair()).await?;
    // Spawn the network task for it to run in the background.
    tokio::spawn(network_event_loop.run());
    network_client.start_listening(cmd.listen_address).await?;
    while let Some(ev) = network_events.next().await {
        trace!("Event received.");
        match ev {
            PeerConnectionEvent::InboundRequest { request, channel } => {
                debug!("Inbound request received: {request:?}")
                // handle the application logic for the request
                // call the client with the relevant command, passing the result and channel
            }
        }
    }
    info!("Server has shut down.");
    Ok(())
}

fn assign_identity(path: PathBuf, id_name: Option<&String>) -> Result<ChannelIdentity, anyhow::Error> {
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

async fn exec_channel_command(cmd: ChannelCommand, options: GlobalOptions) -> Result<(), anyhow::Error> {
    info!("Initiating channel command");
    let path = options.config_file.unwrap_or_else(default_id_path);
    let identity = assign_identity(path, options.id_name.as_ref())?;
    let (mut network_client, _network_events, network_event_loop) = new_connection(identity.take_keypair()).await?;
    // Spawn the network task for it to run in the background.
    tokio::spawn(network_event_loop.run());
    let server_addr = cmd.server_address;
    network_client.dial(server_addr).await?;
    match cmd.action {
        ChannelAction::List => {}
        ChannelAction::Open => {}
        ChannelAction::Send => {}
        ChannelAction::Close => {}
        ChannelAction::Dispute => {}
    }

    info!("Command completed.");
    Ok(())
}
