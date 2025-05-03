use crate::config::{ChannelAction, ChannelCommand, GlobalOptions};
use crate::id_management::{assign_identity, default_id_path};
use anyhow::anyhow;
use grease_p2p::new_connection;
use log::*;

pub async fn exec_channel_command(cmd: ChannelCommand, options: GlobalOptions) -> Result<(), anyhow::Error> {
    info!("Initiating channel command");
    let path = options.config_file.unwrap_or_else(default_id_path);
    let identity = assign_identity(path, options.id_name.as_ref())?;
    let (mut network_client, _network_events, network_event_loop) = new_connection(identity.take_keypair()).await?;
    // Spawn the network task for it to run in the background.
    tokio::spawn(network_event_loop.run());
    let server_addr = cmd.server_address;
    info!("Dialing remote server");
    network_client.dial(server_addr).await?;
    info!("Remote server connected");
    let mut peers = network_client.connected_peers().await?;
    if peers.is_empty() {
        return Err(anyhow!("Remote peer list is empty after a successful dial. Data race?"));
    }
    let peer_id = peers.remove(0);
    match cmd.action {
        ChannelAction::List => {}
        ChannelAction::Open { .. } => {
            let channel_data = cmd.action.extract_new_channel_data().expect("action to be Open");
            println!(
                "Creating new channel with initial balance {} : {}",
                channel_data.initial_balances.customer, channel_data.initial_balances.merchant
            );
            let result = network_client.new_channel_proposal(peer_id, channel_data).await?;
            match result {
                Ok(success) => {
                    println!(
                        "New channel open: {}. My balance: {}, Their balance: {}",
                        success.data.channel_name,
                        success.data.initial_balances.customer,
                        success.data.initial_balances.merchant
                    )
                }
                Err(err) => {
                    println!("Could not open channel. {:?}", err.reason)
                }
            }
        }
        ChannelAction::Send => {}
        ChannelAction::Close => {}
        ChannelAction::Dispute => {}
    }

    info!("Command completed.");
    network_client.shutdown().await?;
    Ok(())
}
