use crate::config::{GlobalOptions, ServerCommand};
use crate::id_management::{assign_identity, default_id_path};
use futures::StreamExt;
use grease_p2p::errors::PeerConnectionError;
use grease_p2p::message_types::{AckChannelProposal, NewChannelProposal};
use grease_p2p::{new_connection, Client, GreaseRequest, GreaseResponse, PeerConnectionEvent};
use libp2p::request_response::ResponseChannel;
use log::{debug, error, info, trace};

pub async fn start_server(cmd: ServerCommand, config: GlobalOptions) -> Result<(), anyhow::Error> {
    info!("Starting server");
    let path = config.config_file.unwrap_or_else(default_id_path);
    let identity = assign_identity(path, config.id_name.as_ref())?;
    let (mut network_client, mut network_events, network_event_loop) = new_connection(identity.take_keypair()).await?;
    // Spawn the network task for it to run in the background.
    let handle = tokio::spawn(network_event_loop.run());
    network_client.start_listening(cmd.listen_address).await?;
    while let Some(ev) = network_events.next().await {
        trace!("Event received.");
        match ev {
            PeerConnectionEvent::InboundRequest { request, channel } => {
                debug!("Inbound request received: {request:?}");
                let client = network_client.clone();
                tokio::spawn(async move {
                    handle_incoming_grease_request(request, client, channel).await;
                });
            }
        }
    }
    handle.await?;
    info!("Server has shut down.");
    Ok(())
}

/// Business logic handling for payment channel requests.
///
/// This function is called by the network event loop when a new inbound request is received.
/// It takes the request, performs the relevant work, and then calls the appropriate method on the network client
/// to respond.
pub async fn handle_incoming_grease_request(
    request: GreaseRequest,
    client: Client,
    channel: ResponseChannel<GreaseResponse>,
) {
    let result = match request {
        GreaseRequest::ProposeNewChannel(data) => handle_open_channel_request(data, client, channel).await,
        GreaseRequest::SendMoney => todo!("SendMoney"),
        GreaseRequest::RequestMoney => todo!("RequestMoney"),
        GreaseRequest::CloseChannel => todo!("CloseChannel"),
    };
    if let Err(err) = result {
        error!("Error handling request: {err}");
    }
}

/// Handle an incoming request to open a payment channel.
pub async fn handle_open_channel_request(
    data: NewChannelProposal,
    mut client: Client,
    channel: ResponseChannel<GreaseResponse>,
) -> Result<(), PeerConnectionError> {
    // Perform the necessary work to open a channel.
    // For now, we'll just return a successful response.
    let success = AckChannelProposal { data };
    client.send_channel_proposal_response(Ok(success), channel).await
}
