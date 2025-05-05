use crate::config::{GlobalOptions, ServerCommand};
use crate::id_management::{assign_identity, default_config_path};
use crate::interactive::InteractiveApp;
use futures::StreamExt;
use grease_p2p::errors::PeerConnectionError;
use grease_p2p::message_types::{AckChannelProposal, NewChannelProposal};
use grease_p2p::{new_connection, Client, GreaseRequest, GreaseResponse, PeerConnectionEvent};
use libp2p::request_response::ResponseChannel;
use log::{debug, error, info, trace};

pub const APP_NAME: &str = env!("CARGO_PKG_NAME");

/// Starts the peer-to-peer payment channel server or runs the interactive application.
///
/// If the `quiet` flag is set in the server command, initializes the server with the specified identity and configuration, establishes a network connection, listens for incoming peer requests, and handles them asynchronously. Otherwise, launches the interactive command-line application.
///
/// # Returns
///
/// Returns `Ok(())` if the server or interactive application completes successfully, or an error if initialization or network operations fail.
///
/// # Examples
///
/// ```
/// let cmd = ServerCommand { quiet: true, listen_address: "127.0.0.1:8080".parse().unwrap() };
/// let config = GlobalOptions::default();
/// tokio::spawn(async move {
///     start_server(cmd, config).await.unwrap();
/// });
/// ```
pub async fn start_server(cmd: ServerCommand, config: GlobalOptions) -> Result<(), anyhow::Error> {
    info!("Starting server");
    if cmd.quiet {
        let path = config.identities_file.unwrap_or_else(default_config_path);
        let identity = assign_identity(path, config.preferred_identity.as_ref())?;
        let (mut network_client, mut network_events, network_event_loop) =
            new_connection(identity.take_keypair()).await?;
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
    } else {
        // If the user has not specified a command, run the interactive app.
        run_interactive(config).await;
    }
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

async fn run_interactive(global_options: GlobalOptions) {
    println!(
        "No command given. If this was unintended, enter `CTRL-C` to exit and run `{APP_NAME} --help` to see a full \
         list of commands."
    );
    let mut app = InteractiveApp::new(global_options);
    match app.run().await {
        Ok(_) => println!("Bye!"),
        Err(e) => error!("Session ended with error: {}", e),
    }
}
