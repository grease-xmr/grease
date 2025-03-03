use grease_p2p::errors::PeerConnectionError;
use grease_p2p::message_types::{NewChannelData, OpenChannelSuccess};
use grease_p2p::{Client, GreaseRequest, GreaseResponse};
use libp2p::request_response::ResponseChannel;
use log::error;

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
        GreaseRequest::OpenChannel(data) => handle_open_channel_request(data, client, channel).await,
        GreaseRequest::SendMoney => todo!("SendMoney"),
        GreaseRequest::RequestMoney => todo!("RequestMoney"),
        GreaseRequest::CloseChannel => todo!("CloseChannel"),
    };
    if let Err(err) = result {
        error!("Error handling request: {err}");
        //todo - retry logic
    }
}

/// Handle an incoming request to open a payment channel.
pub async fn handle_open_channel_request(
    data: NewChannelData,
    mut client: Client,
    channel: ResponseChannel<GreaseResponse>,
) -> Result<(), PeerConnectionError> {
    // Perform the necessary work to open a channel.
    // For now, we'll just return a successful response.
    let success = OpenChannelSuccess { channel_id: 1, data };
    client.open_channel_response(Ok(success), channel).await
}
