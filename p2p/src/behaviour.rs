use crate::{GreaseRequest, GreaseResponse};
use libgrease::crypto::traits::PublicKey;
use libp2p::identify;
use libp2p::request_response::json;
use libp2p::swarm::NetworkBehaviour;

#[derive(NetworkBehaviour)]
pub struct ConnectionBehavior<P: PublicKey + Send + 'static> {
    pub(crate) identify: identify::Behaviour,
    pub(crate) json: json::Behaviour<GreaseRequest<P>, GreaseResponse<P>>,
}
