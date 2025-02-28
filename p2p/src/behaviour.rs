use crate::{GreaseRequest, GreaseResponse};
use libp2p::identify;
use libp2p::request_response::json;
use libp2p::swarm::NetworkBehaviour;

#[derive(NetworkBehaviour)]
pub struct ConnectionBehavior {
    pub(crate) identify: identify::Behaviour,
    pub(crate) json: json::Behaviour<GreaseRequest, GreaseResponse>,
}
