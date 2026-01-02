use libp2p::identify;
use libp2p::request_response::json;
use libp2p::swarm::NetworkBehaviour;
use serde::de::DeserializeOwned;
use serde::Serialize;

#[derive(NetworkBehaviour)]
pub struct ConnectionBehavior<Req, Resp>
where
    Req: DeserializeOwned + Serialize + Send + 'static,
    Resp: DeserializeOwned + Serialize + Send + 'static,
{
    pub(crate) identify: identify::Behaviour,
    pub(crate) json: json::Behaviour<Req, Resp>,
}
