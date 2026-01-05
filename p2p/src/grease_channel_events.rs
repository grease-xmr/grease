use crate::behaviour::ConnectionBehavior;
use crate::event_loop::{ClientCommand, RemoteRequest};
use crate::{EventLoop, GreaseRequest, GreaseResponse};
use futures::channel::mpsc;
use libp2p::Swarm;

pub struct GreaseChannelEvents {
    events: EventLoop<GreaseRequest, GreaseResponse>,
}

impl GreaseChannelEvents {
    pub fn new(
        swarm: Swarm<ConnectionBehavior<GreaseRequest, GreaseResponse>>,
        command_receiver: mpsc::Receiver<ClientCommand<GreaseRequest, GreaseResponse>>,
        request_forwarder: mpsc::Sender<RemoteRequest<GreaseRequest, GreaseResponse>>,
    ) -> Self {
        let events = EventLoop::new(swarm, command_receiver, request_forwarder);
        Self { events }
    }

    pub async fn run(self) {
        self.events.run().await;
    }
}
