use crate::errors::{PaymentChannelError, PeerConnectionError};
use crate::message_types::{
    ChannelProposalResult, NewChannelProposal, RejectChannelProposal, RejectReason, RetryOptions,
};
use crate::payment_channel::PaymentChannels;
use crate::{
    new_network, Client, ContactInfo, ConversationIdentity, GreaseChannelDelegate, GreaseRequest, GreaseResponse,
    KeyManager, PaymentChannel, PeerConnectionEvent,
};
use futures::future::join;
use futures::StreamExt;
use libgrease::crypto::traits::PublicKey;
use libgrease::kes::KeyEscrowService;
use libgrease::monero::MultiSigWallet;
use libgrease::payment_channel::ActivePaymentChannel;
use libgrease::state_machine::error::{InvalidProposal, LifeCycleError};
use libgrease::state_machine::{ChannelLifeCycle, LifecycleStage, NewChannelBuilder};
use libp2p::request_response::ResponseChannel;
use libp2p::Multiaddr;
use log::*;
use std::path::Path;
use tokio::sync::OwnedRwLockWriteGuard;
use tokio::task::JoinHandle;

pub type WritableState<P, C, W, KES> = OwnedRwLockWriteGuard<PaymentChannel<P, C, W, KES>>;

pub struct NetworkServer<P, C, W, KES, D, K>
where
    P: PublicKey,
    C: ActivePaymentChannel,
    W: MultiSigWallet,
    KES: KeyEscrowService,
    D: GreaseChannelDelegate<P, C, W, KES>,
    K: KeyManager,
{
    id: ConversationIdentity,
    inner: InnerEventHandler<P, C, W, KES, D, K>,
    event_loop_handle: JoinHandle<()>,
    event_handler_handle: JoinHandle<()>,
}

impl<P, C, W, KES, D, K> NetworkServer<P, C, W, KES, D, K>
where
    P: PublicKey + 'static,
    C: ActivePaymentChannel + 'static,
    W: MultiSigWallet + 'static,
    KES: KeyEscrowService + 'static,
    D: GreaseChannelDelegate<P, C, W, KES> + 'static,
    K: KeyManager<PublicKey = P> + Send + Sync + 'static,
{
    pub fn new(
        id: ConversationIdentity,
        channels: PaymentChannels<P, C, W, KES>,
        delegate: D,
        key_delegate: K,
    ) -> Result<Self, PeerConnectionError> {
        let keypair = id.keypair().clone();
        // Create a new network client and event loop.
        let (network_client, mut network_events, network_event_loop) = new_network::<P>(keypair)?;
        // Spawn the network task for it to run in the background.
        let event_loop_handle = tokio::spawn(network_event_loop.run());
        let inner = InnerEventHandler { network_client, channels, delegate, key_manager: key_delegate };
        let inner_clone = inner.clone();
        let event_handler_handle = tokio::spawn(async move {
            while let Some(ev) = network_events.next().await {
                trace!("libp2p network event received.");
                match ev {
                    PeerConnectionEvent::InboundRequest { request, response } => {
                        debug!("Inbound grease request received");
                        inner_clone.handle_incoming_grease_request(request, response).await;
                    }
                }
            }
        });
        Ok(Self { id, inner, event_loop_handle, event_handler_handle })
    }

    pub fn key_manager(&self) -> &K {
        &self.inner.key_manager
    }

    pub fn contact_info(&self) -> ContactInfo {
        self.id.contact_info()
    }

    pub async fn start_listening(&mut self, at: Multiaddr) -> Result<(), PeerConnectionError> {
        self.inner.start_listening(at).await
    }

    /// Provides a cheap clone of the network client. It is thread-safe.
    pub fn client(&self) -> Client<P> {
        self.inner.network_client.clone()
    }

    pub async fn list_channels(&self) -> Vec<String> {
        self.inner.channels.list_channels().await
    }

    pub async fn channel_status(&self, name: &str) -> Option<LifecycleStage> {
        self.inner.channels.try_peek(name).await.map(|channel| channel.state().stage())
    }

    pub async fn save_channels<Pth: AsRef<Path>>(&self, path: Pth) -> Result<(), PaymentChannelError> {
        self.inner.channels.save_channels(path).await
    }

    pub async fn add_channel(&self, channel: PaymentChannel<P, C, W, KES>) {
        self.inner.channels.add(channel).await
    }

    pub async fn shutdown(self) -> Result<bool, PeerConnectionError> {
        let res_client = self.inner.network_client.shutdown().await;
        let (res_loop, res_events) = join(self.event_loop_handle, self.event_handler_handle).await;
        if let Err(err) = res_loop.and(res_events) {
            error!("Error waiting on event threads: {err}");
        }
        res_client
    }

    pub async fn send_proposal(
        &self,
        secret: P::SecretKey,
        proposal: NewChannelProposal<P>,
    ) -> Result<Result<String, RejectChannelProposal>, PeerConnectionError> {
        let mut client = self.client();
        let address = proposal.contact_info_proposee.dial_address();
        // todo: check what happens if there's already a connection?
        client.dial(address).await?;
        debug!("Sending channel proposal to peer.");
        let state = self.create_new_state(secret, proposal.clone());
        let res = client.new_channel_proposal(proposal).await?;
        let result = match res {
            ChannelProposalResult::Accepted(final_proposal) => {
                // We got an ack, but the merchant may have changed the proposal, so we need to check.
                debug!("Channel proposal ACK received. Validating response.");
                let peer_info = final_proposal.contact_info_proposee.clone();
                let mut channel = PaymentChannel::new(peer_info, state);
                match channel.receive_proposal_ack(final_proposal.clone()) {
                    Ok(_) => info!("🥂 Channel proposal accepted."),
                    Err(err) => warn!("😢 We cannot accept the channel creation terms: {err}"),
                }
                let name = channel.name();
                // We add the channel evn if we're rejecting it, because the merchant may want to send messages related
                // to it, and we need to be able to remind ourselves of what happened.
                self.add_channel(channel).await;
                Ok(name)
            }
            ChannelProposalResult::Rejected(rej) => {
                warn!("Channel proposal rejected: {}", rej.reason);
                Err(rej)
            }
        };
        Ok(result)
    }

    fn create_new_state(&self, secret: P::SecretKey, prop: NewChannelProposal<P>) -> ChannelLifeCycle<P, C, W, KES> {
        let new_state = NewChannelBuilder::new(prop.seed.role, prop.proposer_pubkey, secret)
            .with_my_user_label(&prop.proposer_label)
            .with_peer_label(&prop.seed.user_label)
            .with_merchant_initial_balance(prop.seed.initial_balances.merchant)
            .with_customer_initial_balance(prop.seed.initial_balances.customer)
            .with_peer_public_key(prop.seed.pubkey)
            .with_kes_public_key(prop.seed.kes_public_key)
            .build::<blake2::Blake2b512>()
            .expect("Missing new channel state data");
        ChannelLifeCycle::New(Box::new(new_state))
    }
}

struct InnerEventHandler<P, C, W, KES, D, K>
where
    P: PublicKey,
    C: ActivePaymentChannel,
    W: MultiSigWallet,
    KES: KeyEscrowService,
    D: GreaseChannelDelegate<P, C, W, KES>,
    K: KeyManager,
{
    network_client: Client<P>,
    channels: PaymentChannels<P, C, W, KES>,
    delegate: D,
    key_manager: K,
}

impl<P, C, W, KES, D, K> Clone for InnerEventHandler<P, C, W, KES, D, K>
where
    P: PublicKey,
    C: ActivePaymentChannel,
    W: MultiSigWallet,
    KES: KeyEscrowService,
    D: GreaseChannelDelegate<P, C, W, KES>,
    K: KeyManager,
{
    fn clone(&self) -> Self {
        Self {
            network_client: self.network_client.clone(),
            channels: self.channels.clone(),
            delegate: self.delegate.clone(),
            key_manager: self.key_manager.clone(),
        }
    }
}

impl<P, C, W, KES, D, K> InnerEventHandler<P, C, W, KES, D, K>
where
    P: PublicKey,
    C: ActivePaymentChannel,
    W: MultiSigWallet,
    KES: KeyEscrowService,
    D: GreaseChannelDelegate<P, C, W, KES>,
    K: KeyManager<PublicKey = P>,
{
    async fn start_listening(&mut self, addr: Multiaddr) -> Result<(), PeerConnectionError> {
        self.network_client.start_listening(addr).await?;
        Ok(())
    }

    /// Business logic handling for payment channel requests.
    ///
    /// This function is called by the network event loop when a new inbound request is received.
    /// It takes the request, performs the relevant work, and then calls the appropriate method on the network client
    /// to respond.
    async fn handle_incoming_grease_request(
        &self,
        request: GreaseRequest<P>,
        return_chute: ResponseChannel<GreaseResponse<P>>,
    ) {
        let name = request.channel_name();
        let response = if self.channels.exists(&name).await {
            match self.channels.checkout(&name).await {
                Some(channel) => self.handle_pertinent_grease_request(request, channel).await,
                None => {
                    warn!("Channel exists, but we could not get a write lock: {name}");
                    GreaseResponse::Error("Could not get write lock".into())
                }
            }
        } else {
            // Channel doesn't exist, so this must be a new proposal, or we can´t do anything about it
            match &request {
                GreaseRequest::ProposeNewChannel(proposal) => self.handle_open_channel_request(proposal).await,
                _ => {
                    warn!("Request made for unknown channel: {name}");
                    GreaseResponse::ChannelNotFound
                }
            }
        };
        let mut client = self.network_client.clone();
        if let Err(err) = client.send_response_to_peer(response, return_chute).await {
            error!("Request was handled, but could not send response to peer: {err}");
        }
        // Response has been sent, now check to see if there's any work to do on the channel
        self.drive_channel_forward(name).await;
    }

    async fn handle_pertinent_grease_request(
        &self,
        request: GreaseRequest<P>,
        _channel: OwnedRwLockWriteGuard<PaymentChannel<P, C, W, KES>>,
    ) -> GreaseResponse<P> {
        match request {
            GreaseRequest::ProposeNewChannel(_) => {
                GreaseResponse::Error("Cannot create a new channel. Channel already exists.".into())
            }
            GreaseRequest::SendMoney => todo!("SendMoney"),
            GreaseRequest::RequestMoney => todo!("RequestMoney"),
            GreaseRequest::CloseChannel => todo!("CloseChannel"),
        }
    }

    async fn drive_channel_forward(&self, name: String) {
        if let Some(channel) = self.channels.checkout(&name).await {
            let stage = channel.state().stage();
            match stage {
                LifecycleStage::Establishing => {
                    self.establish_channel(name, channel).await;
                }
                _ => {
                    debug!("Nothing to do for channel {name} in state {stage}");
                }
            }
        } else {
            warn!("Channel does not exist: {name}");
        }
    }

    //---------------------------------------- State machine handling functions --------------------------------------//

    /// Handle an incoming request to open a payment channel.
    async fn handle_open_channel_request(&self, data: &NewChannelProposal<P>) -> GreaseResponse<P> {
        // Check that the public key passed in the proposal matches our keypair
        let (my_secret, my_pubkey) = match self.check_pubkey_matches(data) {
            Ok(keys) => keys,
            Err(err) => return err,
        };
        // Let the delegate do their checks
        let delegate = self.delegate.clone();
        if let Err(invalid) = delegate.verify_proposal(data) {
            let retry = RetryOptions::close_only();
            let rej = ChannelProposalResult::reject(RejectReason::InvalidProposal(invalid), retry);
            return GreaseResponse::ChannelProposalResult(rej);
        }
        // Construct the new channel
        let role = data.seed.role.other();
        // Reconstruct the new channel state from our point of view
        let new_state = NewChannelBuilder::new(role, my_pubkey, my_secret)
            .with_my_user_label(&data.seed.user_label)
            .with_peer_public_key(data.proposer_pubkey.clone())
            .with_customer_initial_balance(data.seed.initial_balances.customer)
            .with_merchant_initial_balance(data.seed.initial_balances.merchant)
            .with_peer_label(&data.proposer_label)
            .with_kes_public_key(data.seed.kes_public_key.clone())
            .build::<blake2::Blake2b512>()
            .expect("You've forgotten a field in the new state machine builder, dev");

        let state = ChannelLifeCycle::New(Box::new(new_state));
        let peer_info = data.contact_info_proposer.clone();
        let mut channel = PaymentChannel::new(peer_info, state);
        // Emit an `AckProposal` event on the channel
        if let Err(err) = channel.receive_proposal() {
            warn!("Channel proposal was not accepted by the state machine");
            let reason = match err {
                LifeCycleError::InvalidStateTransition => RejectReason::NotANewChannel,
                LifeCycleError::Proposal(invalid) => RejectReason::InvalidProposal(invalid),
            };
            return GreaseResponse::ChannelProposalResult(ChannelProposalResult::reject(
                reason,
                RetryOptions::close_only(),
            ));
        }
        self.channels.add(channel).await;
        let ack = ChannelProposalResult::accept(data.clone());
        GreaseResponse::ChannelProposalResult(ack)
    }

    async fn establish_channel(&self, name: String, channel: OwnedRwLockWriteGuard<PaymentChannel<P, C, W, KES>>) {
        info!("Establishing channel {name}");
    }

    //------------------------------------------- Minor helper functions ---------------------------------------------//
    /// Check that the public key passed in the proposal matches our keypair
    fn check_pubkey_matches(&self, data: &NewChannelProposal<P>) -> Result<(P::SecretKey, P), GreaseResponse<P>> {
        let my_pubkey = data.seed.pubkey.clone();
        let key_index = data.seed.key_id;
        let (my_secret, my_pubkey2) = self.key_manager.new_keypair(key_index);
        if my_pubkey == my_pubkey2 {
            Ok((my_secret, my_pubkey))
        } else {
            warn!("Public key in proposal does not match our keypair");
            Err(GreaseResponse::ChannelProposalResult(ChannelProposalResult::reject(
                RejectReason::InvalidProposal(InvalidProposal::MismatchedMerchantPublicKey),
                RetryOptions::close_only(),
            )))
        }
    }
}
