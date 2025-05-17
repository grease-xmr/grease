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
use futures::stream::Next;
use futures::StreamExt;
use libgrease::channel_id::ChannelId;
use libgrease::crypto::traits::PublicKey;
use libgrease::kes::KeyEscrowService;
use libgrease::monero::data_objects::RequestEnvelope;
use libgrease::monero::{MultiSigWallet, WalletState};
use libgrease::payment_channel::{ActivePaymentChannel, ChannelRole};
use libgrease::state_machine::error::{InvalidProposal, LifeCycleError};
use libgrease::state_machine::{ChannelLifeCycle, LifecycleStage, NewChannelBuilder};
use libp2p::request_response::ResponseChannel;
use libp2p::Multiaddr;
use log::*;
use std::collections::VecDeque;
use std::future;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::{OwnedRwLockWriteGuard, RwLock};
use tokio::task::JoinHandle;

pub type WritableState<P, C, W, KES> = OwnedRwLockWriteGuard<PaymentChannel<P, C, W, KES>>;

macro_rules! abort {
    ($channel_name:expr, $msg:expr) => {{
        use crate::server::NextAction;
        warn!("{}", $msg);
        NextAction::Abort {
            channel_name: $channel_name.to_string(),
            reason: format!("Aborting {}. Reason: {}", $channel_name, $msg),
        }}
    };
    ($channel_name:expr, $fmt:literal, $($args:tt)*) => {{
        let msg = format!($fmt, $($args)*);
        abort!($channel_name, msg)
    }};
}

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
        let inner = InnerEventHandler::new(network_client, channels, delegate, key_delegate);
        let mut inner_clone = inner.clone();
        let event_handler_handle = tokio::spawn(async move {
            while let Some(ev) = network_events.next().await {
                trace!("libp2p network event received.");
                match ev {
                    PeerConnectionEvent::InboundRequest { request, response } => {
                        debug!("Inbound grease request received");
                        inner_clone.handle_incoming_grease_request(request, response).await;
                    }
                }
                // Carry out any pending tasks
                inner_clone.clear_todo_list().await;
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
                match channel.receive_proposal_ack(final_proposal.clone()).await {
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
    todo_list: Arc<RwLock<VecDeque<TodoListItem>>>,
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
            todo_list: Arc::clone(&self.todo_list),
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
    fn new(client: Client<P>, channels: PaymentChannels<P, C, W, KES>, delegate: D, key_manager: K) -> Self {
        Self {
            network_client: client,
            channels,
            delegate,
            key_manager,
            todo_list: Arc::new(RwLock::new(VecDeque::new())),
        }
    }

    async fn add_todo_list_item(&self, item: TodoListItem) {
        debug!("🖥️  Adding item to todo list: {item:?}");
        let mut write_lock = self.todo_list.write().await;
        write_lock.push_back(item);
        drop(write_lock);
    }

    async fn add_todo_list_items(&self, items: impl IntoIterator<Item = TodoListItem>) {
        trace!("🖥️  Adding items to todo list");
        let mut write_lock = self.todo_list.write().await;
        write_lock.extend(items);
        drop(write_lock);
    }

    async fn get_next_todo_list_item(&self) -> Option<TodoListItem> {
        let mut write_lock = self.todo_list.write().await;
        let next_item = write_lock.pop_front();
        drop(write_lock);
        next_item
    }

    async fn clear_todo_list(&mut self) {
        while let Some(next_item) = self.get_next_todo_list_item().await {
            let next = match next_item {
                TodoListItem::CreateMultiSigWallet { channel_name } => self.prepare_multisig_wallet(channel_name).await,
                TodoListItem::CreateNewKes { channel_name } => self.create_kes(channel_name).await,
                TodoListItem::ConstructFundingTransaction { channel_name } => {
                    self.create_funding_transaction(channel_name).await
                }
                TodoListItem::CloseChannel { channel_name, reason } => self.close_channel(channel_name, reason).await,
            };
            match next {
                NextAction::Continue => trace!("🖥️  Todo item completed successfully"),
                NextAction::Ignore => trace!("🖥️  Todo item errored out, but we're ignoring it"),
                NextAction::Abort { channel_name, reason } => {
                    debug!("🖥️  Aborting channel: {reason}");
                    let item = TodoListItem::CloseChannel { channel_name, reason };
                    self.add_todo_list_item(item).await;
                }
            }
        }
    }

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
                Some(channel) => self.handle_grease_request_for_existing_channel(request, channel).await,
                None => {
                    warn!("🖥️  Channel exists, but we could not get a write lock: {name}");
                    GreaseResponse::Error("Could not get write lock".into())
                }
            }
        } else {
            // Channel doesn't exist, so this must be a new proposal, or we can´t do anything about it
            match &request {
                GreaseRequest::ProposeNewChannel(proposal) => self.handle_open_channel_request(proposal).await,
                _ => {
                    warn!("🖥️  Request made for unknown channel: {name}");
                    GreaseResponse::ChannelNotFound
                }
            }
        };
        let mut client = self.network_client.clone();
        if let Err(err) = client.send_response_to_peer(response, return_chute).await {
            error!("🖥️  Request was handled, but could not send response to peer: {err}");
        }
    }

    async fn handle_grease_request_for_existing_channel(
        &self,
        request: GreaseRequest<P>,
        mut channel: OwnedRwLockWriteGuard<PaymentChannel<P, C, W, KES>>,
    ) -> GreaseResponse<P> {
        // Note: The channel name has already been checked against the incoming message.
        match request {
            GreaseRequest::ProposeNewChannel(_) => {
                GreaseResponse::Error("Cannot create a new channel. Channel already exists.".into())
            }
            GreaseRequest::MsInit(envelope) => {
                trace!("🖥️  Multisig Init request received");
                let (channel_name, peer_info) = envelope.open();
                if let Err(err) = channel.wallet_preparation(|wallet_state| wallet_state.prepare_multisig()).await {
                    warn!("🖥️  Error preparing multisig wallet: {err}");
                    return GreaseResponse::MsInit(Err("Customer could not create wallet".into()));
                }
                trace!("🖥️  Customer: Multisig wallet prepared");
                let Some(my_info) = channel.wallet_state().ok().and_then(|s| s.init_info().cloned()) else {
                    return GreaseResponse::MsInit(Err("Customer could not generate initialization info".into()));
                };
                // Add customer's peer info and make multisig wallet
                if let Err(err) =
                    channel.wallet_preparation(|wallet_state| Box::pin(wallet_state.make_multisig(peer_info))).await
                {
                    warn!("🖥️  Error making multisig wallet: {err}");
                    return GreaseResponse::MsInit(Err("Customer could not create wallet".into()));
                }
                trace!("🖥️  Customer: Multisig wallet made. Returning init info to merchant");
                let envelope = RequestEnvelope::new(channel_name, my_info);
                GreaseResponse::MsInit(Ok(envelope))
            }
            GreaseRequest::MsKeyExchange(envelope) => {
                trace!("🖥️  Multisig Key Exchange request received");
                let (channel_name, peer_key_info) = envelope.open();
                if let Err(err) = channel
                    .wallet_preparation(|wallet_state| Box::pin(wallet_state.import_multisig_keys(peer_key_info)))
                    .await
                {
                    warn!("Error importing multisig keys: {err}");
                    return GreaseResponse::MsKeyExchange(Err("Customer could not import keys".into()));
                }
                trace!("🖥️  Customer: Peer multisig keys imported.");
                let Some(my_key_info) = channel.wallet_state().ok().and_then(|s| s.multisig_keys().cloned()) else {
                    return GreaseResponse::MsKeyExchange(Err("Customer could not generate key info".into()));
                };
                trace!("🖥️  Customer: Multisig keys retrieved. Sending them onto merchant");
                let envelope = RequestEnvelope::new(channel_name, my_key_info);
                GreaseResponse::MsKeyExchange(Ok(envelope))
            }
            GreaseRequest::ConfirmMsAddress(envelope) => {
                trace!("🖥️  Confirm multisig address request received");
                let (channel_name, address) = envelope.open();
                let addr_str = address.to_string();
                let result = match channel.wallet_state() {
                    Ok(state) => match state.get_address().await {
                        Some(my_address) if my_address == address => {
                            info!("🖥️  Multisig wallet created with address {addr_str}");
                            true
                        }
                        Some(my_address) if my_address != address => {
                            warn!(
                                "🖥️  The merchant's address {addr_str} does not match the one we generated {}",
                                my_address.to_string()
                            );
                            false
                        }
                        _ => false,
                    },
                    Err(_) => false,
                };
                if !result {
                    warn!("🖥️  Could not confirm multisig address");
                }
                let envelope = RequestEnvelope::new(channel_name, result);
                GreaseResponse::ConfirmMsAddress(envelope)
            }
        }
    }

    //---------------------------------------- State machine handling functions --------------------------------------//

    /// Handle an incoming request to open a payment channel.
    async fn handle_open_channel_request(&self, data: &NewChannelProposal<P>) -> GreaseResponse<P> {
        self.establish_new_channel(data).await.unwrap_or_else(|early| early)
    }

    /// Establish a new payment channel with a peer.
    ///
    /// The steps involved are:
    /// 1. Verify the proposal and create a new channel state machine.
    /// 2. Emit an `AckProposal` event on the channel.
    /// 3. Queue up the tasks to complete in order to establish the channel.
    async fn establish_new_channel(
        &self,
        data: &NewChannelProposal<P>,
    ) -> Result<GreaseResponse<P>, GreaseResponse<P>> {
        let mut channel = self.verify_proposal_and_create_channel(data)?;
        // Submit the proposal to the state machine and generate a response
        channel.receive_proposal().await.map_err(|err| {
            warn!("🖥️  Channel proposal was not accepted by the state machine");
            let rejection = ChannelProposalResult::reject(err.into(), RetryOptions::close_only());
            GreaseResponse::ChannelProposalResult(rejection)
        })?;
        let ack = ChannelProposalResult::accept(data.clone());
        // Queue up the tasks to complete next in order to establish the channel
        let channel_name = channel.name();
        let todo_list = [
            TodoListItem::CreateMultiSigWallet { channel_name: channel_name.clone() },
            TodoListItem::CreateNewKes { channel_name: channel_name.clone() },
            TodoListItem::ConstructFundingTransaction { channel_name: channel_name.clone() },
            // When the Funding tx is broadcast, it'll get picked up by the event loop and the state will move to
            // Open automatically.
        ];
        self.add_todo_list_items(todo_list).await;
        self.channels.add(channel).await;

        Ok(GreaseResponse::ChannelProposalResult(ack))
    }

    async fn close_channel(&self, channel_name: String, reason: String) -> NextAction {
        info!("🖥️  Closing channel {channel_name}. {reason}");
        error!("🖥️  TODO!");
        NextAction::Continue
    }

    /// As a merchant, fetch the multisig initialization data from the wallet.
    ///Once received, pass the information to the peer over the wire and wait.
    async fn prepare_multisig_wallet(&self, channel_name: String) -> NextAction {
        let next = self.prepare_multisig_wallet_wrapped(channel_name).await.unwrap_or_else(|next_action| next_action);
        match next {
            NextAction::Continue => {
                info!("🖥️  Multisig wallet prepared successfully");
                NextAction::Continue
            }
            NextAction::Ignore => {
                info!("🖥️  Multisig wallet preparation failed, but we're ignoring it");
                NextAction::Ignore
            }
            NextAction::Abort { channel_name, reason } => {
                warn!("🖥️  Multisig wallet preparation failed: {reason}");
                NextAction::Abort { channel_name, reason }
            }
        }
    }

    async fn create_funding_transaction(&self, channel_name: String) -> NextAction {
        debug!("🖥️  Creating funding transaction for channel {channel_name}");
        NextAction::Continue
    }

    async fn create_kes(&self, channel_name: String) -> NextAction {
        debug!("🖥️  Creating KES for channel {channel_name}");
        NextAction::Continue
    }

    // This function is the actual implementation of the multisig wallet preparation. It returns result for ergonomics
    // so that abort! macros can return early.
    async fn prepare_multisig_wallet_wrapped(&self, channel_name: String) -> Result<NextAction, NextAction> {
        // Pre creation sanity checks and get the required channel info from the state machine
        let (channel_id, role, peer) = self.pre_wallet_checks(&channel_name).await?;

        // Step 1 - Prepare multisig
        let wallet = W::new(&channel_id).map_err(|e| abort!(&channel_name, "Error creating wallet: {}", e))?;
        let mut wallet_state = WalletState::new(wallet);
        trace!("🖥️  Merchant: Preparing multisig wallet");
        wallet_state = wallet_state.prepare_multisig().await;
        let info = wallet_state.init_info().ok_or_else(|| abort!(&channel_name, "Wallet state is not prepared"))?;

        // Step 2 - Share info with peer
        let mut client = self.network_client.clone();
        trace!("🖥️  Sending init info to customer");
        let (peer_channel, peer_info) =
            match client.send_multisig_init(peer.peer_id, channel_name.clone(), info.clone()).await {
                Ok(Ok(envelope)) => Ok(envelope.open()),
                Ok(Err(e)) => Err(abort!(&channel_name, "Peer did not return multisig init data: {}", e)),
                Err(e) => Err(abort!(&channel_name, "Error sending multisig init data to peer: {}", e)),
            }?;
        if peer_channel != channel_name {
            return Err(abort!(&channel_name, "Peer returned a different channel name: {peer_channel}"));
        }
        trace!("🖥️  Merchant: Received multisig init data from customer. Calling make_multisig");
        wallet_state = wallet_state.make_multisig(peer_info).await;
        // Step 3 - Send key info to peer
        let key =
            wallet_state.multisig_keys().ok_or_else(|| abort!(&channel_name, "Wallet state is not prepared"))?.clone();
        trace!("🖥️  Merchant: Sending multisig partial key to customer");
        let (peer_channel, peer_key) = match client.send_multisig_key(peer.peer_id, channel_name.clone(), key).await {
            Ok(Ok(envelope)) => Ok(envelope.open()),
            Ok(Err(e)) => Err(abort!(&channel_name, "Peer did not return multisig key data: {}", e)),
            Err(e) => Err(abort!(&channel_name, "Error sending multisig key data to peer: {}", e)),
        }?;
        if peer_channel != channel_name {
            return Err(abort!(&channel_name, "Peer returned a different channel name: {peer_channel}"));
        }
        // Step 4 - Confirm address
        trace!("🖥️  Merchant: Received multisig key data from customer. Calling import_multisig_keys");
        wallet_state = wallet_state.import_multisig_keys(peer_key).await;
        trace!("🖥️  Merchant: Fetching address");
        let address =
            wallet_state.get_address().await.ok_or_else(|| abort!(&channel_name, "Wallet state is not prepared"))?;
        trace!("🖥️  Merchant: Sending address {} to customer", address.to_string());
        let (peer_channel, addresses_match) =
            match client.confirm_multisig_address(peer.peer_id, channel_name.clone(), address).await {
                Ok(Ok(envelope)) => Ok(envelope.open()),
                Ok(Err(e)) => Err(abort!(&channel_name, "Error confirming multisig address: {}", e)),
                Err(e) => Err(abort!(&channel_name, "Error sending multisig address data to peer: {}", e)),
            }?;
        if peer_channel != channel_name {
            return Err(abort!(&channel_name, "Peer returned a different channel name: {peer_channel}"));
        }
        if !addresses_match {
            return Err(abort!(&channel_name, "Peer rejected the monero wallet address"));
        }
        trace!("🖥️  Merchant: Address confirmed. Accepting new wallet and moving to next state");
        match self.channels.checkout(&channel_name).await {
            Some(mut channel) => {
                // Inject this wallet state machine
                channel
                    .wallet_preparation(|_state| future::ready(wallet_state))
                    .await
                    .map_err(|e| abort!(channel_name, "Error setting wallet state: {}", e))?;
                channel
                    .accept_new_wallet()
                    .await
                    .map(|_| NextAction::Continue)
                    .map_err(|e| abort!(channel_name, "Error accepting new wallet: {}", e))
            }
            None => Err(abort!(&channel_name, "So close! Channel not found")),
        }
    }

    //------------------------------------------- Minor helper functions ---------------------------------------------//

    fn verify_proposal_and_create_channel(
        &self,
        data: &NewChannelProposal<P>,
    ) -> Result<PaymentChannel<P, C, W, KES>, GreaseResponse<P>> {
        // Check that the public key passed in the proposal matches our keypair
        let (my_secret, my_pubkey) = self.check_pubkey_matches(data)?;
        // Let the delegate do their checks
        let delegate = self.delegate.clone();
        delegate.verify_proposal(data).map_err(|invalid| {
            let retry = RetryOptions::close_only();
            let rej = ChannelProposalResult::reject(RejectReason::InvalidProposal(invalid), retry);
            GreaseResponse::ChannelProposalResult(rej)
        })?;
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
        Ok(PaymentChannel::new(peer_info, state))
    }

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

    // Before creating a new 2-of-2 wallet, check the following:
    // 1. The channel exists
    // 2. The channel is in the Establishing state
    // 3. The role of this side of the channel is Merchant
    async fn pre_wallet_checks(&self, channel_name: &str) -> Result<(ChannelId, ChannelRole, ContactInfo), NextAction> {
        trace!("Peeking at channel {channel_name}");
        match self.channels.try_peek(&channel_name).await {
            Some(channel) => match channel.state() {
                ChannelLifeCycle::Establishing(state) => {
                    let state_needed = (
                        state.channel_info.channel_id.clone(),
                        state.channel_info.role,
                        channel.peer_info(),
                    );
                    drop(channel);
                    if state_needed.1.is_customer() {
                        error!("🖥️  Wallet setup must start from merchant side. Channel {channel_name} is not a merchant channel");
                        Err(abort!(&channel_name, "Channel is not a merchant channel"))
                    } else {
                        Ok(state_needed)
                    }
                }
                _ => Err(abort!(&channel_name, "Channel is not in the Establishing state")),
            },
            None => Err(abort!(&channel_name, "Channel not found")),
        }
    }
}

#[derive(Debug)]
pub enum TodoListItem {
    /// Send the multisig wallet init data to the peer for channel `channel_name`
    CreateMultiSigWallet {
        channel_name: String,
    },
    CreateNewKes {
        channel_name: String,
    },
    ConstructFundingTransaction {
        channel_name: String,
    },
    CloseChannel {
        channel_name: String,
        reason: String,
    },
}

pub enum NextAction {
    /// Task completed successfully. Continue as normal
    Continue,
    /// There was an error, but we can continue
    Ignore,
    /// Close the channel with reason given
    Abort { channel_name: String, reason: String },
}
