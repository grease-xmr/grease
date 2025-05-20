use crate::errors::{ChannelServerError, PaymentChannelError, PeerConnectionError};
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
use libgrease::channel_id::ChannelId;
use libgrease::crypto::traits::PublicKey;
use libgrease::kes::{KesInitializationRecord, KeyEscrowService};
use libgrease::monero::data_objects::{
    MessageEnvelope, MsKeyAndVssInfo, MultiSigInitInfo, MultisigKeyInfo, WalletConfirmation,
};
use libgrease::monero::{MultiSigWallet, WalletState};
use libgrease::payment_channel::ActivePaymentChannel;
use libgrease::state_machine::error::InvalidProposal;
use libgrease::state_machine::{
    ChannelInitSecrets, ChannelLifeCycle, ChannelMetadata, LifecycleStage, NewChannelBuilder, VssOutput,
};
use libp2p::request_response::ResponseChannel;
use libp2p::Multiaddr;
use log::*;
use monero::Network;
use std::collections::VecDeque;
use std::fmt::{Display, Formatter};
use std::future;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::{OwnedRwLockWriteGuard, RwLock};
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
        let inner = InnerEventHandler::new(network_client, channels, delegate, key_delegate);
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
                // Carry out any pending tasks
                inner_clone.work_through_todo_list().await;
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
        debug!("🖥️  Adding item to todo list: {item}");
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

    async fn work_through_todo_list(&self) {
        while let Some(next_item) = self.get_next_todo_list_item().await {
            let channel_name = next_item.channel_name();
            let next = match next_item {
                TodoListItem::CreateMultiSigWallet { channel_name } => self.build_biparty_channel(channel_name).await,
                TodoListItem::ConstructFundingTransaction { channel_name } => {
                    self.create_funding_transaction(&channel_name).await
                }
                TodoListItem::CloseChannel { channel_name, reason } => self.close_channel(channel_name, reason).await,
            };
            if let Err(err) = next {
                debug!("🖥️  Aborting channel: {err}");
                let item = TodoListItem::CloseChannel { channel_name, reason: err.to_string() };
                self.add_todo_list_item(item).await;
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
            self.handle_request_for_existing_channel(request).await
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

    async fn handle_request_for_existing_channel(&self, request: GreaseRequest<P>) -> GreaseResponse<P> {
        // Note: The channel name has already been checked against the incoming message.
        match request {
            GreaseRequest::ProposeNewChannel(_) => {
                GreaseResponse::Error("Cannot create a new channel. Channel exists.".into())
            }
            GreaseRequest::MsInit(envelope) => self.customer_wallet_init(envelope).await.unwrap_or_else(|early| early),
            GreaseRequest::MsKeyExchange(envelope) => {
                self.customer_add_ms_key_and_split_secrets(envelope).await.unwrap_or_else(|early| early)
            }
            GreaseRequest::ConfirmMsAddress(envelope) => {
                trace!("🖥️  Confirm multisig address request received");
                let (channel_name, confirmation) = envelope.open();
                let response = self.compare_address_and_save_vss(&channel_name, confirmation).await.unwrap_or(false);
                let envelope = MessageEnvelope::new(channel_name, response);
                GreaseResponse::ConfirmMsAddress(envelope)
            }
        }
    }
    //----------------------------   State machine handling functions (Customer)   ----------------------------------//

    async fn customer_wallet_init(
        &self,
        envelope: MessageEnvelope<MultiSigInitInfo>,
    ) -> Result<GreaseResponse<P>, GreaseResponse<P>> {
        trace!("🖥️  Customer: Multisig Init request received");
        let (channel_name, merchant_info) = envelope.open();

        // fetch init info for merchant
        let mut channel = self.channels.checkout(&channel_name).await.ok_or_else(|| GreaseResponse::ChannelNotFound)?;
        channel.wallet_preparation(|wallet_state| wallet_state.prepare_multisig()).await.map_err(|err| {
            warn!("🖥️  Error preparing multisig wallet: {err}");
            GreaseResponse::MsInit(Err("Customer could not create wallet".into()))
        })?;
        trace!("🖥️  Customer: Multisig wallet prepared. Returning key info to merchant.");
        let customer_info = channel
            .wallet_state()
            .map_err(|err| {
                warn!("🖥️  Customer: Error getting multisig wallet state: {err}");
                GreaseResponse::MsInit(Err("Customer could not generate initialization info".into()))
            })
            .and_then(|state| {
                state.init_info().ok_or_else(|| {
                    warn!("🖥️  Customer: Wallet is not is the 'Prepared' state");
                    GreaseResponse::MsInit(Err(
                        "Customer could not generate initialization info. Wallet state was incorrect".into(),
                    ))
                })
            })?
            .clone();

        // Add customer's peer info and make multisig wallet
        channel.wallet_preparation(|wallet_state| Box::pin(wallet_state.make_multisig(merchant_info))).await.map_err(
            |err| {
                warn!("🖥️  Error making multisig wallet: {err}");
                return GreaseResponse::MsInit(Err("Customer could not create wallet".into()));
            },
        )?;
        drop(channel);
        trace!("🖥️  Customer: Multisig wallet made. Returning init info to merchant");
        let envelope = MessageEnvelope::new(channel_name, customer_info);
        Ok(GreaseResponse::MsInit(Ok(envelope)))
    }

    async fn customer_add_ms_key_and_split_secrets(
        &self,
        envelope: MessageEnvelope<MultisigKeyInfo>,
    ) -> Result<GreaseResponse<P>, GreaseResponse<P>> {
        trace!("🖥️  Multisig Key Exchange request received");
        let (name, peer_key_info) = envelope.open();

        // import the multisig key into our wallet. Prep step 2
        let mut channel = self.channels.checkout(&name).await.ok_or_else(|| GreaseResponse::ChannelNotFound)?;
        channel
            .wallet_preparation(|wallet_state| Box::pin(wallet_state.import_multisig_keys(peer_key_info)))
            .await
            .map_err(|err| {
                warn!("Error importing multisig keys: {err}");
                return GreaseResponse::MsKeyExchange(Err("Customer could not import keys".into()));
            })?;
        trace!("🖥️  Customer: Peer multisig keys imported.");

        // Generate the VSS info that we return to the merchant
        let secrets = self.get_vss_info(&name).await.map_err(|err| {
            warn!("🖥️  Error getting VSS info: {err}");
            GreaseResponse::MsKeyExchange(Err("Customer could not get VSS info".into()))
        })?;
        let shards_for_merchant = self.delegate.split_and_encrypt_keys(secrets).await.map_err(|err| {
            warn!("🖥️  Error splitting and encrypting keys: {err}");
            GreaseResponse::MsKeyExchange(Err("Customer could not split and encrypt keys".into()))
        })?;

        // Get the Multisig key info and save the shards we've just calculated.
        let mut channel = self.channels.checkout(&name).await.ok_or_else(|| GreaseResponse::ChannelNotFound)?;
        let multisig_key = channel
            .wallet_state()
            .unwrap()
            .multisig_keys()
            .cloned()
            .ok_or_else(|| GreaseResponse::MsKeyExchange(Err("Customer could not generate MultisigKey".into())))?;
        channel.update_wallet_state(|state| state.save_peer_shards(shards_for_merchant.clone()));

        let response = MsKeyAndVssInfo { multisig_key, shards_for_merchant: shards_for_merchant };
        trace!("🖥️ Customer: VSS complete. Responding to merchant.");
        let envelope = MessageEnvelope::new(name, response);
        Ok(GreaseResponse::MsKeyExchange(Ok(envelope)))
    }

    /// The customer checks that the wallet address they created matches the one in the confirmation record.
    /// If it does, it saves the split secrets, and returns `true` to the merchant.
    ///
    /// Otherwise, it returns `false` and the merchant will close the channel.
    async fn compare_address_and_save_vss(&self, channel: &str, confirmation: WalletConfirmation) -> Option<bool> {
        let mut channel = self.channels.checkout(channel).await?;
        let address = channel.wallet_state().ok()?.get_address().await?;
        let addresses_match = address == confirmation.address;
        if addresses_match {
            channel.update_wallet_state(|state| state.save_my_shards(confirmation.merchant_vss_info));
            debug!("🖥️  Customer: Address confirmed. Merchant split secrets for KES and Merchant saved.");
        } else {
            warn!("🖥️  Customer: The derived address for the merchant's wallet doesn't match ours. This channel will be closed.");
        }
        Some(addresses_match)
    }

    //------------------------------ State machine handling functions (Merchant) ------------------------------------//

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
        // We don't queue up the KES yet, because we need the partial encrypted key info, which only becomes available
        // upon wallet setup completion.
        let item = TodoListItem::CreateMultiSigWallet { channel_name: channel.name() };
        self.add_todo_list_item(item).await;
        self.channels.add(channel).await;

        Ok(GreaseResponse::ChannelProposalResult(ack))
    }

    async fn close_channel(&self, channel_name: String, reason: String) -> Result<(), ChannelServerError> {
        info!("🖥️  Closing channel {channel_name}. {reason}");
        // TODO - complete this
        Ok(())
    }

    /// Returns the channel metadata for the given channel name, if the current lifecycle state has the information
    /// available.
    async fn get_channel_metadata(&self, channel_name: &str) -> Option<ChannelMetadata<P>> {
        let lock = self.channels.try_peek(channel_name).await?;
        lock.state().channel_info().cloned()
    }

    /// The merchant takes the lead in establishing a new channel. After going through the multisig wallet creation
    /// process, he must establish the KES and allow the customer to verify it. Finally, the funding transaction(s)
    /// must be broadcast and verified, at which point the channel is open.
    async fn build_biparty_channel(&self, channel_name: String) -> Result<(), ChannelServerError> {
        self.prepare_multisig_wallet(&channel_name).await?;
        info!(" 🖥️  New Multisig wallet for {channel_name} created.");
        self.establish_kes(&channel_name).await?;
        info!(" 🖥️  KES established for {channel_name}.");
        self.create_funding_transaction(&channel_name).await?;
        info!(" 🖥️  Funding transaction created for {channel_name}.");
        Ok(())
    }

    async fn establish_kes(&self, channel_name: &str) -> Result<(), ChannelServerError> {
        let channel = self.channels.try_peek(channel_name).await.ok_or(ChannelServerError::ChannelNotFound)?;
        let kes_info =
            channel.state().kes_info().ok_or(ChannelServerError::InvalidState("KES info not available".to_string()))?;
        drop(channel);
        let result = self.delegate.initialize_kes(kes_info).await.map_err(|err| ChannelServerError::KesError(err))?;
        let mut channel = self.channels.checkout(channel_name).await.ok_or(ChannelServerError::ChannelNotFound)?;
        channel.save_kes_result(result)?;
        Ok(())
    }

    async fn create_funding_transaction(&self, channel_name: &str) -> Result<(), ChannelServerError> {
        Ok(())
    }

    async fn create_kes(&self, channel_name: String, init: KesInitializationRecord) -> NextAction {
        debug!("🖥️  Initiating new KES for channel {channel_name}");
        match self.delegate.initialize_kes(init).await {
            Ok(kes_result) => {
                info!("🖥️  KES initialized successfully");
                NextAction::Continue
            }
            Err(err) => {
                warn!("🖥️  KES initialization failed: {err}");
                NextAction::Abort { channel_name, reason: "KES initialization failed".to_string() }
            }
        }
    }

    /// Creates a new multisig wallet and prepares it for use.
    ///
    /// On successful return, the wallet is in the `WalletCreated` state and is ready to receive funds.
    /// The VSS record has also been sent to the customer.
    async fn prepare_multisig_wallet(&self, channel_name: &str) -> Result<(), ChannelServerError> {
        // Pre creation sanity checks and get the required channel info from the state machine
        let (network, channel_id, peer) = self.pre_wallet_checks(&channel_name).await?;
        let (mut wallet_state, info) = Self::init_new_wallet(network, channel_name, &channel_id).await?;
        let mut client = self.network_client.clone();
        wallet_state = Self::share_init_info_with_peer(channel_name, &peer, wallet_state, &info, &mut client).await?;
        wallet_state = Self::share_key_info_with_peer(channel_name, &peer, &mut client, wallet_state).await?;
        wallet_state =
            Self::confirm_wallet_address_and_share_vss(&self, channel_name, peer, wallet_state, &mut client).await?;
        trace!("🖥️  Merchant: Address confirmed. Accepting new wallet and moving to next state");
        let mut channel = self.channels.checkout(&channel_name).await.ok_or(ChannelServerError::ChannelNotFound)?;
        // Inject this wallet state machine
        channel.wallet_preparation(|_state| future::ready(wallet_state)).await?;
        channel.accept_new_wallet().await?;
        Ok(())
    }

    /// The merchant creates a new multisig wallet and prepares it for use.
    async fn init_new_wallet(
        network: Network,
        channel_name: &str,
        channel_id: &ChannelId,
    ) -> Result<(WalletState<W>, MultiSigInitInfo), ChannelServerError> {
        let wallet = W::new(&channel_id)?;
        let mut wallet_state = WalletState::new(network, wallet);
        trace!("🖥️  Merchant: Preparing multisig wallet");
        wallet_state = wallet_state.prepare_multisig().await;
        let info = wallet_state
            .init_info()
            .ok_or_else(|| {
                ChannelServerError::InvalidState(format!("Wallet state for channel {channel_name} is not 'Prepared'"))
            })?
            .clone();
        Ok((wallet_state, info))
    }

    /// The merchant shares the Monero multisig wallet initialization info (step 1) with the customer, expecting the
    /// customer to respond with their own init info.
    async fn share_init_info_with_peer(
        channel_name: &str,
        peer: &ContactInfo,
        wallet_state: WalletState<W>,
        info: &MultiSigInitInfo,
        client: &mut Client<P>,
    ) -> Result<WalletState<W>, ChannelServerError> {
        trace!("🖥️  Sending init info to customer");
        let (peer_channel, peer_info) = client
            .send_multisig_init(peer.peer_id, channel_name.to_owned(), info.clone())
            .await?
            .map_err(|s| ChannelServerError::PeerCommsError(s))?
            .open();

        if peer_channel != channel_name {
            return Err(ChannelServerError::PeerCommsError(format!(
                "Mismatched channel names. Expected {channel_name}, Received {peer_channel}"
            )));
        }
        trace!("🖥️  Merchant: Received multisig init data from customer. Calling make_multisig");
        Ok(wallet_state.make_multisig(peer_info).await)
    }

    /// The merchant shares the Monero multisig wallet key info (step 2) with the customer, expecting the customer to
    /// respond with their own key info PLUS their VSS info in a `MsKeyAndVssInfo` envelope.
    async fn share_key_info_with_peer(
        channel_name: &str,
        peer: &ContactInfo,
        client: &mut Client<P>,
        mut wallet_state: WalletState<W>,
    ) -> Result<WalletState<W>, ChannelServerError> {
        let key = wallet_state
            .multisig_keys()
            .ok_or_else(|| {
                ChannelServerError::InvalidState(format!("Channel {channel_name}'s wallet state is not 'Prepared'"))
            })?
            .clone();

        trace!("🖥️  Merchant: Sending multisig partial key to customer");
        let (peer_channel, customer_keys) = client
            .send_multisig_key(peer.peer_id, channel_name.to_owned(), key)
            .await?
            .map_err(|s| ChannelServerError::PeerCommsError(s))?
            .open();

        if peer_channel != channel_name {
            return Err(ChannelServerError::PeerCommsError(format!(
                "Mismatched channel names. Expected {channel_name}, Received {peer_channel}"
            )));
        }
        trace!("🖥️  Merchant: Received multisig key data from customer. Calling import_multisig_keys");
        wallet_state = wallet_state.import_multisig_keys(customer_keys.multisig_key).await;
        wallet_state = wallet_state.save_my_shards(customer_keys.shards_for_merchant);
        Ok(wallet_state)
    }

    /// The merchant sends the derived multisig wallet address to the customer and waits for confirmation (i.e. that
    /// the customer was able to derive the same address).
    /// The merchant must also generate their VSS data and include it in the request.
    async fn confirm_wallet_address_and_share_vss(
        &self,
        channel_name: &str,
        peer: ContactInfo,
        wallet_state: WalletState<W>,
        client: &mut Client<P>,
    ) -> Result<WalletState<W>, ChannelServerError> {
        trace!("🖥️  Merchant: Fetching address");
        let address = wallet_state.get_address().await.ok_or_else(|| {
            ChannelServerError::InvalidState(format!("Channel {channel_name}'s wallet state is not 'Prepared'"))
        })?;
        let secrets = self.get_vss_info(&channel_name).await?;
        let shards_for_customer = self.create_vss(secrets).await?;

        let mut channel = self.channels.checkout(&channel_name).await.ok_or(ChannelServerError::ChannelNotFound)?;
        channel.update_wallet_state(|state| state.save_peer_shards(shards_for_customer.clone()));
        drop(channel);

        trace!(
            "🖥️  Merchant: Sending wallet confirmation for {} to customer",
            address.to_string()
        );
        let confirmation = WalletConfirmation { address, merchant_vss_info: shards_for_customer };
        let (peer_channel, addresses_match) = client
            .confirm_multisig_address(peer.peer_id, channel_name.to_owned(), confirmation)
            .await?
            .map_err(|s| ChannelServerError::PeerCommsError(s))?
            .open();
        if peer_channel != channel_name {
            return Err(ChannelServerError::PeerCommsError(format!(
                "Mismatched channel names. Expected {channel_name}, Received {peer_channel}"
            )));
        }
        if !addresses_match {
            return Err(ChannelServerError::PeerCommsError(format!(
                "Peer rejected the monero wallet address for {channel_name}"
            )));
        }
        Ok(wallet_state)
    }

    // ------------------------------   State machine handling functions (Common)   ----------------------------------//

    async fn get_vss_info(&self, channel_name: &str) -> Result<ChannelInitSecrets<P>, ChannelServerError> {
        let channel = self.channels.try_peek(&channel_name).await.ok_or(ChannelServerError::ChannelNotFound)?;
        let vss_info = match channel.state() {
            ChannelLifeCycle::WalletCreated(state) => state.vss_info(),
            _ => {
                return Err(ChannelServerError::InvalidState(format!(
                    "Channel {channel_name} is not in the WalletCreated state"
                )))
            }
        }?;
        Ok(vss_info)
    }

    async fn create_vss(&self, vss_info: ChannelInitSecrets<P>) -> Result<VssOutput, ChannelServerError> {
        let vss_info = self.delegate.create_vss(vss_info).await.map_err(|err| {
            warn!("🖥️  VSS creation failed: {}", err.reason);
            ChannelServerError::VssFailure(err.reason)
        })?;
        debug!("🖥️  VSS created successfully");
        Ok(vss_info)
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
    async fn pre_wallet_checks(
        &self,
        channel_name: &str,
    ) -> Result<(Network, ChannelId, ContactInfo), ChannelServerError> {
        trace!("Peeking at channel {channel_name}");
        match self.channels.try_peek(channel_name).await {
            Some(channel) => match channel.state() {
                ChannelLifeCycle::Establishing(state) => {
                    let role = state.channel_info.role;
                    let state_needed = (
                        state.channel_info.network,
                        state.channel_info.channel_id.clone(),
                        channel.peer_info(),
                    );
                    drop(channel);
                    if role.is_customer() {
                        error!("🖥️  Wallet setup must start from merchant side. Channel {channel_name} is not a merchant channel");
                        Err(ChannelServerError::NotMerchantRole)
                    } else {
                        Ok(state_needed)
                    }
                }
                _ => Err(ChannelServerError::InvalidState(format!(
                    "Channel {channel_name} is not in the Establishing state"
                ))),
            },
            None => Err(ChannelServerError::ChannelNotFound),
        }
    }
}

#[derive(Debug)]
pub enum TodoListItem {
    /// Send the multisig wallet init data to the peer for channel `channel_name`
    CreateMultiSigWallet {
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

impl Display for TodoListItem {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            TodoListItem::CreateMultiSigWallet { channel_name } => {
                write!(f, "Create multisig wallet for {channel_name}")
            }
            TodoListItem::ConstructFundingTransaction { channel_name } => {
                write!(f, "Construct funding transaction for {channel_name}")
            }
            TodoListItem::CloseChannel { channel_name, reason } => write!(f, "Close channel {channel_name}: {reason}"),
        }
    }
}

impl TodoListItem {
    pub fn channel_name(&self) -> String {
        match self {
            TodoListItem::CreateMultiSigWallet { channel_name } => channel_name.clone(),
            TodoListItem::ConstructFundingTransaction { channel_name } => channel_name.clone(),
            TodoListItem::CloseChannel { channel_name, .. } => channel_name.clone(),
        }
    }
}

pub enum NextAction {
    /// Task completed successfully. Continue as normal
    Continue,
    /// Close the channel with reason given
    Abort { channel_name: String, reason: String },
}
