use crate::delegates::GreaseChannelDelegate;
use crate::errors::{ChannelServerError, PaymentChannelError, PeerConnectionError, RemoteServerError};
use crate::message_types::{
    ChannelProposalResult, NewChannelProposal, RejectChannelProposal, RejectReason, RetryOptions,
};
use crate::{
    new_network, Client, ContactInfo, ConversationIdentity, GreaseRequest, GreaseResponse, PaymentChannel,
    PaymentChannels, PeerConnectionEvent,
};
use futures::future::join;
use futures::StreamExt;
use libgrease::amount::{MoneroAmount, MoneroDelta};
use libgrease::channel_metadata::ChannelMetadata;
use libgrease::crypto::keys::{Curve25519PublicKey, Curve25519Secret};
use libgrease::crypto::traits::PublicKey;
use libgrease::kes::{FundingTransaction, ShardInfo};
use libgrease::monero::data_objects::{
    ChannelUpdate, ChannelUpdateFinalization, MessageEnvelope, MultisigKeyInfo, MultisigSplitSecrets, PaymentRejection,
    StartChannelUpdateConfirmation,
};
use libgrease::payment_channel::UpdateError;
use libgrease::state_machine::error::LifeCycleError;
use libgrease::state_machine::lifecycle::{ChannelState, LifeCycle, LifecycleStage};
use libgrease::state_machine::{LifeCycleEvent, NewChannelBuilder, ProposedChannelInfo};
use libp2p::request_response::ResponseChannel;
use libp2p::{Multiaddr, PeerId};
use log::*;
use rand::rng;
use std::collections::VecDeque;
use std::fmt::{Display, Formatter};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::{OwnedRwLockWriteGuard, RwLock};
use tokio::task::JoinHandle;
use wallet::watch_only::WatchOnlyWallet;
use wallet::{connect_to_rpc, MultisigWallet};

pub type WritableState = OwnedRwLockWriteGuard<PaymentChannel>;

pub struct NetworkServer<D: GreaseChannelDelegate> {
    id: ConversationIdentity,
    inner: InnerEventHandler<D>,
    event_loop_handle: JoinHandle<()>,
    event_handler_handle: JoinHandle<()>,
}

impl<D> NetworkServer<D>
where
    D: GreaseChannelDelegate + 'static,
{
    pub fn new(
        id: ConversationIdentity,
        channels: PaymentChannels,
        rpc_address: impl Into<String>,
        delegate: D,
    ) -> Result<Self, PeerConnectionError> {
        let keypair = id.keypair().clone();
        // Create a new network client and event loop.
        let (network_client, mut network_events, network_event_loop) = new_network(keypair)?;
        // Spawn the network task for it to run in the background.
        let event_loop_handle = tokio::spawn(network_event_loop.run());
        let inner = InnerEventHandler::new(network_client, channels, delegate, rpc_address.into());
        let inner_clone = inner.clone();
        let event_handler_handle = tokio::spawn(async move {
            while let Some(ev) = network_events.next().await {
                trace!("libp2p network event received.");
                match ev {
                    PeerConnectionEvent::InboundRequest { request, response } => {
                        trace!("Inbound grease request received");
                        inner_clone.handle_incoming_grease_request(request, response).await;
                    }
                }
                // Carry out any pending tasks
                inner_clone.work_through_todo_list().await;
            }
        });
        Ok(Self { id, inner, event_loop_handle, event_handler_handle })
    }

    pub fn controller(&self) -> InnerEventHandler<D> {
        self.inner.clone()
    }

    pub fn contact_info(&self) -> ContactInfo {
        self.id.contact_info()
    }

    pub async fn start_listening(&mut self, at: Multiaddr) -> Result<(), PeerConnectionError> {
        self.inner.start_listening(at).await
    }

    /// Provides a cheap clone of the network client. It is thread-safe.
    pub fn client(&self) -> Client {
        self.inner.network_client.clone()
    }

    pub async fn list_channels(&self) -> Vec<String> {
        self.inner.channels.list_channels().await
    }

    pub async fn channel_status(&self, name: &str) -> Option<LifecycleStage> {
        self.inner.channels.peek(name).await.map(|channel| channel.state().stage())
    }

    pub async fn channel_metadata(&self, name: &str) -> Option<ChannelMetadata> {
        self.inner.get_channel_metadata(name).await
    }

    pub async fn save_channels<Pth: AsRef<Path>>(&self, path: Pth) -> Result<(), PaymentChannelError> {
        self.inner.channels.save_channels(path).await
    }

    pub async fn add_channel(&self, channel: PaymentChannel) {
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

    /// Establish a new payment channel with a merchant.
    ///
    /// The steps involved are:
    /// 1. Complete the proposal phase with the merchant.
    /// 2. Move to the Establishing phase
    ///   2.1. Generate a new multisig wallet
    ///     2.1.1. Create a new keypair for the wallet. This is always a Curve25519 keypair.
    ///     2.1.2. Exchange the public keys with the merchant.
    ///     2.1.3. Create a new multisig wallet with the public keys.
    ///   2.2. Split and encrypt the wallet spend key secrets to give to the KES and merchant.
    ///   2.3. Verify the wallet address with the peer.
    pub async fn establish_new_channel(
        &self,
        secret: &str,
        proposal: NewChannelProposal,
    ) -> Result<String, ChannelServerError> {
        self.inner.customer_establish_new_channel(secret, proposal).await
    }

    /// Submit a funding transaction to the channel. This will potentially trigger a transition to the Established
    /// state if all the criteria are met.
    ///
    /// No validation is done on the transaction, so it is up to the caller to ensure that the transaction is valid
    /// **before** calling this function.
    pub async fn submit_funding_transaction(
        &self,
        name: &str,
        tx: FundingTransaction,
    ) -> Result<(), ChannelServerError> {
        self.inner.submit_funding_transaction(name, tx).await
    }

    /// A convenience function for [`Self::update_balance`] that pays the given amount from customer to merchant.
    ///
    /// Refer to [`Self::update_balance`] for more details on the update process.
    pub async fn pay(
        &mut self,
        channel: &str,
        amount: MoneroAmount,
    ) -> Result<ChannelUpdateFinalization, ChannelServerError> {
        let delta = MoneroDelta::from(amount);
        self.update_balance(channel, delta).await
    }

    /// A convenience function for [`Self::update_balance`] that refunds the given amount from merchant to customer.
    ///
    /// Refer to [`Self::update_balance`] for more details on the update process.
    pub async fn refund(
        &mut self,
        channel: &str,
        amount: MoneroAmount,
    ) -> Result<ChannelUpdateFinalization, ChannelServerError> {
        let delta = -MoneroDelta::from(amount);
        self.update_balance(channel, delta).await
    }

    /// Perform a channel update.
    ///
    /// It is assumed that the user has verified that the payment is acceptable. There is no recourse to interrupt
    /// the update process manually at this point (although the update can still fail for a myriad reasons).
    ///
    /// The usual flow is:
    /// 1. Generating the necessary proofs for the update.
    /// 2. Sending the update request and proofs to the remote peer.
    /// 3. Waiting for the remote peer to confirm the update (or reject it) and respond with the final partial
    ///    signature and transaction.
    /// 4. Verify the partial signature and transaction.
    /// 5. Inform peer of the result of the verification.
    /// 6. Return the same result to the client.
    pub async fn update_balance(
        &mut self,
        channel: &str,
        delta: MoneroDelta,
    ) -> Result<ChannelUpdateFinalization, ChannelServerError> {
        self.inner.update_balance_protocol(channel, delta).await
    }

    pub async fn rescan_for_funding(&self, channel: &str) {
        match self.inner.rescan_for_funding(channel).await {
            Some(()) => info!("Rescanning {} for funding transaction", channel),
            None => info!("Not scanning {} for funding transaction. See logs above for reason.", channel),
        }
    }
}

pub struct InnerEventHandler<D>
where
    D: GreaseChannelDelegate,
{
    network_client: Client,
    rpc_address: String,
    channels: PaymentChannels,
    delegate: D,
    todo_list: Arc<RwLock<VecDeque<TodoListItem>>>,
}

impl<D> Clone for InnerEventHandler<D>
where
    D: GreaseChannelDelegate,
{
    fn clone(&self) -> Self {
        Self {
            network_client: self.network_client.clone(),
            rpc_address: self.rpc_address.clone(),
            channels: self.channels.clone(),
            delegate: self.delegate.clone(),
            todo_list: Arc::clone(&self.todo_list),
        }
    }
}

impl<D> InnerEventHandler<D>
where
    D: GreaseChannelDelegate,
{
    fn new(client: Client, channels: PaymentChannels, delegate: D, rpc_address: String) -> Self {
        Self {
            network_client: client,
            channels,
            delegate,
            todo_list: Arc::new(RwLock::new(VecDeque::new())),
            rpc_address,
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
                TodoListItem::ConstructFundingTransaction { channel } => {
                    self.create_funding_transaction(&channel).await
                }
                TodoListItem::CloseChannel { channel, reason } => self.close_channel(channel, reason).await,
            };
            if let Err(err) = next {
                debug!("🖥️  Aborting channel: {err}");
                let item = TodoListItem::CloseChannel { channel: channel_name, reason: err.to_string() };
                self.add_todo_list_item(item).await;
            }
        }
    }

    async fn start_listening(&mut self, addr: Multiaddr) -> Result<(), PeerConnectionError> {
        self.network_client.start_listening(addr).await?;
        Ok(())
    }

    // ----------------------------                Proposal handling                ----------------------------------//

    /// Establish a new payment channel with a merchant.
    ///
    /// The steps involved are:
    /// 1. Complete the proposal phase with the merchant.
    /// 2. Move to the Establishing phase
    ///   2.1. Generate a new multisig wallet
    ///     2.1.1. Create a new keypair for the wallet. This is always a Curve25519 keypair.
    ///     2.1.2. Exchange the public keys with the merchant.
    ///     2.1.3. Create a new multisig wallet with the public keys.
    ///   2.2. Split and encrypt the wallet spend key secrets to give to the KES and merchant.
    ///   2.3. Verify the wallet address with the peer.
    pub async fn customer_establish_new_channel(
        &self,
        secret: &str,
        proposal: NewChannelProposal,
    ) -> Result<String, ChannelServerError> {
        // 1. Proposal phase
        info!("💍️ Sending new channel proposal to merchant");
        let name = self
            .customer_send_proposal(secret, proposal)
            .await?
            .map_err(|rej| ChannelServerError::ProposalRejected(rej))?;
        info!("💍️ Proposal accepted. Channel name: {name}");
        // 2. We're in establishing phase now.
        let channel = self.channels.peek(&name).await.ok_or(ChannelServerError::ChannelNotFound)?;
        let peer_id = channel.peer_id();
        if !channel.is_establishing() {
            return Err(ChannelServerError::ProtocolError(format!(
                "Channel {name} should be in Establishing phase"
            )));
        }
        drop(channel);
        // 2.1.1. Create a new keypair for the wallet.
        info!("👛️ Creating new multisig wallet keys for channel {name}");
        let (k, p) = Curve25519PublicKey::keypair(&mut rng());
        // 2.1.2. Exchange the public keys with the merchant.
        debug!("👛️ Sharing public key with merchant for channel {name}");
        let peer_key_info = self.exchange_wallet_keys(peer_id, &name, &p).await?;
        debug!("👛️ Received merchant's public key for channel {name}");
        // 2.1.3. Create a new multisig wallet with the public keys.
        let wallet = self.customer_create_multisig_wallet(&name, k, p, peer_key_info).await?;
        // 2.2. Split and encrypt the wallet spend key secrets to give to the KES and merchant.
        debug!("👛️ Splitting, encrypting and sharing spend key with merchant for channel {name}");
        let merchant_shards = self.split_secrets(wallet.my_spend_key()).await?;
        let my_shards = self.customer_exchange_split_secrets(peer_id, &name, merchant_shards.clone()).await?;
        debug!("👛️ Merchant provided their encrypted shards for channel {name}");
        let shards = ShardInfo { my_shards, their_shards: merchant_shards };
        self.common_verify_and_store_shards(&name, shards).await?;
        debug!("👛️ Wallet shards are valid and are stored for channel {name}");
        // 2.3. Verify the wallet address with the peer.
        let address = wallet.address();
        debug!("👛️ Verifying wallet address with peer for channel {name}. Address: {address}");
        let confirmed = self.customer_verify_wallet_address(peer_id, &name, address.to_string()).await?;
        if !confirmed {
            warn!("📢️ Wallet address verification failed for channel {name}. Address: {address}");
            return Err(ChannelServerError::ProtocolError(format!(
                "Wallet address verification failed for channel {name}"
            )));
        }
        let pvk = wallet.joint_private_view_key().clone();
        let pub_spend_key = wallet.joint_public_spend_key().clone();
        let birthday = Some(wallet.birthday());
        info!("👛️ Multisig wallet has been successfully created for channel {name}.");
        self.watch_for_funding_transaction(&name, pvk, pub_spend_key, birthday).await?;
        // This is as far as we can take the channel establishment process for now.
        // It will be continued once we received the KES creation confirmation from the merchant, as the merchant now
        // has everything they need to create the KES.
        Ok(name)
    }

    async fn rescan_for_funding(&self, name: &str) -> Option<()> {
        let channel = self.channels.peek(name).await?;
        if !channel.is_establishing() {
            debug!("Channel {name} is not establishing, so no need to scan for funding txnsaction.");
            return None;
        }
        let wallet_info = match channel.state().as_establishing().ok()?.wallet() {
            Some(info) => info,
            None => {
                debug!("Channel {name} does not have a wallet, so no need to scan for funding transaction.");
                return None;
            }
        };
        let pvt_vk = wallet_info.joint_private_view_key.clone();
        let pub_sk = wallet_info.joint_public_spend_key.clone();
        let bday = wallet_info.birthday.saturating_sub(5);
        trace!("Scanning blockchain from block {bday} for funding transaction for channel {name}");
        self.watch_for_funding_transaction(&name, pvt_vk, pub_sk, Some(bday))
            .await
            .map_err(|e| warn!("Error creating funding tx watcher: {e}"))
            .ok()?;
        Some(())
    }

    /// Proceed through the proposal phase of channel negotiation.
    ///
    /// Sends a channel proposal to the merchant and waits for a response. If the merchant ACKs the proposal, we
    /// verify the terms and create a new channel state machine. If the merchant rejects the proposal, or if we
    /// reject the final proposal, we return the reason to the client.
    async fn customer_send_proposal(
        &self,
        secret: &str,
        proposal: NewChannelProposal,
    ) -> Result<Result<String, RejectChannelProposal>, PeerConnectionError> {
        let mut client = self.network_client.clone();
        let address = proposal.contact_info_proposee.dial_address();
        // todo: check what happens if there's already a connection?
        client.dial(address).await?;
        trace!("Sending channel proposal to merchant.");
        let state = self.customer_create_new_state(secret, proposal.clone());
        let res = client.new_channel_proposal(proposal).await?;
        let result = match res {
            ChannelProposalResult::Accepted(final_proposal) => {
                // We got an ack, but the merchant may have changed the proposal, so we need to check.
                debug!("Channel proposal ACK received. Validating response.");
                if let Err(err) = self.delegate.verify_proposal(&final_proposal).await {
                    info!("Channel proposal verification failed: {}", err);
                    let rej =
                        RejectChannelProposal::new(RejectReason::InvalidProposal(err), RetryOptions::close_only());
                    return Ok(Err(rej));
                }
                // Proposal has been verified. Create the new channel.
                let peer_info = final_proposal.contact_info_proposee.clone();
                let info = final_proposal.proposed_channel_info();
                self.common_create_channel(state, peer_info, info)
                    .await
                    .map_err(|e| RejectChannelProposal::internal("Error creating new channel"))
            }
            ChannelProposalResult::Rejected(rej) => {
                warn!("Channel proposal rejected: {}", rej.reason);
                Err(rej)
            }
        };
        Ok(result)
    }

    /// Create a new channel state machine and add it to the channels list.
    /// Then migrate the state machine to the Establishing phase.
    async fn common_create_channel(
        &self,
        state: ChannelState,
        peer_info: ContactInfo,
        info: ProposedChannelInfo,
    ) -> Result<String, LifeCycleError> {
        let mut channel = PaymentChannel::new(peer_info, state);
        let event = LifeCycleEvent::VerifiedProposal(Box::new(info));
        channel.handle_event(event)?;
        let name = channel.name();
        trace!("Adding new channel {name}. Stage: {}", channel.state().stage());
        self.channels.add(channel).await;
        Ok(name)
    }

    /// Helper function. Creates a [`NewChannelState`] from the given proposal and secret.
    fn customer_create_new_state(&self, secret: &str, prop: NewChannelProposal) -> ChannelState {
        let new_state = NewChannelBuilder::new(prop.seed.role, &prop.proposer_pubkey, secret)
            .with_my_user_label(&prop.proposer_label)
            .with_peer_label(&prop.seed.user_label)
            .with_merchant_initial_balance(prop.seed.initial_balances.merchant)
            .with_customer_initial_balance(prop.seed.initial_balances.customer)
            .with_peer_public_key(prop.seed.pubkey)
            .with_kes_public_key(prop.seed.kes_public_key)
            .build::<blake2::Blake2b512>()
            .expect("Missing new channel state data");
        new_state.to_channel_state()
    }

    // TODO - the merchant label should be used to extract data that was generated ourselves, rather than trusting
    // the proposal.
    fn merchant_create_new_state(&self, secret: &str, prop: NewChannelProposal) -> ChannelState {
        let new_state = NewChannelBuilder::new(prop.seed.role.other(), &prop.seed.pubkey, secret)
            .with_my_user_label(&prop.seed.user_label)
            .with_peer_label(&prop.proposer_label)
            .with_merchant_initial_balance(prop.seed.initial_balances.merchant)
            .with_customer_initial_balance(prop.seed.initial_balances.customer)
            .with_peer_public_key(prop.proposer_pubkey)
            .with_kes_public_key(prop.seed.kes_public_key)
            .build::<blake2::Blake2b512>()
            .expect("Missing new channel state data");
        new_state.to_channel_state()
    }

    /// Handle an incoming request to open a payment channel.
    async fn merchant_handle_proposal(&self, data: &NewChannelProposal) -> GreaseResponse {
        info!("💍️ New proposal received from customer: {}", data.contact_info_proposer.name);
        self.verify_proposal_and_create_channel(data.clone())
            .await
            .map(|name| {
                info!("💍️ Proposal accepted from customer: {}", data.contact_info_proposer.name);
                let result = ChannelProposalResult::Accepted(data.clone());
                GreaseResponse::ProposeChannelResponse(Ok(result))
            })
            .unwrap_or_else(|rej| {
                info!("💍️ New proposal rejected for customer: {}", data.contact_info_proposer.name);
                let result = ChannelProposalResult::Rejected(rej);
                GreaseResponse::ProposeChannelResponse(Ok(result))
            })
    }

    async fn verify_proposal_and_create_channel(
        &self,
        data: NewChannelProposal,
    ) -> Result<String, RejectChannelProposal> {
        // Let the delegate do their checks
        self.delegate.verify_proposal(&data).await.map_err(|err| {
            debug!("Channel proposal verification failed: {err}");
            let reason = RejectReason::InvalidProposal(err);
            RejectChannelProposal::new(reason, RetryOptions::close_only())
        })?;
        let secret = self.delegate.derive_channel_secret(&data).await.map_err(|e| {
            warn!("Deriving new channel secret failed: {e}");
            RejectChannelProposal::internal("Error deriving new channel secret")
        })?;
        // Construct the new channel
        let peer_info = data.contact_info_proposer.clone();
        let info = data.proposed_channel_info();
        let new_state = self.merchant_create_new_state(&secret, data);
        let name = self.common_create_channel(new_state, peer_info, info).await.map_err(|e| {
            warn!("Error creating new channel {e}");
            RejectChannelProposal::internal("Error creating new channel")
        })?;
        Ok(name)
    }

    //----------------------------   Channel establishment functions (Customer)   ----------------------------------//

    async fn exchange_wallet_keys(
        &self,
        peer_id: PeerId,
        name: &str,
        my_pubkey: &Curve25519PublicKey,
    ) -> Result<MultisigKeyInfo, ChannelServerError> {
        let mut client = self.network_client.clone();
        let key_info = MultisigKeyInfo { key: my_pubkey.clone() };
        let peer_pubkey = match client.send_multisig_key(peer_id, name, key_info).await? {
            Ok(envelope) => {
                let (channel_name, peer_key_info) = envelope.open();
                if channel_name != name {
                    return Err(ChannelServerError::ProtocolError(format!(
                        "Mismatched channel names. Expected {name}, Received {channel_name}"
                    )));
                }
                peer_key_info
            }
            Err(err) => {
                debug!("👛️ Failed to exchange multisig keys with peer: {err}");
                return Err(ChannelServerError::ProtocolError(err.to_string()));
            }
        };
        Ok(peer_pubkey)
    }

    async fn create_new_2_of_2_wallet(
        &self,
        my_spend_key: Curve25519Secret,
        my_pubkey: Curve25519PublicKey,
        peer_key: MultisigKeyInfo,
    ) -> Result<MultisigWallet, ChannelServerError> {
        // Create a new multisig wallet with the peer's key info.
        let rpc = connect_to_rpc(&self.rpc_address).await?;
        let mut wallet = MultisigWallet::new(rpc, my_spend_key, &my_pubkey, &peer_key.key, None)?;
        let height = wallet.reset_birthday().await?;
        debug!("👛️  New Multisig wallet created with birthday at height {height}.");
        Ok(wallet)
    }

    /// Create a new multisig wallet for the merchant.
    ///
    /// 1. Create a new keypair for the wallet.
    /// 2. Return the public key to the customer.
    /// 3. Create a new multisig wallet and save it in the channel.
    async fn merchant_create_multisig_wallet(
        &self,
        envelope: MessageEnvelope<MultisigKeyInfo>,
    ) -> Result<GreaseResponse, GreaseResponse> {
        let (name, peer_key_info) = envelope.open();
        info!("👛️ Received multisig pubkey from Customer. Creating new wallet keys for channel {name}.");
        let (k, p) = Curve25519PublicKey::keypair(&mut rng());
        let wallet = self.common_create_wallet_and_advance(&name, k, p, peer_key_info).await.map_err(|e| {
            GreaseResponse::MsKeyExchange(Err(RemoteServerError::internal(format!("Failed to create new wallet: {e}"))))
        })?;
        debug!("👛️ Saved multisig data in channel. Watching for funding transaction.");
        let jpvk = wallet.joint_private_view_key().clone();
        let jpsk = wallet.joint_public_spend_key().clone();
        let _ = self
            .watch_for_funding_transaction(&name, jpvk, jpsk, Some(wallet.birthday()))
            .await
            .map_err(|e| {
                warn!("Error creating funding transaction watcher: {e}. You will need to rescan manually later.");
            })
            .ok();
        debug!("👛️ Sending public key to customer.");
        let response = MultisigKeyInfo { key: wallet.my_public_key().clone() };
        let envelope = MessageEnvelope::new(name, response);
        Ok(GreaseResponse::MsKeyExchange(Ok(envelope)))
    }

    async fn customer_create_multisig_wallet(
        &self,
        name: &str,
        my_spend_key: Curve25519Secret,
        my_pubkey: Curve25519PublicKey,
        key: MultisigKeyInfo,
    ) -> Result<MultisigWallet, ChannelServerError> {
        self.common_create_wallet_and_advance(name, my_spend_key, my_pubkey, key).await
    }

    async fn common_create_wallet_and_advance(
        &self,
        name: &str,
        my_spend_key: Curve25519Secret,
        my_pubkey: Curve25519PublicKey,
        peer_key: MultisigKeyInfo,
    ) -> Result<MultisigWallet, ChannelServerError> {
        let wallet = self.create_new_2_of_2_wallet(my_spend_key, my_pubkey, peer_key).await?;
        let data = wallet.serializable();
        let event = LifeCycleEvent::MultiSigWalletCreated(Box::new(data));
        let mut channel = self.channels.checkout(&name).await.ok_or_else(|| ChannelServerError::ChannelNotFound)?;
        channel.handle_event(event)?;
        drop(channel);
        debug!("👛️  Multisig wallet created successfully.");
        Ok(wallet)
    }

    async fn split_secrets(&self, secret: &Curve25519Secret) -> Result<MultisigSplitSecrets, ChannelServerError> {
        let split_secrets = self.delegate.split_secret_share(secret)?;
        Ok(split_secrets)
    }

    async fn customer_exchange_split_secrets(
        &self,
        peer_id: PeerId,
        name: &str,
        shards: MultisigSplitSecrets,
    ) -> Result<MultisigSplitSecrets, ChannelServerError> {
        let mut client = self.network_client.clone();
        let env = client
            .send_split_secrets(peer_id, name, shards)
            .await?
            .map_err(|e| ChannelServerError::ProtocolError(e.to_string()))?;
        let (remote_channel, shards) = env.open();
        confirm_channel_matches(&remote_channel, name)?;
        Ok(shards)
    }

    async fn common_verify_and_store_shards(
        &self,
        channel_name: &str,
        shards: ShardInfo,
    ) -> Result<(), ChannelServerError> {
        let channel = self.channels.peek(channel_name).await.ok_or(ChannelServerError::ChannelNotFound)?;
        let state = channel.state().as_establishing()?;
        let wallet =
            state.wallet().ok_or(ChannelServerError::InvalidState("Multisig wallet not available".to_string()))?;
        let key = wallet.my_spend_key.clone();
        drop(channel);
        self.delegate.verify_my_shards(&key, &shards.my_shards)?;
        trace!("👛️  My shards are correctly encrypted for channel {channel_name}.");
        // Save the shards info in the state channel.
        let mut channel = self.channels.checkout(channel_name).await.ok_or(ChannelServerError::ChannelNotFound)?;
        let event = LifeCycleEvent::KesShards(Box::new(shards));
        channel.handle_event(event)?;
        trace!("👛️  Shards are stored in channel {channel_name}.");
        Ok(())
    }

    async fn customer_verify_wallet_address(
        &self,
        peer_id: PeerId,
        name: &str,
        address: String,
    ) -> Result<bool, ChannelServerError> {
        let mut client = self.network_client.clone();
        let envelope = client.send_wallet_confirmation(peer_id, name, address).await??;
        let (remote_name, confirmation) = envelope.open();
        confirm_channel_matches(&remote_name, name)?;
        Ok(confirmation)
    }

    /// The merchant receives the split secrets from the customer and returns the customer's set of shards.
    /// This is part of the KES creation process.
    ///
    /// When receiving an [`MsSplitSecretExchange`] request, the merchant will:
    /// 1. Verify that the channel exists and is in the Establishing state.
    /// 2. Verify the received shards are valid.
    /// 3. Split the merchant's wallet spend key into shards and encrypt them.
    /// 4. Save the shards in the channel state.
    /// 5. Return the customer's shards to the customer.
    async fn merchant_exchange_split_secrets(
        &self,
        envelope: MessageEnvelope<MultisigSplitSecrets>,
    ) -> Result<GreaseResponse, GreaseResponse> {
        trace!("👛️  Split secrets exchange request received");
        let (name, my_shards) = envelope.open();
        let channel = self.channels.peek(&name).await.ok_or_else(|| GreaseResponse::ChannelNotFound)?;
        let state = channel
            .state()
            .as_establishing()
            .map_err(|e| GreaseResponse::MsSplitSecretExchange(Err(RemoteServerError::internal(e.to_string()))))?;
        let wallet = state.wallet().ok_or_else(|| {
            GreaseResponse::MsSplitSecretExchange(Err(RemoteServerError::internal(
                "Merchant's Multisig wallet is not available",
            )))
        })?;
        let key = wallet.my_spend_key.clone();
        drop(channel);
        debug!("👛️  Splitting multisig wallet spend key for customer and KES.");
        let customer_shards = self.split_secrets(&key).await.map_err(|e| {
            GreaseResponse::MsKeyExchange(Err(RemoteServerError::internal(format!(
                "Merchant could not create encrypted secret shares: {e}"
            ))))
        })?;
        let shard_info = ShardInfo { my_shards, their_shards: customer_shards.clone() };
        self.common_verify_and_store_shards(&name, shard_info.clone()).await.map_err(|e| {
            GreaseResponse::MsSplitSecretExchange(Err(RemoteServerError::internal(format!(
                "Failed to verify received shards: {e}"
            ))))
        })?;
        let envelope = MessageEnvelope::new(name, customer_shards);
        Ok(GreaseResponse::MsSplitSecretExchange(Ok(envelope)))
    }

    async fn address_matches(&self, name: &str, address: &str) -> Result<bool, ChannelServerError> {
        let channel = self.channels.peek(name).await.ok_or(ChannelServerError::ChannelNotFound)?;
        debug!("👛️  Verifying address {address} for channel {name}.");
        let state = channel.state().as_establishing()?;
        trace!("👛️  Loading wallet for channel {name}.");
        let wallet =
            state.wallet().ok_or(ChannelServerError::InvalidState("Multisig wallet not available".to_string()))?;
        let rpc = connect_to_rpc(&self.rpc_address).await?;
        let wallet = MultisigWallet::from_serializable(rpc, wallet.clone())?;
        if wallet.address().to_string() == address {
            debug!("👛️  Address {address} matches for channel {name}.");
            Ok(true)
        } else {
            Err(ChannelServerError::ProtocolError(format!(
                "Address mismatch for channel {name}. Expected {}, got {}",
                wallet.address(),
                address
            )))
        }
    }

    /// Watch for a funding transaction for the given channel.
    ///
    /// todo: This spawns an orphan watcher task that will listen for the funding transaction of the channel. add
    /// things to clean up after ourselves here
    async fn watch_for_funding_transaction(
        &self,
        name: &str,
        private_view_key: Curve25519Secret,
        public_spend_key: Curve25519PublicKey,
        birthday: Option<u64>,
    ) -> Result<(), ChannelServerError> {
        let mut client = self.network_client.clone();
        let channel_name = name.to_string();
        self.delegate
            .register_watcher(channel_name, client.clone(), private_view_key, public_spend_key, birthday)
            .await;
        let channels = self.channels.clone();
        let name = name.to_string();
        tokio::spawn(async move {
            trace!("Spawning TXf watcher for channel {name}.");
            match client.wait_for_funding_tx(&name).await {
                Ok(record) => {
                    info!("🪙️  Received funding transaction for channel {name}: {:?}", record);
                    match channels.checkout(&name).await {
                        Some(mut channel) => {
                            let event =
                                LifeCycleEvent::FundingTxConfirmed(Box::new((record.transaction_id, record.amount)));
                            match channel.handle_event(event) {
                                Ok(()) => info!("🪙️  Funding transaction for channel {name} processed successfully."),
                                Err(err) => {
                                    warn!("🪙️  Error processing funding transaction for channel {name}: {err}");
                                }
                            }
                        }
                        None => {
                            warn!("🪙️  Channel {name} not found when processing funding transaction.");
                        }
                    }
                }
                Err(err) => {
                    warn!("🪙️  Error waiting for funding transaction for channel {name}: {err}");
                }
            }
        });
        Ok(())
    }

    async fn close_channel(&self, channel_name: String, reason: String) -> Result<(), ChannelServerError> {
        info!("🖥️  Closing channel {channel_name}. {reason}");
        // TODO - initiate co-operative channel closing
        Ok(())
    }
    /// Returns the channel metadata for the given channel name, if the current lifecycle state has the information
    /// available.
    async fn get_channel_metadata(&self, channel_name: &str) -> Option<ChannelMetadata> {
        let lock = self.channels.peek(channel_name).await?;
        Some(lock.state().metadata().clone())
    }

    async fn notify_customer_of_kes(&self, channel_name: &str) -> Result<(), ChannelServerError> {
        let channel = self.channels.peek(channel_name).await.ok_or(ChannelServerError::ChannelNotFound)?;
        let peer = channel.peer_id();
        todo!();
        // let kes_info = channel
        //     .state()
        //     .kes_result_info()
        //     .ok_or(ChannelServerError::InvalidState("KES info not available".to_string()))?;
        // let mut client = self.network_client.clone();
        // let envelope = client.send_kes_info(peer, channel_name.into(), kes_info).await??;
        // let (channel, ratified) = envelope.open();
        // if channel != channel_name {
        //     return Err(ChannelServerError::ProtocolError(format!(
        //         "Mismatched channel names. Expected {channel_name}, Received {channel}"
        //     )));
        // }
        // match ratified {
        //     true => {
        //         info!(" 🖥️  The customer ratified the KES. We can start watching for funding transactions.");
        //         Ok(())
        //     }
        //     false => {
        //         warn!(" 🖥️  The customer rejected the KES. Closing channel.");
        //         Err(ChannelServerError::KesError(KesError::KesRejected))
        //     }
        // }
    }

    async fn create_funding_transaction(&self, channel_name: &str) -> Result<(), ChannelServerError> {
        // todo: implement funding transaction creation
        Ok(())
    }

    /// Submit a funding transaction receipt directly to the request handler.
    ///
    /// It is assumed that this transaction completely funds the relevant side of the channel. No verifications or
    /// validations are done here.
    pub async fn submit_funding_transaction(
        &self,
        name: &str,
        tx: FundingTransaction,
    ) -> Result<(), ChannelServerError> {
        let mut channel = self.channels.checkout(name).await.ok_or(ChannelServerError::ChannelNotFound)?;
        let event = LifeCycleEvent::FundingTxConfirmed(Box::new((tx.transaction_id, tx.amount)));
        channel.handle_event(event)?;
        Ok(())
    }

    // ------------------------------   State machine handling functions (Common)   ----------------------------------//

    //---------------------------------   Network request handling functions   ---------------------------------//

    /// Business logic handling for payment channel requests.
    ///
    /// This function is called by the network event loop when a new inbound request is received.
    /// It takes the request, performs the relevant work, and then calls the appropriate method on the network client
    /// to respond.
    async fn handle_incoming_grease_request(
        &self,
        request: GreaseRequest,
        return_chute: ResponseChannel<GreaseResponse>,
    ) {
        let name = request.channel_name();
        let response = if self.channels.exists(&name).await {
            self.handle_request_for_existing_channel(request).await
        } else {
            // Channel doesn't exist, so this must be a new proposal, or we can´t do anything about it
            match &request {
                GreaseRequest::ProposeChannelRequest(proposal) => self.merchant_handle_proposal(proposal).await,
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

    async fn handle_request_for_existing_channel(&self, request: GreaseRequest) -> GreaseResponse {
        // Note: The channel name has already been checked against the incoming message.
        match request {
            GreaseRequest::ProposeChannelRequest(_) => {
                GreaseResponse::Error("Cannot create a new channel. Channel exists.".into())
            }
            GreaseRequest::MsKeyExchange(envelope) => {
                self.merchant_create_multisig_wallet(envelope).await.unwrap_or_else(|early| early)
            }
            GreaseRequest::MsSplitSecretExchange(envelope) => {
                self.merchant_exchange_split_secrets(envelope).await.unwrap_or_else(|early| early)
            }
            GreaseRequest::ConfirmMsAddress(envelope) => {
                trace!("🖥️  Customer: Confirm multisig address request received");
                let (channel_name, address) = envelope.open();
                let response = self.address_matches(&channel_name, &address).await.unwrap_or(false);
                let envelope = MessageEnvelope::new(channel_name, response);
                GreaseResponse::ConfirmMsAddress(Ok(envelope))
            }
            GreaseRequest::VerifyKes(envelope) => {
                trace!("🖥️  Customer: Verify KES request received");
                let (channel_name, kes_info) = envelope.open();
                todo!()
                // let response = self.verify_kes(&channel_name, kes_info).await.unwrap_or(false);
                // let envelope = MessageEnvelope::new(channel_name, response);
                // GreaseResponse::AcceptKes(Ok(envelope))
            }
            GreaseRequest::StartChannelUpdate(request) => {
                let (name, update) = request.open();
                trace!("🖥️  Balance update request received for channel {name}");
                let response = self.respond_to_update_request(name, update).await;
                GreaseResponse::ConfirmUpdate(response)
            }
            GreaseRequest::FinalizeChannelUpdate(request) => {
                let (name, update) = request.open();
                trace!("🖥️  Channel update finalization request received for channel {name}");
                self.respond_to_finalization(name, update).await;
                GreaseResponse::NoResponse
            }
        }
    }

    // ----------------------------             Channel update methods              ----------------------------------//
    async fn update_balance_protocol(
        &self,
        channel_name: &str,
        delta: MoneroDelta,
    ) -> Result<ChannelUpdateFinalization, ChannelServerError> {
        // Get peer ID for the channel
        let channel = self.channels.peek(channel_name).await.ok_or(ChannelServerError::ChannelNotFound)?;
        let peer = channel.peer_id().clone();
        drop(channel);
        // 1. Generating the necessary proofs for the update.
        let update = self.generate_update_proofs(channel_name, delta).await?;
        // 2. Send the update request w/ proofs to the peer and 3, wait for the remote peer to confirm/reject
        let peer_proofs = self.send_update_proofs(channel_name, peer, update).await?;
        let peer_update = match peer_proofs {
            StartChannelUpdateConfirmation::Rejected(rej) => {
                info!("🖥️  Channel update was rejected by peer: {}", rej.reason);
                debug!("🖥️  Channel rejection. Peer's last update was: {:?}", rej.last_update);
                // TODO - use the rej.last_update to do error recovery if needed
                return Err(ChannelServerError::UpdateError(rej.reason));
            }
            StartChannelUpdateConfirmation::Confirmed(update) => {
                trace!("🖥️  Channel update confirmed by peer. Proceeding to verification.");
                update
            }
        };
        // 4. Verify the partial signature and transaction.
        let verification_result = self.verify_peer_proofs_and_tx(channel_name, peer_update).await?;
        // 5. Inform peer of the result of the verification.
        self.send_finalization(channel_name, peer, verification_result.clone()).await;
        // 6. Return the same result to the client.
        Ok(verification_result)
    }

    async fn generate_update_proofs(
        &self,
        name: &str,
        delta: MoneroDelta,
    ) -> Result<ChannelUpdate, ChannelServerError> {
        let channel = self.channels.peek(name).await.ok_or(ChannelServerError::ChannelNotFound)?;
        todo!()
        // let last_update = channel.state().latest_secrets().ok_or(ChannelServerError::InvalidState(format!(
        //     "Channel {name} was not in Open state"
        // )))?;
        // let update = self.delegate.generate_update_proofs(delta, &last_update)?;
        // Ok(update)
    }

    async fn send_update_proofs(
        &self,
        name: &str,
        peer: PeerId,
        update: ChannelUpdate,
    ) -> Result<StartChannelUpdateConfirmation, ChannelServerError> {
        let mut client = self.network_client.clone();
        let result = client.update_balance(peer, name, update).await?;
        trace!("🖥️  Channel update: Peer responded with an accept/reject message to our initial update request.");
        Ok(result)
    }

    async fn verify_peer_proofs_and_tx(
        &self,
        name: &str,
        confirmation: ChannelUpdate,
    ) -> Result<ChannelUpdateFinalization, ChannelServerError> {
        let proofs_ok = self.verify_peer_proofs(name, &confirmation).await;
        todo!("verify_peer_proofs not implemented yet");
    }

    async fn send_finalization(&self, name: &str, peer: PeerId, confirmation: ChannelUpdateFinalization) {
        todo!()
    }

    async fn verify_peer_proofs(&self, name: &str, confirmation: &ChannelUpdate) -> Result<(), UpdateError> {
        todo!()
    }

    async fn get_latest_update(&self, name: &str) -> Result<Option<ChannelUpdate>, ChannelServerError> {
        let channel = self.channels.peek(name).await.ok_or(ChannelServerError::ChannelNotFound)?;
        todo!()
    }

    /// Carry out the steps need to handle a payment channel update as a Responder. This entails:
    /// 1. Verifying the update proofs and transaction partial signature. If they are invalid, we reject the update.
    /// 2. Generate our own update proofs.
    /// 3. Return the update confirmation response.
    /// 4. Wait for the finalization from the peer and note the outcome.
    async fn respond_to_update_request(
        &self,
        name: String,
        update: ChannelUpdate,
    ) -> Result<MessageEnvelope<StartChannelUpdateConfirmation>, RemoteServerError> {
        if let Err(err) = self.verify_peer_proofs(&name, &update).await {
            info!("🖥️  Update proofs are invalid. Rejecting update request. {err}");
            let my_update = self.get_latest_update(&name).await?;
            let rej = PaymentRejection::new(err, my_update);
            let result = StartChannelUpdateConfirmation::Rejected(rej);
            return Ok(MessageEnvelope::new(name, result));
        }
        let update = self.generate_update_proofs(&name, update.delta).await?;
        // TODO - add a pending update to the channel state
        let confirmation = StartChannelUpdateConfirmation::Confirmed(update);
        Ok(MessageEnvelope::new(name, confirmation))
    }

    async fn respond_to_finalization(&self, name: String, update: ChannelUpdateFinalization) {
        match update {
            ChannelUpdateFinalization::Finalized { txid, balances } => {
                trace!(
                    "⚡️  Channel update finalized with txid {txid}. Merchant: {}. Customer: {}",
                    balances.merchant,
                    balances.customer
                );
                todo!("move the pending update in the state to the updates Vector");
            }
            ChannelUpdateFinalization::Rejected(rej) => {
                info!("⚡️  Channel update was rejected at the final hurdle :(. Reason: {}", rej.reason);
                todo!("Drop the pending update in the state");
            }
        }
    }
}
//------------------------------------------- Minor helper functions ---------------------------------------------//

#[derive(Debug)]
pub enum TodoListItem {
    ConstructFundingTransaction { channel: String },
    CloseChannel { channel: String, reason: String },
}

impl Display for TodoListItem {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            TodoListItem::ConstructFundingTransaction { channel: channel_name } => {
                write!(f, "Construct funding transaction for {channel_name}")
            }
            TodoListItem::CloseChannel { channel: channel_name, reason } => {
                write!(f, "Close channel {channel_name}: {reason}")
            }
        }
    }
}

impl TodoListItem {
    pub fn channel_name(&self) -> String {
        match self {
            TodoListItem::ConstructFundingTransaction { channel } => channel.clone(),
            TodoListItem::CloseChannel { channel, .. } => channel.clone(),
        }
    }
}

pub enum NextAction {
    /// Task completed successfully. Continue as normal
    Continue,
    /// Close the channel with reason given
    Abort { channel_name: String, reason: String },
}

fn confirm_channel_matches(remote: &str, local: &str) -> Result<(), ChannelServerError> {
    if remote != local {
        return Err(ChannelServerError::ProtocolError(format!(
            "Mismatched channel names. Expected {local}, Received {remote}"
        )));
    }
    Ok(())
}

#[cfg(feature = "graveyard")]
mod graveyard {
    use super::*;

    impl<D> InnerEventHandler<D>
    where
        D: GreaseChannelDelegate,
    {
        // Before creating a new 2-of-2 wallet, check the following:
        // 1. The channel exists
        // 2. The channel is in the Establishing state
        // 3. The role of this side of the channel is Merchant
        async fn pre_wallet_checks(
            &self,
            channel_name: &str,
        ) -> Result<(Network, ChannelId, crate::identity::ContactInfo), crate::errors::ChannelServerError> {
            match self.channels.peek(channel_name).await {
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
                            Err(crate::errors::ChannelServerError::NotMerchantRole)
                        } else {
                            Ok(state_needed)
                        }
                    }
                    _ => Err(crate::errors::ChannelServerError::InvalidState(format!(
                        "Channel {channel_name} is not in the Establishing state"
                    ))),
                },
                None => Err(crate::errors::ChannelServerError::ChannelNotFound),
            }
        }

        /// Called by the customer when the merchant sends KES data over for the customer to verify.
        ///
        /// Calls out to the delegate to verify the KES data, and returns the decision whether the customer ratified the
        /// KES or not.
        async fn verify_kes(&self, channel_name: &str, kes_info: KesInitializationResult) -> Option<bool> {
            let kes = self
                .delegate
                .with_kes()
                .map_err(|e| warn!("🖥️  Customer: KES delegate function was not available: {e}"))
                .ok()?;
            let accepted = kes
                .verify(kes_info.clone())
                .await
                .map_err(|e| warn!("🖥️  Customer: KES delegate function did not return successfully: {e}"))
                .ok()?;
            if accepted {
                let mut channel = self.channels.checkout(channel_name).await?;
                channel
                    .save_verified_kes_result(kes_info)
                    .await
                    .map_err(|e| warn!("🖥️  Customer: failed to handle KES verification event. {e}"))
                    .ok()?;
            }
            Some(accepted)
        }
    }
}
