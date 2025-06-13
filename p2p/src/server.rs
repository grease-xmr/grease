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
use libgrease::balance::Balances;
use libgrease::channel_metadata::ChannelMetadata;
use libgrease::crypto::keys::{Curve25519PublicKey, Curve25519Secret, PublicKey};
use libgrease::crypto::zk_objects::{
    generate_txc0_nonces, GenericPoint, GenericScalar, KesProof, PublicProof0, ShardInfo, UpdateInfo, UpdateProofs,
};
use libgrease::monero::data_objects::{
    FundingTransaction, MessageEnvelope, MultisigKeyInfo, MultisigSplitSecrets, MultisigSplitSecretsResponse, Updated,
};
use libgrease::state_machine::error::LifeCycleError;
use libgrease::state_machine::lifecycle::{ChannelState, LifeCycle, LifecycleStage};
use libgrease::state_machine::{ChannelCloseRecord, LifeCycleEvent, NewChannelBuilder, ProposedChannelInfo};
use libp2p::request_response::ResponseChannel;
use libp2p::{Multiaddr, PeerId};
use log::*;
use monero::Network;
use rand::rng;
use std::path::Path;
use tokio::sync::OwnedRwLockWriteGuard;
use tokio::task::JoinHandle;
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
            }
        });
        Ok(Self { id, inner, event_loop_handle, event_handler_handle })
    }

    pub fn controller(&self) -> InnerEventHandler<D> {
        self.inner.clone()
    }

    /// Ensures that there's an active connection to the `name`d channel's peer.
    pub async fn ensure_connection(&self, name: &str) -> Result<(), PeerConnectionError> {
        self.inner.ensure_connection(name).await
    }

    pub fn contact_info(&self) -> ContactInfo {
        self.id.contact_info()
    }

    pub async fn start_listening(&mut self, at: Multiaddr) -> Result<(), PeerConnectionError> {
        self.inner.start_listening(at).await
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

    /// Returns the multisig wallet address for the given channel and network.
    pub async fn wallet_address(&self, channel_name: &str, network: &str) -> Result<String, ChannelServerError> {
        let channel = self.inner.channels.peek(channel_name).await.ok_or(ChannelServerError::ChannelNotFound)?;
        let network = match network.to_ascii_lowercase().as_str() {
            "mainnet" => Network::Mainnet,
            "testnet" => Network::Testnet,
            "stagenet" => Network::Stagenet,
            _ => Network::Mainnet,
        };
        channel
            .state()
            .wallet_address(network)
            .ok_or_else(|| ChannelServerError::InvalidState("Wallet not available".to_string()))
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
    ///   1. Generate a new multisig wallet
    ///      1. Create a new keypair for the wallet. This is always a Curve25519 keypair.
    ///      2. Exchange the public keys with the merchant.
    ///      3. Create a new multisig wallet with the public keys.
    ///   2. Split and encrypt the wallet spend key secrets to give to the KES and merchant.
    ///   3. Verify the wallet address with the peer.
    pub async fn establish_new_channel(&self, proposal: NewChannelProposal) -> Result<String, ChannelServerError> {
        self.inner.customer_establish_new_channel(proposal).await
    }

    /// A convenience function for [`Self::update_balance`] that pays the given amount from customer to merchant.
    ///
    /// Refer to [`Self::update_balance`] for more details on the update process.
    pub async fn pay(&self, channel: &str, amount: MoneroAmount) -> Result<Updated, ChannelServerError> {
        let delta = MoneroDelta::from(amount);
        self.update_balance(channel, delta).await
    }

    /// Start the co-operative close process for a channel.
    pub async fn close_channel(&self, channel: &str) -> Result<Balances, ChannelServerError> {
        self.ensure_connection(channel).await?;
        self.inner.close_channel(channel).await
    }

    /// Perform a channel update.
    ///
    /// It is assumed that the user has verified that the payment is acceptable. There is no recourse to interrupt
    /// the update process manually at this point (although the update can still fail for a myriad reasons).
    pub async fn update_balance(&self, channel: &str, delta: MoneroDelta) -> Result<Updated, ChannelServerError> {
        self.ensure_connection(channel).await?;
        self.inner.customer_channel_update(channel, delta).await
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
        }
    }
}

impl<D> InnerEventHandler<D>
where
    D: GreaseChannelDelegate,
{
    fn new(client: Client, channels: PaymentChannels, delegate: D, rpc_address: String) -> Self {
        Self { network_client: client, channels, delegate, rpc_address }
    }

    async fn start_listening(&mut self, addr: Multiaddr) -> Result<(), PeerConnectionError> {
        self.network_client.start_listening(addr).await?;
        Ok(())
    }

    async fn ensure_connection(&self, name: &str) -> Result<(), PeerConnectionError> {
        debug!("Ensuring connection to peer for channel {name}");
        let mut client = self.network_client.clone();
        let channel = self.channels.peek(name).await.ok_or(PeerConnectionError::ChannelNotFound(name.to_string()))?;
        let contact_info = channel.peer_info().clone();
        drop(channel);
        let current_peers = client.connected_peers().await?;
        if current_peers.contains(&contact_info.peer_id) {
            debug!("Channel {name} is already connected. Great!");
        } else {
            client.dial(contact_info.address.clone()).await?;
            info!(
                "Reconnected to peer {}({}) for channel {name}",
                contact_info.name, contact_info.peer_id
            );
        }
        Ok(())
    }

    // ----------------------------                Proposal handling                ----------------------------------//

    /// Establish a new payment channel with a merchant.
    ///
    /// The steps involved are:
    /// 1. Complete the proposal phase with the merchant.
    /// 2. Move to the Establishing phase
    ///    1. Generate a new multisig wallet
    ///       1. Create a new keypair for the wallet. This is always a Curve25519 keypair.
    ///       2. Exchange the public keys with the merchant.
    ///       3. Create a new multisig wallet with the public keys.
    ///    2. Split and encrypt the wallet spend key secrets to give to the KES and merchant.
    ///    3. Verify the wallet address with the peer.
    ///    4. Watch for the funding transaction to be confirmed.
    ///    5. Generate the proofs to TXc0 (along with witness_0).
    ///    6. Exchange proofs with the merchant.
    pub async fn customer_establish_new_channel(
        &self,
        proposal: NewChannelProposal,
    ) -> Result<String, ChannelServerError> {
        // 1. Proposal phase
        info!("💍️ Sending new channel proposal to merchant");
        // Needed for KES verification later..
        let kes_public_key = proposal.seed.kes_public_key.clone();
        let name = self.customer_send_proposal(proposal).await?.map_err(ChannelServerError::ProposalRejected)?;
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
        let peer_pubkey = wallet.peer_public_key();
        let merchant_shards = self.split_secrets(wallet.my_spend_key(), &kes_public_key, peer_pubkey).await?;
        let shards_and_kes =
            self.customer_exchange_split_secrets(peer_id, &name, merchant_shards.clone(), &kes_public_key).await?;
        debug!("👛️ Merchant provided their encrypted shards for channel {name}");
        let my_shards =
            MultisigSplitSecrets { peer_shard: shards_and_kes.peer_shard, kes_shard: shards_and_kes.kes_shard };
        let shards = ShardInfo { my_shards, their_shards: merchant_shards };
        self.common_verify_and_store_shards(&name, shards, shards_and_kes.kes_proof).await?;
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
        info!("👁️‍🗨️ Generating initial ZK-proofs for channel {name}.");
        let peer_proof = self.generate_and_store_witness0(&name).await?;
        info!("👁️‍🗨️ Exchanging ZK-proofs proofs for channel {name} with merchant.");
        let merchant_proof = self.customer_send_proofs0(&name, peer_id, peer_proof).await?;
        info!("👁️‍🗨️ Verifying merchant's initial transaction proof for channel {name}. (ZK-Witness0 proof)");
        self.verify_proof0(&name, &merchant_proof).await?;
        info!("👁️‍🗨️ Merchant's initial transaction proof is VALID for channel {name}. (ZK-Witness0 proof)");
        self.store_public_proof0(&name, merchant_proof).await?;
        info!("👁️‍🗨️ Stored Merchant's initial transaction proof for channel {name}.");
        // This is as far as we can take the channel establishment process for now.
        // If Txf has already been confirmed, then we will be in the Established state.
        Ok(name)
    }

    async fn rescan_for_funding(&self, name: &str) -> Option<()> {
        let channel = self.channels.peek(name).await?;
        if !channel.is_establishing() {
            debug!("Channel {name} is not establishing, so no need to scan for funding txnsaction.");
            return None;
        }
        let wallet_info = match channel.state().as_establishing().ok()?.wallet() {
            Some(info) => info.clone(),
            None => {
                debug!("Channel {name} does not have a wallet, so no need to scan for funding transaction.");
                return None;
            }
        };
        drop(channel);
        let pvt_vk = wallet_info.joint_private_view_key.clone();
        let pub_sk = wallet_info.joint_public_spend_key.clone();
        let bday = wallet_info.birthday.saturating_sub(5);
        trace!("Scanning blockchain from block {bday} for funding transaction for channel {name}");
        self.watch_for_funding_transaction(name, pvt_vk, pub_sk, Some(bday))
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
        proposal: NewChannelProposal,
    ) -> Result<Result<String, RejectChannelProposal>, PeerConnectionError> {
        let mut client = self.network_client.clone();
        let address = proposal.contact_info_proposee.dial_address();
        // todo: check what happens if there's already a connection?
        client.dial(address).await?;
        trace!("Sending channel proposal to merchant.");
        let state = self.customer_create_new_state(proposal.clone());
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
                    .map_err(|_| RejectChannelProposal::internal("Error creating new channel"))
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
    fn customer_create_new_state(&self, prop: NewChannelProposal) -> ChannelState {
        let new_state = NewChannelBuilder::new(prop.seed.role)
            .with_my_user_label(&prop.proposer_label)
            .with_peer_label(&prop.seed.user_label)
            .with_merchant_initial_balance(prop.seed.initial_balances.merchant)
            .with_customer_initial_balance(prop.seed.initial_balances.customer)
            .with_kes_public_key(prop.seed.kes_public_key)
            .with_customer_closing_address(prop.closing_address)
            .with_merchant_closing_address(prop.seed.closing_address)
            .build::<blake2::Blake2b512>()
            .expect("Missing new channel state data");
        new_state.to_channel_state()
    }

    // TODO - the merchant label should be used to extract data that was generated ourselves, rather than trusting
    // the proposal.
    fn merchant_create_new_state(&self, prop: NewChannelProposal) -> ChannelState {
        let new_state = NewChannelBuilder::new(prop.seed.role.other())
            .with_my_user_label(&prop.seed.user_label)
            .with_peer_label(&prop.proposer_label)
            .with_merchant_initial_balance(prop.seed.initial_balances.merchant)
            .with_customer_initial_balance(prop.seed.initial_balances.customer)
            .with_kes_public_key(prop.seed.kes_public_key)
            .with_customer_closing_address(prop.closing_address)
            .with_merchant_closing_address(prop.seed.closing_address)
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
                info!(
                    "💍️ Proposal for channel {name} accepted from customer: {}",
                    data.contact_info_proposer.name
                );
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
        // Construct the new channel
        let peer_info = data.contact_info_proposer.clone();
        let info = data.proposed_channel_info();
        let new_state = self.merchant_create_new_state(data);
        let name = self.common_create_channel(new_state, peer_info, info).await.map_err(|e| {
            warn!("Error creating new channel {e}");
            RejectChannelProposal::internal("Error creating new channel")
        })?;
        Ok(name)
    }

    //----------------------------        Channel establishment functions         ----------------------------------//

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
        let mut channel = self.channels.checkout(name).await.ok_or_else(|| ChannelServerError::ChannelNotFound)?;
        channel.handle_event(event)?;
        drop(channel);
        debug!("👛️  Multisig wallet created successfully.");
        Ok(wallet)
    }

    async fn split_secrets(
        &self,
        secret: &Curve25519Secret,
        kes_pubkey: &str,
        peer: &Curve25519PublicKey,
    ) -> Result<MultisigSplitSecrets, ChannelServerError> {
        let kes = GenericPoint::from_hex(kes_pubkey)
            .map_err(|e| ChannelServerError::ProtocolError(format!("Failed to derive KES public key: {e}.")))?;
        let split_secrets = self.delegate.split_secret_share(secret, &kes, peer)?;
        Ok(split_secrets)
    }

    async fn customer_exchange_split_secrets(
        &self,
        peer_id: PeerId,
        name: &str,
        shards_for_merchant: MultisigSplitSecrets,
        kes_public_key: &str,
    ) -> Result<MultisigSplitSecretsResponse, ChannelServerError> {
        let mut client = self.network_client.clone();
        let merchant_kes_shard = shards_for_merchant.kes_shard.clone();
        let env = client
            .send_split_secrets(peer_id, name, shards_for_merchant)
            .await?
            .map_err(|e| ChannelServerError::ProtocolError(e.to_string()))?;
        let (remote_channel, shards_for_customer) = env.open();
        confirm_channel_matches(&remote_channel, name)?;
        info!("🔐️ Verifying KES proofs for channel {name}.");
        let pubkey = GenericPoint::from_hex(kes_public_key)
            .map_err(|e| ChannelServerError::ProtocolError(format!("Failed to derive KES public key: {e}.")))?;
        self.delegate
            .verify_kes_proofs(
                name.to_string(),
                merchant_kes_shard,
                shards_for_customer.kes_shard.clone(),
                pubkey,
                shards_for_customer.kes_proof.clone(),
            )
            .await?;
        trace!("🔐️ KES proofs verified for channel {name}.");
        Ok(shards_for_customer)
    }

    async fn common_verify_and_store_shards(
        &self,
        channel_name: &str,
        shards: ShardInfo,
        kes_proof: KesProof,
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
        // Save the KES proof in the state channel.
        let kes_event = LifeCycleEvent::KesCreated(Box::new(kes_proof));
        channel.handle_event(kes_event)?;
        trace!("👛️  KES proof is stored in channel {channel_name}.");
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
        let channel = self.channels.peek(&name).await.ok_or(GreaseResponse::MsSplitSecretExchange(Err(
            RemoteServerError::ChannelDoesNotExist,
        )))?;
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
        let peer = wallet.peer_public_key().clone();
        let kes_pubkey = channel.state().metadata().kes_public_key().to_string();
        drop(channel);
        debug!("👛️  Splitting multisig wallet spend key for customer and KES.");
        let customer_shards = self.split_secrets(&key, &kes_pubkey, &peer).await.map_err(|e| {
            GreaseResponse::MsKeyExchange(Err(RemoteServerError::internal(format!(
                "Merchant could not create encrypted secret shares: {e}"
            ))))
        })?;

        info!("🔐️ Establishing KES.");
        // Remember, `my_shards` are the shards FOR ME. So the customer's KES-encrypted secret is in
        // `my_shards.kes_shard`.
        let kes = GenericPoint::from_hex(&kes_pubkey).map_err(|e| {
            GreaseResponse::MsSplitSecretExchange(Err(RemoteServerError::InternalError(format!(
                "Failed to derive KES public key: {e}."
            ))))
        })?;
        let proof = self
            .delegate
            .create_kes_proofs(
                name.clone(),
                my_shards.kes_shard.clone(),
                customer_shards.kes_shard.clone(),
                kes,
            )
            .await
            .map_err(|e| {
                GreaseResponse::MsSplitSecretExchange(Err(RemoteServerError::internal(format!(
                    "Failed to create KES proofs: {e}"
                ))))
            })?;
        info!("🔐️ KES established for channel {name}.");
        let shard_info = ShardInfo { my_shards, their_shards: customer_shards.clone() };
        self.common_verify_and_store_shards(&name, shard_info.clone(), proof.clone()).await.map_err(|e| {
            GreaseResponse::MsSplitSecretExchange(Err(RemoteServerError::internal(format!(
                "Failed to verify received shards: {e}"
            ))))
        })?;
        let response = MultisigSplitSecretsResponse {
            peer_shard: customer_shards.peer_shard,
            kes_shard: customer_shards.kes_shard,
            kes_proof: proof,
        };
        let envelope = MessageEnvelope::new(name, response);
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

    async fn generate_and_store_witness0(&self, name: &str) -> Result<PublicProof0, ChannelServerError> {
        let channel = self.channels.peek(name).await.ok_or(ChannelServerError::ChannelNotFound)?;
        let metadata = channel.state().metadata().clone();
        drop(channel);
        debug!("👁️‍🗨️ Generating witness_0 proof for channel {name}.");
        let inputs = generate_txc0_nonces(&mut rand::rng());
        let proof = self.delegate.generate_initial_proofs(inputs, &metadata).await?;
        let pub_proof = proof.public_only();
        debug!("👁️‍🗨️ Storing witness_0 proof for channel {name}.");
        let event = LifeCycleEvent::MyProof0Generated(Box::new(proof));
        let mut channel = self.channels.checkout(name).await.ok_or(ChannelServerError::ChannelNotFound)?;
        channel.handle_event(event)?;
        Ok(pub_proof)
    }

    async fn customer_send_proofs0(
        &self,
        name: &str,
        peer_id: PeerId,
        proof: PublicProof0,
    ) -> Result<PublicProof0, ChannelServerError> {
        debug!("👁️‍🗨️ Sending public witness_0 proof to peer for channel {name}.");
        let mut client = self.network_client.clone();
        let proof = client.send_proof0(peer_id, name, proof).await??;
        let (remote_name, remote_proof) = proof.open();
        confirm_channel_matches(&remote_name, name)?;
        debug!("👁️‍🗨️ Received witness_0 proof from peer for channel {name}.");
        Ok(remote_proof)
    }

    async fn store_public_proof0(&self, name: &str, peer_proof: PublicProof0) -> Result<(), ChannelServerError> {
        let mut channel = self.channels.checkout(name).await.ok_or(ChannelServerError::ChannelNotFound)?;
        let event = LifeCycleEvent::PeerProof0Received(Box::new(peer_proof));
        channel.handle_event(event)?;
        debug!("👁️‍🗨️ Stored peer's witness_0 proof for channel {name}.");
        Ok(())
    }

    /// The merchant receives the witness0 proof from the customer and returns their own proof.
    async fn merchant_exchange_proof0(
        &self,
        envelope: MessageEnvelope<PublicProof0>,
    ) -> Result<GreaseResponse, GreaseResponse> {
        debug!("👁️‍🗨️  Received witness_0 proof exchange request");
        let (name, peer_proof) = envelope.open();
        debug!("👁️‍🗨️  Verifying received witness0 proof for channel {name}.");
        self.verify_proof0(&name, &peer_proof)
            .await
            .map_err(|e| GreaseResponse::ExchangeProof0(Err(RemoteServerError::InvalidProof(e.to_string()))))?;
        debug!("👁️‍🗨️  Storing witness0 proof for channel {name}.");
        self.store_public_proof0(&name, peer_proof).await.map_err(|e| {
            GreaseResponse::ExchangeProof0(Err(RemoteServerError::internal(format!(
                "Error storing witness_0 proof: {e}"
            ))))
        })?;
        debug!("👁️‍🗨️  Customer's witness0 proof is VALID for channel {name}.");
        let pub_proof = self.generate_and_store_witness0(&name).await.map_err(|e| {
            GreaseResponse::ExchangeProof0(Err(RemoteServerError::internal(format!(
                "Failed to generate witness_0 proof: {e}"
            ))))
        })?;
        debug!("👁️‍🗨️  Sending witness_0 proof to customer for channel {name}.");
        let envelope = MessageEnvelope::new(name, pub_proof);
        Ok(GreaseResponse::ExchangeProof0(Ok(envelope)))
    }

    async fn verify_proof0(&self, name: &str, proof: &PublicProof0) -> Result<(), ChannelServerError> {
        let channel = self.channels.peek(name).await.ok_or(ChannelServerError::ChannelNotFound)?;
        let metadata = channel.state().metadata().clone();
        drop(channel);
        self.delegate.verify_initial_proofs(proof, &metadata).await?;
        Ok(())
    }

    /// Returns the channel metadata for the given channel name, if the current lifecycle state has the information
    /// available.
    async fn get_channel_metadata(&self, channel_name: &str) -> Option<ChannelMetadata> {
        let lock = self.channels.peek(channel_name).await?;
        Some(lock.state().metadata().clone())
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

    // ----------------------------             Channel update methods              ----------------------------------//
    async fn customer_channel_update(&self, name: &str, delta: MoneroDelta) -> Result<Updated, ChannelServerError> {
        let proofs = self.generate_next_witness(name, delta).await?;
        let index = proofs.private_outputs.update_count;
        info!("💸️  Exchange proofs for update {index} in channel {name} with merchant");
        let update_info = UpdateInfo { index, delta, proof: proofs.public_only() };
        let merchant_proofs = self.customer_send_update(name, update_info).await?;
        info!("💸️  Received update {index} proofs for channel {name} for merchant");
        self.validate_update_proofs(name, index, delta, &merchant_proofs).await?;
        let result = self.store_update_proofs(name, proofs, merchant_proofs).await?;
        Ok(result)
    }

    async fn generate_next_witness(
        &self,
        channel_name: &str,
        delta: MoneroDelta,
    ) -> Result<UpdateProofs, ChannelServerError> {
        debug!("💸️  Fetching last update for channel {channel_name}.");
        let channel = self.channels.peek(channel_name).await.ok_or(ChannelServerError::ChannelNotFound)?;
        let state = channel.state().as_open()?;
        let last_witness = state.current_witness();
        let mut index = state.update_count();
        let metadata = state.metadata().clone();
        drop(channel);
        index += 1;
        info!("💸️  Generating witness_{index} for channel {channel_name}.");
        let blinding_dleq = GenericScalar::random(&mut rand::rng());
        let proofs = self.delegate.generate_update(index, delta, &last_witness, &blinding_dleq, &metadata).await?;
        info!("💸️  Witness_{index} for channel {channel_name} successfully generated.");
        Ok(proofs)
    }

    async fn customer_send_update(&self, name: &str, info: UpdateInfo) -> Result<UpdateInfo, ChannelServerError> {
        let channel = self.channels.peek(name).await.ok_or(ChannelServerError::ChannelNotFound)?;
        let peer = channel.peer_id();
        drop(channel);
        let mut client = self.network_client.clone();
        debug!("💸️  Exchanging update {} proofs with merchant for channel {name}.", info.index);
        let merchant_update = client.send_update(peer, name, info).await??;
        let (remote_name, remote_proofs) = merchant_update.open();
        confirm_channel_matches(&remote_name, name)?;
        Ok(remote_proofs)
    }

    async fn merchant_exchange_update(
        &self,
        envelope: MessageEnvelope<UpdateInfo>,
    ) -> Result<GreaseResponse, GreaseResponse> {
        let (name, info) = envelope.open();
        info!("💸️  Received new channel update request from customer for channel {name}");
        let delta = info.delta;
        let channel = self.channels.peek(&name).await.ok_or_else(|| {
            GreaseResponse::ChannelUpdate(Err(RemoteServerError::internal(format!("Channel {name} not found."))))
        })?;
        let state = channel.state().as_open().map_err(|e| {
            GreaseResponse::ChannelUpdate(Err(RemoteServerError::internal(format!("Channel is not open. {e}"))))
        })?;
        // Expect the update index to be one more than the current update count.
        let index = state.update_count() + 1;
        drop(channel);
        info!("💸️  Validating update {index} for channel {name}");
        self.validate_update_proofs(&name, index, delta, &info)
            .await
            .map_err(|e| GreaseResponse::ChannelUpdate(Err(RemoteServerError::InvalidProof(e.to_string()))))?;
        info!("💸️  Validating update {index} for channel {name} is VALID.");
        let my_proofs = self.generate_next_witness(&name, delta).await.map_err(|e| {
            GreaseResponse::ChannelUpdate(Err(RemoteServerError::internal(format!(
                "Could not generate update proof. {e}"
            ))))
        })?;
        let proof = my_proofs.public_only();
        let updated = self.store_update_proofs(&name, my_proofs, info).await.map_err(|e| {
            GreaseResponse::ChannelUpdate(Err(RemoteServerError::internal(format!(
                "Could not generate update proof. {e}"
            ))))
        })?;
        info!(
            "💸️  Channel {name} update #{}. Merchant: {} XMR. Customer: {} XMR",
            updated.update_count, updated.new_balances.merchant, updated.new_balances.customer
        );
        let peer_proofs = UpdateInfo { index, delta, proof };
        let envelope = MessageEnvelope::new(name, peer_proofs);
        Ok(GreaseResponse::ChannelUpdate(Ok(envelope)))
    }

    async fn validate_update_proofs(
        &self,
        name: &str,
        index: u64,
        delta: MoneroDelta,
        peer_proofs: &UpdateInfo,
    ) -> Result<(), ChannelServerError> {
        // The update index must match the one we generated.
        if peer_proofs.index != index {
            return Err(ChannelServerError::ProtocolError(format!(
                "Mismatched update index. Expected {index}, got {}",
                peer_proofs.index
            )));
        }
        // The update delta must match the one we requested.
        if peer_proofs.delta != delta {
            return Err(ChannelServerError::ProtocolError(format!(
                "Mismatched update delta. Expected {:?}, got {:?}",
                delta, peer_proofs.delta
            )));
        }
        // Verify the peer's proofs.
        debug!("💸️  Validating peer's update {index} proofs for channel {name}.");
        let channel = self.channels.peek(name).await.ok_or(ChannelServerError::ChannelNotFound)?;
        let metadata = channel.state().metadata().clone();
        drop(channel);
        self.delegate.verify_update(index, delta, &peer_proofs.proof, &metadata).await?;
        debug!("💸️  Peer's update {index} proofs are VALID for channel {name}.");
        Ok(())
    }

    // Make sure proofs are validated before calling this!
    async fn store_update_proofs(
        &self,
        name: &str,
        my_proofs: UpdateProofs,
        peer_proofs: UpdateInfo,
    ) -> Result<Updated, ChannelServerError> {
        let index = my_proofs.private_outputs.update_count;
        let delta = peer_proofs.delta;
        let mut channel = self.channels.checkout(name).await.ok_or(ChannelServerError::ChannelNotFound)?;
        let event = LifeCycleEvent::ChannelUpdate(Box::new((my_proofs, peer_proofs)));
        channel.handle_event(event)?;
        debug!("💸️  Update {index} proofs stored for channel {name}.");
        let result = Updated { new_balances: channel.state().balance(), update_count: index, delta };
        Ok(result)
    }

    //---------------------------------         Channel Closure functions      ---------------------------------//

    async fn close_channel(&self, name: &str) -> Result<Balances, ChannelServerError> {
        info!("🔚️  Closing channel {name}...");
        let (close_info, commitment, metadata, peer) = self.get_close_data(name).await?;

        info!("🔚️  Requesting closing transaction info from peer for channel {name}");
        let mut client = self.network_client.clone();
        let final_balance = close_info.final_balance;
        let close_response = client.send_close_request(peer, name, close_info).await??;
        info!("🔚️  Received closing transaction info for channel {name} from peer. Verifying its authenticity.");
        let (remote_name, close_response) = close_response.open();
        confirm_channel_matches(&remote_name, name)?;
        // Validate the response - in particular, the witness_i should match the T_i that we have on record.
        let peer_witness = close_response.witness;
        self.delegate.verify_peer_witness(&peer_witness, &commitment, &metadata).await?;

        // Happy, so close the channel.
        info!("🔚️  Closing transaction details are VALID for channel {name}. Moving to close channel.");
        let event = LifeCycleEvent::CloseChannel(Box::new(close_response));
        let mut channel = self.channels.checkout(name).await.ok_or(ChannelServerError::ChannelNotFound)?;
        channel.handle_event(event)?;
        info!("🔚️  Channel {name} is is the closing state. Waiting for final transaction to be confirmed.");
        Ok(final_balance)
    }

    async fn get_close_data(
        &self,
        name: &str,
    ) -> Result<(ChannelCloseRecord, GenericPoint, ChannelMetadata, PeerId), ChannelServerError> {
        let channel = self.channels.peek(name).await.ok_or(ChannelServerError::ChannelNotFound)?;
        if !channel.is_open() {
            return Err(ChannelServerError::InvalidState(format!(
                "Channel {name} is not open. Cannot close."
            )));
        }
        let state = channel.state().as_open()?;
        let close_info = state.get_close_record();
        let commitment = state.current_peer_commitment();
        let metadata = state.metadata().clone();
        let peer = channel.peer_id();
        Ok((close_info, commitment, metadata, peer))
    }

    async fn respond_to_channel_close(
        &self,
        envelope: MessageEnvelope<ChannelCloseRecord>,
    ) -> Result<GreaseResponse, GreaseResponse> {
        let (name, peer_close) = envelope.open();
        info!("🔚️  Received request to close channel {name}");
        let (close_info, commitment, metadata, _) = self
            .get_close_data(&name)
            .await
            .map_err(|e| GreaseResponse::ChannelClose(Err(RemoteServerError::internal(e.to_string()))))?;

        info!("🔚️  Received closing transaction info for channel {name} from peer. Verifying its authenticity.");
        // Validate the response - in particular, the witness_i should match the T_i that we have on record.
        let peer_witness = peer_close.witness;
        self.delegate
            .verify_peer_witness(&peer_witness, &commitment, &metadata)
            .await
            .map_err(|e| GreaseResponse::ChannelClose(Err(RemoteServerError::InvalidProof(e.to_string()))))?;
        // Transition to closing state.

        info!("🔚️  Closing transaction details are VALID for {name}. Closing channel and responding to peer.");
        let event = LifeCycleEvent::CloseChannel(Box::new(close_info.clone()));
        let mut channel = self.channels.checkout(&name).await
            .ok_or(GreaseResponse::ChannelClose(Err(RemoteServerError::ChannelDoesNotExist)))?;
        channel.handle_event(event)
            .map_err(|e| GreaseResponse::ChannelClose(Err(RemoteServerError::internal(e.to_string()))))?;
        let envelope = MessageEnvelope::new(name, close_info);
        Ok(GreaseResponse::ChannelClose(Ok(envelope)))
    }
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
                    GreaseResponse::Error(format!("Channel {name} does not exist."))
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
            GreaseRequest::ExchangeProof0(envelope) => {
                self.merchant_exchange_proof0(envelope).await.unwrap_or_else(|early| early)
            }
            GreaseRequest::ChannelUpdate(envelope) => {
                self.merchant_exchange_update(envelope).await.unwrap_or_else(|early| early)
            }
            GreaseRequest::ChannelClose(envelope) => {
                self.respond_to_channel_close(envelope).await.unwrap_or_else(|early| early)
            }
        }
    }
}
//------------------------------------------- Minor helper functions ---------------------------------------------//

fn confirm_channel_matches(remote: &str, local: &str) -> Result<(), ChannelServerError> {
    if remote != local {
        return Err(ChannelServerError::ProtocolError(format!(
            "Mismatched channel names. Expected {local}, Received {remote}"
        )));
    }
    Ok(())
}
