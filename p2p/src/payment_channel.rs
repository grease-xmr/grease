use crate::errors::PaymentChannelError;
use crate::ContactInfo;
use libgrease::amount::MoneroDelta;
use libgrease::cryptography::zk_objects::{KesProof, Proofs0, PublicProof0, ShardInfo};
use libgrease::monero::data_objects::{TransactionId, TransactionRecord};
use libgrease::multisig::MultisigWalletData;
use libgrease::state_machine::error::LifeCycleError;
use libgrease::state_machine::lifecycle::{ChannelState, LifeCycle};
use libgrease::state_machine::{
    ChannelCloseRecord, ChannelSeedInfo, ClosingChannelState, EstablishedChannelState, EstablishingState,
    LifeCycleEvent, NewChannelState, ProposedChannelInfo, RejectNewChannelReason, TimeoutReason, UpdateRecord,
};
use libp2p::PeerId;
use log::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::{OwnedRwLockReadGuard, OwnedRwLockWriteGuard, RwLock};

#[derive(Serialize, Deserialize)]
pub struct OutOfBandMerchantInfo {
    pub contact: ContactInfo,
    pub seed: ChannelSeedInfo,
}

impl OutOfBandMerchantInfo {
    /// Creates a new `OutOfBandMerchantInfo` with the given contact and channel seed information.
    pub fn new(contact: ContactInfo, seed: ChannelSeedInfo) -> Self {
        OutOfBandMerchantInfo { contact, seed }
    }
}

macro_rules! update_state {
    ($method_name:ident, $state:ty, $accessor:ident) => {
        fn $method_name<F>(&mut self, updater: F) -> Result<(), LifeCycleError>
        where
            F: FnOnce($state) -> Result<ChannelState, (ChannelState, LifeCycleError)>,
        {
            let state = self
                .state
                .take()
                .ok_or(LifeCycleError::InternalError("state should never be None here".to_string()))?;
            let state = state.$accessor().map_err(|(s, err)| {
                self.state = Some(s);
                LifeCycleError::InternalError(format!("State should always be {}, but got: {err}", stringify!($state)))
            })?;
            match updater(state) {
                Ok(s) => {
                    self.state = Some(s);
                    Ok(())
                }
                Err((s, err)) => {
                    self.state = Some(s);
                    Err(err)
                }
            }
        }
    };
}

/// A wrapper for payment channel state.
///
/// This exists so that the channel server can handle multiple payment channels in parallel easily.
///
/// This struct comprises
/// - the details of the peer (i.e. a way to connect to them over the internet)
/// - the current state of the Monero payment channel
#[derive(Clone, Serialize, Deserialize)]
pub struct PaymentChannel {
    peer_info: ContactInfo,
    // Invariant: `state` is `None` only transiently inside `handle_event`.
    state: Option<ChannelState>,
}

impl PaymentChannel {
    /// Creates a new `PaymentChannel` with the given identity and peer information.
    pub fn new(peer_info: ContactInfo, state: ChannelState) -> Self {
        PaymentChannel { peer_info, state: Some(state) }
    }

    pub fn try_load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, PaymentChannelError> {
        debug!("⚡️ Loading channel from {}", path.as_ref().display());
        if path.as_ref().is_file() {
            let file_name = path.as_ref().file_name().unwrap().to_string_lossy().to_string();
            if file_name.ends_with(".ron") {
                let channel = fs::read_to_string(path)
                    .map_err(|e| PaymentChannelError::LoadingError(e.to_string()))
                    .and_then(|s| {
                        ron::from_str::<PaymentChannel>(&s)
                            .map_err(|e| PaymentChannelError::LoadingError(e.to_string()))
                    })?;
                Ok(channel)
            } else {
                Err(PaymentChannelError::LoadingError(format!(
                    "{} is not a ron file",
                    path.as_ref().display()
                )))
            }
        } else {
            Err(PaymentChannelError::LoadingError(format!(
                "{} is not a channel file",
                path.as_ref().display()
            )))
        }
    }

    pub fn peer_info(&self) -> ContactInfo {
        self.peer_info.clone()
    }

    pub fn peer_id(&self) -> PeerId {
        self.peer_info.peer_id
    }

    pub fn state(&self) -> &ChannelState {
        self.state.as_ref().expect("State should be present")
    }

    pub fn is_new_channel(&self) -> bool {
        matches!(self.state, Some(ChannelState::New(_)))
    }

    pub fn is_establishing(&self) -> bool {
        matches!(self.state, Some(ChannelState::Establishing(_)))
    }

    pub fn is_open(&self) -> bool {
        matches!(self.state, Some(ChannelState::Open(_)))
    }

    pub fn is_closing(&self) -> bool {
        matches!(self.state, Some(ChannelState::Closing(_)))
    }

    pub fn is_closed(&self) -> bool {
        matches!(self.state, Some(ChannelState::Closed(_)))
    }

    /// Returns the channel name, which is identical to `channel_id.name()`
    pub fn name(&self) -> String {
        self.state().name()
    }

    pub fn handle_event(&mut self, event: LifeCycleEvent) -> Result<(), LifeCycleError> {
        trace!("⚡️  Handling event: {event}");
        if self.is_new_channel() {
            match event {
                LifeCycleEvent::VerifiedProposal(ack) => self.on_verified_proposal(*ack),
                LifeCycleEvent::RejectNewChannel(reason) => self.on_reject_new_channel(*reason),
                LifeCycleEvent::Timeout(reason) => self.on_timeout(*reason),
                _ => Err(LifeCycleError::InvalidState(format!(
                    "Received event {event} in New state, which is not allowed"
                ))),
            }
        } else if self.is_establishing() {
            match event {
                LifeCycleEvent::MultiSigWalletCreated(data) => self.on_wallet_created(*data),
                LifeCycleEvent::FundingTxWatcher(data) => self.on_save_watcher(data),
                LifeCycleEvent::KesShards(shards) => self.on_kes_shards(*shards),
                LifeCycleEvent::KesCreated(info) => self.on_kes_created(*info),
                LifeCycleEvent::FundingTxConfirmed(info) => self.on_funding_confirmed(*info),
                LifeCycleEvent::MyProof0Generated(proof) => self.on_my_proof0(*proof),
                LifeCycleEvent::PeerProof0Received(proof) => self.on_peer_proof0(*proof),
                _ => Err(LifeCycleError::InvalidState(format!(
                    "Received event {event} in Establishing state, which is not allowed"
                ))),
            }
        } else if self.is_open() {
            match event {
                LifeCycleEvent::ChannelUpdate(updates) => self.on_channel_update(*updates),
                LifeCycleEvent::CloseChannel(info) => self.on_cooperative_close(*info),
                _ => Err(LifeCycleError::InvalidState(format!(
                    "Received event {event} in Open state, which is not allowed"
                ))),
            }
        } else if self.is_closing() {
            match event {
                LifeCycleEvent::FinalTxConfirmed(tx) => self.on_final_tx_confirmed(*tx),
                _ => Err(LifeCycleError::InvalidState(format!(
                    "Received event {event} in Closing state, which is not allowed"
                ))),
            }
        } else if self.is_closed() {
            Err(LifeCycleError::InvalidState(format!(
                "Received event {event} in Closed state, which is not allowed"
            )))
        } else {
            Err(LifeCycleError::InvalidState(format!(
                "No event handlers for state: {}",
                self.state().stage()
            )))
        }
    }

    fn on_verified_proposal(&mut self, proposal: ProposedChannelInfo) -> Result<(), LifeCycleError> {
        debug!("⚡️  Received a verified channel proposal");
        self.update_new(|new| {
            new.next(proposal)
                .map(|s| {
                    debug!("⚡️  Transitioned to Establishing state");
                    s.to_channel_state()
                })
                .map_err(|(s, err)| {
                    warn!("⚡️  Failed to transition from New to Establishing: {err}");
                    (s.to_channel_state(), err)
                })
        })
    }

    fn on_reject_new_channel(&mut self, reason: RejectNewChannelReason) -> Result<(), LifeCycleError> {
        debug!("⚡️  Received a rejection for the new channel proposal: {}", reason.reason());
        self.update_new(|new| {
            let state = new.reject(reason);
            Ok(state.to_channel_state())
        })
    }

    fn on_timeout(&mut self, reason: TimeoutReason) -> Result<(), LifeCycleError> {
        debug!("⚡️  Received a rejection for the new channel proposal: {}", reason.reason());
        self.update_new(|new| Ok(new.timeout(reason).to_channel_state()))
    }

    fn on_wallet_created(&mut self, data: MultisigWalletData) -> Result<(), LifeCycleError> {
        self.update_establishing(|mut establishing| {
            establishing.wallet_created(data);
            Ok(establishing.to_channel_state())
        })
    }

    fn on_save_watcher(&mut self, watcher: Vec<u8>) -> Result<(), LifeCycleError> {
        self.update_establishing(|mut establishing| {
            establishing.save_funding_tx_pipe(watcher);
            Ok(establishing.to_channel_state())
        })
    }

    fn on_my_proof0(&mut self, proof: Proofs0) -> Result<(), LifeCycleError> {
        self.update_establishing(|mut establishing| {
            establishing.save_proof0(proof);
            match establishing.next() {
                Ok(established) => {
                    debug!("⚡️  Transitioned to Established state after saving witness0 proof");
                    Ok(established.to_channel_state())
                }
                Err((establishing, err)) => {
                    trace!("⚡️  Staying in establishing state: {err}");
                    Ok(establishing.to_channel_state())
                }
            }
        })
    }

    fn on_peer_proof0(&mut self, peer_proof: PublicProof0) -> Result<(), LifeCycleError> {
        self.update_establishing(|mut establishing| {
            establishing.save_peer_proof0(peer_proof);
            match establishing.next() {
                Ok(established) => {
                    debug!("⚡️  Transitioned to Established state after receiving peer's proof0");
                    Ok(established.to_channel_state())
                }
                Err((establishing, err)) => {
                    trace!("⚡️  Staying in establishing state: {err}");
                    Ok(establishing.to_channel_state())
                }
            }
        })
    }

    fn on_kes_shards(&mut self, shards: ShardInfo) -> Result<(), LifeCycleError> {
        self.update_establishing(|mut establishing| {
            establishing.save_kes_shards(shards);
            match establishing.next() {
                Ok(established) => {
                    debug!("⚡️  Transitioned to Established state after receiving KES shards");
                    Ok(established.to_channel_state())
                }
                Err((establishing, err)) => {
                    trace!("⚡️  Staying in establishing state: {err}");
                    Ok(establishing.to_channel_state())
                }
            }
        })
    }

    fn on_kes_created(&mut self, info: KesProof) -> Result<(), LifeCycleError> {
        self.update_establishing(|mut establishing| {
            establishing.kes_created(info);
            match establishing.next() {
                Ok(established) => {
                    debug!("⚡️  Transitioned to Established state");
                    Ok(established.to_channel_state())
                }
                Err((establishing, err)) => {
                    trace!("⚡️  Staying in establishing state: {err}");
                    Ok(establishing.to_channel_state())
                }
            }
        })
    }

    fn on_funding_confirmed(&mut self, tx: TransactionRecord) -> Result<(), LifeCycleError> {
        self.update_establishing(move |mut establishing| {
            establishing.funding_tx_confirmed(tx);
            match establishing.next() {
                Ok(established) => {
                    debug!("⚡️  Transitioned to Established state after funding tx confirmed");
                    Ok(established.to_channel_state())
                }
                Err((establishing, err)) => {
                    trace!("⚡️  Staying in establishing state: {err}");
                    Ok(establishing.to_channel_state())
                }
            }
        })
    }

    fn on_channel_update(&mut self, record: (MoneroDelta, UpdateRecord)) -> Result<(), LifeCycleError> {
        let (delta, update) = record;
        self.update_open(|mut open| {
            let n = open.store_update(delta, update);
            trace!("⚡️  Channel update #{n} was successfully applied");
            Ok(open.to_channel_state())
        })
    }

    fn on_cooperative_close(&mut self, close_record: ChannelCloseRecord) -> Result<(), LifeCycleError> {
        self.update_open(|open| {
            open.close(close_record)
                .map(|s| {
                    debug!("⚡️  Transitioned to Closing state after cooperative close");
                    s.to_channel_state()
                })
                .map_err(|(s, err)| (s.to_channel_state(), err))
        })
    }

    fn on_final_tx_confirmed(&mut self, tx: TransactionId) -> Result<(), LifeCycleError> {
        self.update_closing(|mut closing| {
            closing.with_final_tx(tx);
            closing
                .next()
                .map(|closing| {
                    debug!("⚡️  Transitioned to Closed state after final transaction confirmed");
                    closing.to_channel_state()
                })
                .map_err(|(closing, err)| {
                    debug!("⚡️  Failed to transition from Closing to Closed: {err}");
                    (closing.to_channel_state(), err)
                })
        })
    }

    update_state!(update_new, NewChannelState, to_new);
    update_state!(update_establishing, EstablishingState, to_establishing);
    update_state!(update_open, EstablishedChannelState, to_open);
    update_state!(update_closing, ClosingChannelState, to_closing);
}

#[derive(Default)]
pub struct PaymentChannels {
    channels: Arc<RwLock<HashMap<String, Arc<RwLock<PaymentChannel>>>>>,
}

impl Clone for PaymentChannels {
    fn clone(&self) -> Self {
        PaymentChannels { channels: Arc::clone(&self.channels) }
    }
}

impl PaymentChannels {
    pub fn new() -> Self {
        PaymentChannels { channels: Arc::new(RwLock::new(HashMap::new())) }
    }

    pub fn load<Pth: AsRef<Path>>(channel_dir: Pth) -> Result<Self, PaymentChannelError> {
        let channel_dir = channel_dir.as_ref();
        debug!("Loading channels from {}", channel_dir.display());
        if !channel_dir.exists() {
            info!("Channel directory does not exist: {}. Creating it now", channel_dir.display());
            fs::create_dir_all(channel_dir)?;
            return Ok(Self::new());
        }
        let mut channels = HashMap::new();
        for entry in fs::read_dir(channel_dir)? {
            let entry = entry?;
            let path = entry.path();
            match PaymentChannel::try_load_from_file(&path) {
                Ok(channel) => {
                    let key = channel.name();
                    let channel = Arc::new(RwLock::new(channel));
                    channels.insert(key, channel);
                }
                Err(e) => {
                    info!("Non- or invalid channel found in channels folder: {e}");
                }
            }
        }
        let channels = Self { channels: Arc::new(RwLock::new(channels)) };
        Ok(channels)
    }

    pub async fn exists(&self, name: &str) -> bool {
        let lock = self.channels.read().await;
        lock.contains_key(name)
    }

    /// Add a new channel to the list of channels.
    pub async fn add(&self, channel: PaymentChannel) {
        let key = channel.name();
        trace!("Adding channel {key}");
        let channel = Arc::new(RwLock::new(channel));
        let mut lock = self.channels.write().await;
        if lock.insert(key.clone(), channel).is_some() {
            warn!("Channel {key} already existed – it has been replaced");
        };
    }

    /// Check the channel out for writing, if it exists.
    /// If the channel is already checked out, this method will block until the channel is available.
    /// If the channel does not exist, `checkout` returns None.
    pub async fn checkout(&self, channel_name: &str) -> Option<OwnedRwLockWriteGuard<PaymentChannel>> {
        trace!("Trying to check out channel {channel_name}");
        let lock = self.channels.read().await;
        match lock.get(channel_name) {
            Some(lock) => {
                let channel = lock.clone().write_owned().await;
                trace!("Check out channel {channel_name} success");
                Some(channel)
            }
            None => None,
        }
    }

    pub async fn peek(&self, channel_name: &str) -> Option<OwnedRwLockReadGuard<PaymentChannel>> {
        trace!("Trying to peek at channel {channel_name}");
        let map_lock = self.channels.read().await;
        match map_lock.get(channel_name) {
            Some(lock) => {
                let channel = lock.clone().read_owned().await;
                trace!("Peek for {channel_name} success");
                Some(channel)
            }
            None => {
                trace!("Channel {channel_name} not found");
                None
            }
        }
    }

    /// Stores the in-memory channels to the configured channel directory, overwriting any existing files.
    pub async fn save_channels<Pth: AsRef<Path>>(&self, path: Pth) -> Result<(), PaymentChannelError> {
        let lock = self.channels.read().await;
        let channel_dir = path.as_ref();
        fs::create_dir_all(channel_dir)?;
        for (name, channel) in lock.iter() {
            let path = channel_dir.join(format!("{name}.ron"));
            let readable = channel.read().await;
            let serialized = ron::to_string::<PaymentChannel>(&readable)?;
            drop(readable);
            fs::write(path, serialized)?;
        }
        Ok(())
    }

    /// Provides a list of channels, which can be used to index the channels
    pub async fn list_channels(&self) -> Vec<String> {
        let lock = self.channels.read().await;
        lock.keys().cloned().collect()
    }
}

#[cfg(test)]
mod test {
    use crate::{ContactInfo, PaymentChannel};
    use blake2::Blake2b512;
    use libgrease::amount::{MoneroAmount, MoneroDelta};
    use libgrease::cryptography::keys::{Curve25519PublicKey, Curve25519Secret};
    use libgrease::cryptography::zk_objects::{
        GenericScalar, KesProof, PartialEncryptedKey, PrivateUpdateOutputs, Proofs0, ShardInfo, UpdateProofs,
    };
    use libgrease::monero::data_objects::{MultisigSplitSecrets, TransactionId, TransactionRecord};
    use libgrease::multisig::MultisigWalletData;
    use libgrease::payment_channel::ChannelRole;
    use libgrease::state_machine::lifecycle::LifeCycle;
    use libgrease::state_machine::{
        ChannelCloseRecord, LifeCycleEvent, NewChannelBuilder, NewChannelState, UpdateRecord,
    };
    use libgrease::XmrScalar;
    use libp2p::{Multiaddr, PeerId};
    use monero::Address;
    use std::str::FromStr;
    use wallet::multisig_wallet::AdaptSig;

    const SECRET: &str = "0b98747459483650bb0d404e4ccc892164f88a5f1f131cee9e27f633cef6810d";
    const ALICE_ADDRESS: &str =
        "43i4pVer2tNFELvfFEEXxmbxpwEAAFkmgN2wdBiaRNcvYcgrzJzVyJmHtnh2PWR42JPeDVjE8SnyK3kPBEjSixMsRz8TncK";
    const BOB_ADDRESS: &str =
        "4BH2vFAir1iQCwi2RxgQmsL1qXmnTR9athNhpK31DoMwJgkpFUp2NykFCo4dXJnMhU7w9UZx7uC6qbNGuePkRLYcFo4N7p3";

    pub fn new_channel_state() -> NewChannelState {
        // All this info is known, or can be scanned in from a QR code etc
        let initial_state = NewChannelBuilder::new(ChannelRole::Customer);
        let initial_state = initial_state
            .with_kes_public_key("4dd896d542721742aff8671ba42aff0c4c846bea79065cf39a191bbeb11ea634")
            .with_customer_initial_balance(MoneroAmount::from(1000))
            .with_merchant_initial_balance(MoneroAmount::default())
            .with_my_user_label("me")
            .with_peer_label("you")
            .with_customer_closing_address(Address::from_str(ALICE_ADDRESS).unwrap())
            .with_merchant_closing_address(Address::from_str(BOB_ADDRESS).unwrap())
            .build::<Blake2b512>()
            .expect("Failed to build initial state");
        initial_state
    }
    #[test]
    fn happy_path() {
        env_logger::try_init().ok();
        let peer = ContactInfo { name: "Alice".to_string(), peer_id: PeerId::random(), address: Multiaddr::empty() };
        let some_pub =
            Curve25519PublicKey::from_hex("61772c23631fa02db2fbe47515dda43fc28a471ee47719930e388d2ba5275016").unwrap();
        let state = new_channel_state();
        let proposal = state.for_proposal();
        let state = state.to_channel_state();
        let mut channel = PaymentChannel::new(peer, state);
        assert!(channel.is_new_channel());
        let event = LifeCycleEvent::VerifiedProposal(Box::new(proposal));
        channel.handle_event(event).unwrap();
        assert!(channel.is_establishing());
        let wallet = MultisigWalletData {
            my_spend_key: Curve25519Secret::from_hex(SECRET).unwrap(),
            my_public_key: some_pub.clone(),
            sorted_pubkeys: [some_pub.clone(), some_pub.clone()],
            joint_public_spend_key: some_pub.clone(),
            joint_private_view_key: Curve25519Secret::random(&mut rand_core::OsRng),
            birthday: 0,
            known_outputs: Default::default(),
            role: ChannelRole::Customer,
        };
        let event = LifeCycleEvent::MultiSigWalletCreated(Box::new(wallet));
        channel.handle_event(event).unwrap();
        let my_shards = MultisigSplitSecrets {
            peer_shard: PartialEncryptedKey("customer_peer_shard".into()),
            kes_shard: PartialEncryptedKey("customer_kes_shard".into()),
        };
        let their_shards = MultisigSplitSecrets {
            peer_shard: PartialEncryptedKey("merchant_peer_shard".into()),
            kes_shard: PartialEncryptedKey("merchant_kes_shard".into()),
        };
        let event = LifeCycleEvent::KesShards(Box::new(ShardInfo { my_shards, their_shards }));
        channel.handle_event(event).unwrap();
        let proof0 =
            Proofs0 { public_outputs: Default::default(), private_outputs: Default::default(), proofs: vec![] };
        let peer_proof0 = proof0.public_only();
        let event = LifeCycleEvent::MyProof0Generated(Box::new(proof0));
        channel.handle_event(event).unwrap();
        let event = LifeCycleEvent::PeerProof0Received(Box::new(peer_proof0));
        channel.handle_event(event).unwrap();
        let tx = TransactionRecord {
            channel_name: "channel".to_string(),
            transaction_id: TransactionId { id: "tx123".to_string() },
            amount: MoneroAmount::from(1000),
            serialized: b"serialized_funding_tx".to_vec(),
        };
        let event = LifeCycleEvent::FundingTxConfirmed(Box::new(tx));
        channel.handle_event(event).unwrap();
        let event = LifeCycleEvent::KesCreated(Box::new(KesProof { proof: vec![1, 2, 3] }));
        channel.handle_event(event).unwrap();
        assert!(channel.is_open());
        let my_proofs = UpdateProofs {
            public_outputs: Default::default(),
            private_outputs: PrivateUpdateOutputs {
                update_count: 1,
                witness_i: GenericScalar::random(&mut rand_core::OsRng),
                delta_bjj: Default::default(),
                delta_ed: Default::default(),
            },
            proof: b"my_update_proof".to_vec(),
        };
        let key = Curve25519Secret::random(&mut rand_core::OsRng);
        let q = Curve25519Secret::random(&mut rand_core::OsRng);
        let info = UpdateRecord {
            my_signature: b"my_signature".to_vec(),
            my_adapted_signature: AdaptSig::sign(key.as_scalar(), q.as_scalar(), b"", &mut rand_core::OsRng),
            peer_adapted_signature: AdaptSig::sign(key.as_scalar(), q.as_scalar(), b"", &mut rand_core::OsRng),
            my_preprocess: b"my_prepared_info".to_vec(),
            peer_preprocess: b"peer_prepared_info".to_vec(),
            my_proofs,
            peer_proofs: Default::default(),
        };
        let delta = MoneroDelta::from(1000);
        let event = LifeCycleEvent::ChannelUpdate(Box::new((delta, info)));
        channel.handle_event(event).unwrap();
        assert!(channel.is_open());
        let close = ChannelCloseRecord {
            final_balance: channel.state().balance(),
            update_count: 1,
            witness: Default::default(),
        };
        let event = LifeCycleEvent::CloseChannel(Box::new(close));
        channel.handle_event(event).unwrap();
        assert!(channel.is_closing());
        let final_tx = TransactionId::new("final_tx123");
        let event = LifeCycleEvent::FinalTxConfirmed(Box::new(final_tx));
        channel.handle_event(event).unwrap();
        assert!(channel.is_closed());
    }
}
