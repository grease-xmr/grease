use crate::errors::PaymentChannelError;
use crate::message_types::NewChannelProposal;
use crate::ContactInfo;
use libgrease::crypto::traits::PublicKey;
use libgrease::kes::KeyEscrowService;
use libgrease::monero::{MultiSigWallet, WalletState};
use libgrease::payment_channel::ActivePaymentChannel;
use libgrease::state_machine::error::LifeCycleError;
use libgrease::state_machine::lifecycle::LifeCycleEvent;
use libgrease::state_machine::{ChannelLifeCycle, ChannelSeedInfo};
use libp2p::{Multiaddr, PeerId};
use log::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::future::Future;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::{OwnedRwLockReadGuard, OwnedRwLockWriteGuard, RwLock};

#[derive(Serialize, Deserialize)]
#[serde(bound(deserialize = "P: PublicKey  + for<'d> Deserialize<'d>"))]
pub struct OutOfBandMerchantInfo<P>
where
    P: PublicKey,
{
    pub contact: ContactInfo,
    pub seed: ChannelSeedInfo<P>,
}

impl<P> OutOfBandMerchantInfo<P>
where
    P: PublicKey,
{
    /// Creates a new `OutOfBandMerchantInfo` with the given contact and channel seed information.
    pub fn new(contact: ContactInfo, seed: ChannelSeedInfo<P>) -> Self {
        OutOfBandMerchantInfo { contact, seed }
    }
}

/// A payments channel
///
/// A payment channel comprises
/// - the details of the peer (i.e. a way to connect to them over the internet)
/// - the current state of the Monero payment channel
///
/// Again, the word channel is overloaded
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(deserialize = "P: PublicKey  + for<'d> Deserialize<'d>"))]
pub struct PaymentChannel<P, C, W, KES>
where
    P: PublicKey,
    C: ActivePaymentChannel,
    W: MultiSigWallet,
    KES: KeyEscrowService,
{
    peer_info: ContactInfo,
    // Invariant: `state` is `None` only transiently inside `handle_event`.
    state: Option<ChannelLifeCycle<P, C, W, KES>>,
}

impl<P, C, W, KES> PaymentChannel<P, C, W, KES>
where
    P: PublicKey,
    C: ActivePaymentChannel,
    W: MultiSigWallet,
    KES: KeyEscrowService,
{
    /// Creates a new `PaymentChannel` with the given identity and peer information.
    pub fn new(peer_info: ContactInfo, state: ChannelLifeCycle<P, C, W, KES>) -> Self {
        PaymentChannel { peer_info, state: Some(state) }
    }

    pub fn try_load_from_file<PATH: AsRef<Path>>(path: PATH) -> Result<Self, PaymentChannelError> {
        debug!("🛣️ Loading channel from {}", path.as_ref().display());
        if path.as_ref().is_file() {
            let file_name = path.as_ref().file_name().unwrap().to_string_lossy().to_string();
            if file_name.ends_with(".ron") {
                fs::read_to_string(path).map_err(|e| PaymentChannelError::LoadingError(e.to_string())).and_then(|s| {
                    ron::from_str::<PaymentChannel<P, C, W, KES>>(&s)
                        .map_err(|e| PaymentChannelError::LoadingError(e.to_string()))
                })
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

    pub fn peer_address(&self) -> Multiaddr {
        self.peer_info.address.clone()
    }

    pub fn peer_id(&self) -> PeerId {
        self.peer_info.peer_id
    }

    pub fn state(&self) -> &ChannelLifeCycle<P, C, W, KES> {
        self.state.as_ref().expect("State should be present")
    }

    /// Update the wallet state using the state transition function `update` provided.
    ///
    /// This function returns true if the state was updated (but might still have led to an aborted wallet state).
    /// if the state does not exist, or we're not in the `Establishing` state, it returns false.
    pub async fn wallet_preparation<F>(
        &mut self,
        update: impl FnOnce(WalletState<W>) -> F,
    ) -> Result<(), LifeCycleError>
    where
        F: Future<Output = WalletState<W>>,
    {
        let Some(ChannelLifeCycle::Establishing(state)) = &mut self.state else {
            return Err(LifeCycleError::InvalidStateTransition);
        };
        state.update_wallet_state(update).await;
        Ok(())
    }

    pub fn wallet_state(&self) -> Result<&WalletState<W>, LifeCycleError> {
        let Some(ChannelLifeCycle::Establishing(state)) = &self.state else {
            return Err(LifeCycleError::InvalidStateTransition);
        };
        Ok(state.wallet_state())
    }

    /// Returns the channel name, which is identical to `channel_id.name()`
    pub fn name(&self) -> String {
        self.state().current_state().name()
    }

    async fn handle_event(&mut self, event: LifeCycleEvent<P, C, KES>) -> Result<(), LifeCycleError> {
        trace!("🛣️ Handling event: {event}");
        let state = self.state.take().expect("State should be present");
        let (state, result) = match state.handle_event(event).await {
            Ok(new_state) => (new_state, Ok(())),
            Err((new_state, err)) => {
                debug!("Error handling event: {err}");
                (new_state, Err(err))
            }
        };
        self.state = Some(state);
        result
    }

    /// Drive the state transition from New -> Establishing for merchants/proposees accepting a proposal
    pub(crate) async fn receive_proposal(&mut self) -> Result<(), LifeCycleError> {
        debug!("🛣️ Received new channel proposal");
        let proposal = {
            let state = self.state();
            if let ChannelLifeCycle::New(new_state) = state {
                new_state.for_proposal()
            } else {
                warn!("Receive proposal called, but we're not in a New state");
                return Err(LifeCycleError::InvalidStateTransition);
            }
        };
        let event = LifeCycleEvent::OnAckNewChannel(Box::new(proposal));
        self.handle_event(event).await
    }

    /// Drive the state transition from New -> Establishing for customers/proposers handling an ACK on a proposal
    pub async fn receive_proposal_ack(&mut self, ack: NewChannelProposal<P>) -> Result<(), LifeCycleError> {
        debug!("🛣️ Received channel proposal ACK");
        let info = ack.proposed_channel_info();
        let event = LifeCycleEvent::OnAckNewChannel(Box::new(info));
        self.handle_event(event).await
    }

    /// Accept a newly created and verified Multisig wallet and move the state from `Establishing` to `WalletCreated`
    pub async fn accept_new_wallet(&mut self) -> Result<(), LifeCycleError> {
        self.handle_event(LifeCycleEvent::OnMultiSigWalletCreated).await
    }
}

pub struct PaymentChannels<P, C, W, KES>
where
    P: PublicKey,
    C: ActivePaymentChannel,
    W: MultiSigWallet,
    KES: KeyEscrowService,
{
    channels: Arc<RwLock<HashMap<String, Arc<RwLock<PaymentChannel<P, C, W, KES>>>>>>,
}

impl<P, C, W, KES> Clone for PaymentChannels<P, C, W, KES>
where
    P: PublicKey,
    C: ActivePaymentChannel,
    W: MultiSigWallet,
    KES: KeyEscrowService,
{
    fn clone(&self) -> Self {
        PaymentChannels { channels: Arc::clone(&self.channels) }
    }
}

impl<P, C, W, KES> PaymentChannels<P, C, W, KES>
where
    P: PublicKey,
    C: ActivePaymentChannel,
    W: MultiSigWallet,
    KES: KeyEscrowService,
{
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
            match PaymentChannel::<P, C, W, KES>::try_load_from_file(&path) {
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
    pub async fn add(&self, channel: PaymentChannel<P, C, W, KES>) {
        let key = channel.name();
        let channel = Arc::new(RwLock::new(channel));
        let mut lock = self.channels.write().await;
        if lock.insert(key.clone(), channel).is_some() {
            warn!("Channel {key} already existed – it has been replaced");
        };
    }

    /// Check the channel out for writing, if it exists.
    /// If the channel is already checked out, this method will block until the channel is available.
    /// If the channel does not exist, `checkout` returns None.
    pub async fn checkout(&self, channel_name: &str) -> Option<OwnedRwLockWriteGuard<PaymentChannel<P, C, W, KES>>> {
        let lock = self.channels.read().await;
        match lock.get(channel_name) {
            Some(lock) => {
                let channel = lock.clone().write_owned().await;
                Some(channel)
            }
            None => None,
        }
    }

    /// Try and check the channel out for writing.
    ///
    /// If it does not exist or is already checked out, this method will return None.
    pub async fn try_checkout(
        &self,
        channel_name: &str,
    ) -> Option<OwnedRwLockWriteGuard<PaymentChannel<P, C, W, KES>>> {
        let lock = self.channels.read().await;
        lock.get(channel_name).cloned().and_then(|lock| lock.try_write_owned().ok())
    }

    pub async fn try_peek(&self, channel_name: &str) -> Option<OwnedRwLockReadGuard<PaymentChannel<P, C, W, KES>>> {
        let lock = self.channels.read().await;
        lock.get(channel_name).cloned().and_then(|lock| lock.try_read_owned().ok())
    }

    /// Stores the in-memory channels to the configured channel directory, overwriting any existing files.
    pub async fn save_channels<Pth: AsRef<Path>>(&self, path: Pth) -> Result<(), PaymentChannelError> {
        let lock = self.channels.read().await;
        let channel_dir = path.as_ref();
        fs::create_dir_all(channel_dir)?;
        for (name, channel) in lock.iter() {
            let path = channel_dir.join(format!("{name}.ron"));
            let readable = channel.read().await;
            let serialized = ron::to_string::<PaymentChannel<P, C, W, KES>>(&readable)?;
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
