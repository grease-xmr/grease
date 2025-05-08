use crate::errors::PaymentChannelError;
use crate::ContactInfo;
use libgrease::crypto::traits::PublicKey;
use libgrease::kes::KeyEscrowService;
use libgrease::monero::MultiSigWallet;
use libgrease::payment_channel::ActivePaymentChannel;
use libgrease::state_machine::{ChannelLifeCycle, ChannelSeedInfo};
use libp2p::{Multiaddr, PeerId};
use log::{debug, info};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
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
    pub peer_info: ContactInfo,
    pub state: ChannelLifeCycle<P, C, W, KES>,
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
        PaymentChannel { peer_info, state }
    }

    pub fn try_load_from_file<PATH: AsRef<Path>>(path: PATH) -> Result<Self, PaymentChannelError> {
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

    /// Returns the channel name, which is identical to `channel_id.name()`
    pub fn name(&self) -> String {
        self.state.current_state().name()
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
        lock.insert(key, channel);
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
