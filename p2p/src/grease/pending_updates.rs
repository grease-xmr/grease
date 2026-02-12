use grease_babyjubjub::BabyJubJub;
use libgrease::amount::MoneroDelta;
use libgrease::cryptography::keys::Curve25519Secret;
use libgrease::cryptography::CrossCurveScalar;
use libgrease::wallet::multisig_wallet::AdaptSig;
use log::*;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use wallet::MultisigWallet;

pub type DefaultChannelWitness = CrossCurveScalar<BabyJubJub>;

pub struct PendingUpdate {
    pub wallet: MultisigWallet,
    pub delta: MoneroDelta,
    pub update_count: u64,
    pub my_preprocess: Vec<u8>,
    pub merchant_round1: Option<ResponderInfo>,
}

pub struct ResponderInfo {
    pub my_witness: DefaultChannelWitness,
    pub peer_preprocess: Vec<u8>,
    pub my_signature: Curve25519Secret,
    pub my_adapted_signature: AdaptSig,
}

impl PendingUpdate {
    pub fn new(wallet: MultisigWallet, delta: MoneroDelta, update_count: u64, my_preprocess: Vec<u8>) -> Self {
        Self { wallet, delta, update_count, my_preprocess, merchant_round1: None }
    }
}

#[derive(Default)]
pub struct PendingUpdates {
    wallets: Arc<RwLock<HashMap<String, PendingUpdate>>>,
}

impl Clone for PendingUpdates {
    fn clone(&self) -> Self {
        Self { wallets: Arc::clone(&self.wallets) }
    }
}

impl PendingUpdates {
    pub async fn add(&self, name: &str, pending: PendingUpdate) {
        trace!("Saving wallet to memory");
        let mut lock = self.wallets.write().await;
        if lock.insert(name.to_string(), pending).is_some() {
            error!("Wallet for {name} already exists – there should only be one update active per channel ata a time!");
        };
    }

    /// Check the channel out for writing, if it exists.
    /// If the channel is already checked out, this method will block until the channel is available.
    /// If the channel does not exist, `checkout` returns None.
    pub async fn checkout(&self, channel_name: &str) -> Option<PendingUpdate> {
        trace!("Trying to check out wallet for {channel_name}");
        let mut lock = self.wallets.write().await;
        match lock.remove(channel_name) {
            Some(pending) => {
                trace!("Check out wallet for {channel_name} success");
                Some(pending)
            }
            None => None,
        }
    }
}
