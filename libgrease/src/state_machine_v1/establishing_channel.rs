use crate::channel_metadata::ChannelMetadata;
use crate::crypto::traits::PublicKey;
use crate::kes::PartialEncryptedKey;
use crate::monero::{MoneroKeyPair, MultiSigWallet, WalletState};
use serde::{Deserialize, Serialize};
use std::future::Future;
//------------------------------------   Establishing Channel State  ------------------------------------------------//

//------------------------------------    Establishing Wallet State ------------------------------------------------//

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(deserialize = "P: PublicKey + for<'d> Deserialize<'d>"))]
pub struct EstablishingState<P, W>
where
    P: PublicKey,
    W: MultiSigWallet,
{
    pub channel_info: ChannelMetadata<P>,
    pub wallet_state: Option<WalletState<W>>,
}

impl<P, W> EstablishingState<P, W>
where
    P: PublicKey,
    W: MultiSigWallet,
{
    pub fn new(channel_info: ChannelMetadata<P>, uninitialized_wallet: W) -> Self {
        let wallet_state = Some(WalletState::new(channel_info.network, uninitialized_wallet));
        EstablishingState { channel_info, wallet_state }
    }

    pub fn channel_info(&self) -> &ChannelMetadata<P> {
        &self.channel_info
    }

    pub fn wallet_state(&self) -> &WalletState<W> {
        self.wallet_state.as_ref().expect("Wallet state has been removed")
    }

    /// Updates the wallet state machine by applying the provided async function to the current state.
    pub async fn update_wallet_state<F>(&mut self, update: impl FnOnce(WalletState<W>) -> F)
    where
        F: Future<Output = WalletState<W>>,
    {
        let wallet_state = self.wallet_state.take().expect("Wallet state has been removed");
        let new_wallet_state = update(wallet_state).await;
        self.wallet_state = Some(new_wallet_state);
    }

    pub fn update_wallet_state_sync(&mut self, update: impl FnOnce(WalletState<W>) -> WalletState<W>) {
        let wallet_state = self.wallet_state.take().expect("Wallet state has been removed");
        let new_wallet_state = update(wallet_state);
        self.wallet_state = Some(new_wallet_state);
    }
}




