use crate::amount::MoneroAmount;
use crate::channel_id::ChannelId;
use crate::crypto::traits::PublicKey;
use crate::kes::KeyEscrowService;
use crate::monero::{MultiSigWallet, WalletState};
use crate::payment_channel::ActivePaymentChannel;
use crate::payment_channel::ChannelRole;
use crate::state_machine::traits::ChannelState;
use serde::{Deserialize, Serialize};
use std::future::Future;

//------------------------------------   Establishing Channel State  ------------------------------------------------//

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(deserialize = "P: PublicKey + for<'d> Deserialize<'d>"))]
pub struct ChannelMetadata<P>
where
    P: PublicKey,
{
    pub role: ChannelRole,
    pub(crate) secret_key: P::SecretKey,
    pub merchant_pubkey: P,
    pub customer_pubkey: P,
    pub kes_public_key: P,
    /// The amount of money in the channel
    pub initial_balances: Balances,
    /// The channel ID
    pub channel_id: ChannelId,
}

impl<P> ChannelMetadata<P>
where
    P: PublicKey,
{
    pub fn channel_id(&self) -> &ChannelId {
        &self.channel_id
    }

    pub fn role(&self) -> ChannelRole {
        self.role
    }

    pub fn initial_balances(&self) -> Balances {
        self.initial_balances
    }
}

pub struct ChannelEstablishedInfo<C>
where
    C: ActivePaymentChannel,
{
    pub(crate) channel: C,
}

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
        let wallet_state = Some(WalletState::new(uninitialized_wallet));
        EstablishingState { channel_info, wallet_state }
    }

    pub fn channel_info(&self) -> &ChannelMetadata<P> {
        &self.channel_info
    }

    pub fn wallet_state(&self) -> &WalletState<W> {
        self.wallet_state.as_ref().expect("Wallet state has been removed")
    }

    pub async fn update_wallet_state<F>(&mut self, update: impl FnOnce(WalletState<W>) -> F)
    where
        F: Future<Output = WalletState<W>>,
    {
        let wallet_state = self.wallet_state.take().expect("Wallet state has been removed");
        let new_wallet_state = update(wallet_state).await;
        self.wallet_state = Some(new_wallet_state);
    }
}

impl<P, W> ChannelState for EstablishingState<P, W>
where
    P: PublicKey,
    W: MultiSigWallet,
{
    fn channel_id(&self) -> &ChannelId {
        &self.channel_info.channel_id
    }
    fn role(&self) -> ChannelRole {
        self.channel_info.role
    }
}

//------------------------------------     Wallet Created State      ------------------------------------------------//
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(deserialize = "P: PublicKey + for<'d> Deserialize<'d>"))]
pub struct WalletCreatedState<P, W>
where
    P: PublicKey,
    W: MultiSigWallet,
{
    pub channel_info: ChannelMetadata<P>,
    pub wallet: W,
}

impl<P, W> ChannelState for WalletCreatedState<P, W>
where
    P: PublicKey,
    W: MultiSigWallet,
{
    fn channel_id(&self) -> &ChannelId {
        &self.channel_info.channel_id
    }
    fn role(&self) -> ChannelRole {
        self.channel_info.role
    }
}

//------------------------------------       KES Verified State      ------------------------------------------------//
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(deserialize = "P: PublicKey + for<'d> Deserialize<'d>"))]
pub struct KesVerifiedState<P, W, KES>
where
    P: PublicKey,
    W: MultiSigWallet,
    KES: KeyEscrowService,
{
    pub channel_info: ChannelMetadata<P>,
    pub wallet: W,
    pub kes: KES,
}

impl<P, W, KES> ChannelState for KesVerifiedState<P, W, KES>
where
    P: PublicKey,
    W: MultiSigWallet,
    KES: KeyEscrowService,
{
    fn channel_id(&self) -> &ChannelId {
        &self.channel_info.channel_id
    }
    fn role(&self) -> ChannelRole {
        self.channel_info.role
    }
}

//------------------------------------           Balances          ------------------------------------------------//
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Balances {
    pub merchant: MoneroAmount,
    pub customer: MoneroAmount,
}

impl Balances {
    pub fn new(merchant: MoneroAmount, customer: MoneroAmount) -> Self {
        Balances { merchant, customer }
    }

    pub fn total(&self) -> MoneroAmount {
        self.merchant + self.customer
    }

    pub fn pay(&self, amount: MoneroAmount) -> Option<Self> {
        let delta = amount.to_piconero();
        (amount <= self.customer).then(|| {
            let new_customer = MoneroAmount::from_piconero(self.customer.to_piconero() - delta);
            let new_merchant = MoneroAmount::from_piconero(self.merchant.to_piconero() + delta);
            Balances::new(new_merchant, new_customer)
        })
    }

    pub fn refund(&self, amount: MoneroAmount) -> Option<Self> {
        let delta = amount.to_piconero();
        (amount <= self.merchant).then(|| {
            let new_customer = MoneroAmount::from_piconero(self.customer.to_piconero() + delta);
            let new_merchant = MoneroAmount::from_piconero(self.merchant.to_piconero() - delta);
            Balances::new(new_merchant, new_customer)
        })
    }
}
