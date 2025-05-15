use crate::amount::MoneroAmount;
use crate::channel_id::ChannelId;
use crate::crypto::traits::PublicKey;
use crate::kes::KeyEscrowService;
use crate::monero::{MultiSigService, WalletState};
use crate::payment_channel::ActivePaymentChannel;
use crate::payment_channel::ChannelRole;
use crate::state_machine::traits::ChannelState;
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(deserialize = "P: PublicKey + for<'d> Deserialize<'d>, WS: MultiSigService + for<'d> Deserialize<'d>"))]
pub struct EstablishingChannelState<P, WS>
where
    P: PublicKey,
    WS: MultiSigService,
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
    pub wallet: WalletState<WS::Wallet>,
    pub wallet_service: WS,
}

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

impl<P, WS> EstablishingChannelState<P, WS>
where
    P: PublicKey,
    WS: MultiSigService,
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

impl<P, WS> ChannelState for EstablishingChannelState<P, WS>
where
    P: PublicKey,
    WS: MultiSigService,
{
    fn channel_id(&self) -> &ChannelId {
        &self.channel_id
    }

    fn role(&self) -> ChannelRole {
        self.role
    }
}

pub struct ChannelEstablishedInfo<C, WS, KES>
where
    C: ActivePaymentChannel,
    WS: MultiSigService,
    KES: KeyEscrowService,
{
    pub(crate) wallet_service: WS,
    pub(crate) wallet: WS::Wallet,
    pub(crate) kes: KES,
    pub(crate) channel: C,
}
