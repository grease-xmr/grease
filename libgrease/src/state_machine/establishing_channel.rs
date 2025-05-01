use crate::amount::MoneroAmount;
use crate::channel_id::ChannelId;
use crate::crypto::traits::PublicKey;
use crate::kes::KeyEscrowService;
use crate::monero::MultiSigWallet;
use crate::payment_channel::ActivePaymentChannel;
use crate::payment_channel::ChannelRole;

pub struct EstablishingChannelState<P: PublicKey> {
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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

impl<P: PublicKey> EstablishingChannelState<P> {
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

pub struct ChannelEstablishedInfo<C, W, KES>
where
    C: ActivePaymentChannel,
    W: MultiSigWallet,
    KES: KeyEscrowService,
{
    pub(crate) wallet: W,
    pub(crate) kes: KES,
    pub(crate) channel: C,
}
