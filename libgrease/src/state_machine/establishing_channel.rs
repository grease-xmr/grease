use crate::amount::MoneroAmount;
use crate::channel_id::ChannelId;
use crate::crypto::traits::PublicKey;
use crate::kes::{KeyEscrowService, PartialEncryptedKey};
use crate::monero::error::MoneroWalletError;
use crate::monero::{MoneroKeyPair, MultiSigWallet, WalletState};
use crate::payment_channel::ActivePaymentChannel;
use crate::payment_channel::ChannelRole;
use crate::state_machine::traits::ChannelState;
use monero::Network;
use serde::{Deserialize, Serialize};
use std::future::Future;
//------------------------------------   Establishing Channel State  ------------------------------------------------//

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(deserialize = "P: PublicKey + for<'d> Deserialize<'d>"))]
pub struct ChannelMetadata<P>
where
    P: PublicKey,
{
    /// The Monero network this channel lives on
    #[serde(
        deserialize_with = "crate::monero::helpers::deserialize_network",
        serialize_with = "crate::monero::helpers::serialize_network"
    )]
    pub network: Network,
    /// Whether we are the merchant or the customer
    pub role: ChannelRole,
    /// The key that is used to decrypt the peer's multisig secret share.
    pub(crate) decryption_key: P::SecretKey,
    /// The key used to encrypt the merchant's portion of the customer's multisig spend key.
    pub merchant_pubkey: P,
    /// The key used to encrypt the customer's portion of the merchant's multisig spend key.
    pub customer_pubkey: P,
    /// The key both peers use to encrypt their portion of the multisig spend key.
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
    #[serde(
        deserialize_with = "crate::monero::helpers::deserialize_keypair",
        serialize_with = "crate::monero::helpers::serialize_keypair"
    )]
    pub wallet_secret: MoneroKeyPair,
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

impl<P, W> WalletCreatedState<P, W>
where
    P: PublicKey,
    W: MultiSigWallet,
{
    /// Returns the information needed to create the Verifiable Secret Sharing (VSS) record.
    ///
    /// In particular, it returns
    /// - our secret key
    /// - the public key of the merchant
    /// - the public key of the KES
    pub fn vss_info(&self) -> Result<ChannelInitSecrets<P>, MoneroWalletError> {
        let peer_public_key = match self.channel_info.role {
            ChannelRole::Merchant => self.channel_info.customer_pubkey.clone(),
            ChannelRole::Customer => self.channel_info.merchant_pubkey.clone(),
        };
        Ok(ChannelInitSecrets {
            channel_name: self.name(),
            wallet_secret: self.wallet_secret.clone(),
            peer_public_key,
            kes_public_key: self.channel_info.kes_public_key.clone(),
        })
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

//------------------------------------           VSS Info          ------------------------------------------------//

/// Contains information needed to initialise the KES and create the VSS record.
///
/// This object contains a SECRET key and should be handled with care!
#[derive(Debug)]
pub struct ChannelInitSecrets<P>
where
    P: PublicKey,
{
    pub channel_name: String,
    /// My portion of the 2-of-2 multisig secret that needs to be split
    wallet_secret: MoneroKeyPair,
    /// The public key of the peer
    pub peer_public_key: P,
    /// The public key of the KES. One secret shard will be encrypted to this key.
    pub kes_public_key: P,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VssOutput {
    /// The encrypted secret shard for the peer
    pub peer_shard: PartialEncryptedKey,
    /// The encrypted secret shard for the KES
    pub kes_shard: PartialEncryptedKey,
}
