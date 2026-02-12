use crate::balance::Balances;
use crate::key_escrow_services::{KesConfiguration, KesImplementation};
use ciphersuite::{Ciphersuite, Ed25519};
use monero::{Address, Network};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// A record that (usually) the merchant will send out-of-band to the customer to give them the seed information they
/// need to complete a new channel proposal.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(bound = "")]
pub struct MerchantSeedInfo<KC: Ciphersuite = Ed25519> {
    /// The Monero network this channel will run on
    #[serde(
        deserialize_with = "crate::monero::helpers::deserialize_network",
        serialize_with = "crate::monero::helpers::serialize_network"
    )]
    pub network: Network,
    /// The KES configuration for this channel
    pub kes_type: KesImplementation,
    /// The KES configuration parameters (public key, dispute duration, etc.)
    pub kes_config: KesConfiguration<KC>,
    /// The initial set of channel balances
    pub initial_balances: Balances,
    /// The merchant's address that the closing transaction must pay into
    pub merchant_closing_address: Address,
    /// The public key corresponding to the merchant's secret channel nonce. Used to derive a shared secret for the
    /// channel, $kappa$.
    #[serde(serialize_with = "crate::helpers::serialize_ge", deserialize_with = "crate::helpers::deserialize_ge")]
    pub merchant_channel_key: KC::G,
    /// The merchant nonce for channel ID derivation, to help them identify this proposal.
    pub merchant_nonce: u64,
}

/// The builder struct for the [`MerchantSeedInfo`].
/// See [`MerchantSeedInfo`] for more information about each field.
pub struct MerchantSeedBuilder<KC: Ciphersuite> {
    network: Network,
    kes_type: KesImplementation,
    kes_config: Option<KesConfiguration<KC>>,
    initial_balances: Option<Balances>,
    closing_address: Option<Address>,
    channel_key: Option<KC::G>,
    channel_nonce: Option<u64>,
}

impl<KC: Ciphersuite> MerchantSeedBuilder<KC> {
    pub fn new(network: Network, kes_type: KesImplementation) -> Self {
        MerchantSeedBuilder {
            network,
            kes_type,
            kes_config: None,
            initial_balances: None,
            closing_address: None,
            channel_key: None,
            channel_nonce: None,
        }
    }

    pub fn with_kes_config(mut self, kes_config: KesConfiguration<KC>) -> Self {
        self.kes_config = Some(kes_config);
        self
    }

    pub fn with_initial_balances(mut self, initial_balances: Balances) -> Self {
        self.initial_balances = Some(initial_balances);
        self
    }

    pub fn with_closing_address(mut self, address: Address) -> Self {
        self.closing_address = Some(address);
        self
    }

    /// Calculate the ephemeral channel public key $P_g$ from the channel secret, $hat(k)_a$. The secret is not stored.
    pub fn derive_channel_pubkey(mut self, secret: &KC::F) -> Self {
        let channel_key = KC::generator() * *secret;
        self.channel_key = Some(channel_key);
        self
    }

    pub fn with_channel_nonce(mut self, nonce: u64) -> Self {
        self.channel_nonce = Some(nonce);
        self
    }

    pub fn build(self) -> Result<MerchantSeedInfo<KC>, MissingSeedInfo> {
        let kes_config = self.kes_config.ok_or(MissingSeedInfo::KesConfig)?;
        let initial_balances = self.initial_balances.ok_or(MissingSeedInfo::InitialBalances)?;
        let closing_address = self.closing_address.ok_or(MissingSeedInfo::ClosingAddress)?;
        let channel_key = self.channel_key.ok_or(MissingSeedInfo::ChannelKey)?;
        let channel_nonce = self.channel_nonce.ok_or(MissingSeedInfo::ChannelNonce)?;

        Ok(MerchantSeedInfo {
            network: self.network,
            kes_type: self.kes_type,
            kes_config,
            initial_balances,
            merchant_closing_address: closing_address,
            merchant_channel_key: channel_key,
            merchant_nonce: channel_nonce,
        })
    }
}

#[derive(Debug, Clone, Error)]
pub enum MissingSeedInfo {
    #[error("Missing KES configuration")]
    KesConfig,
    #[error("Missing initial balances")]
    InitialBalances,
    #[error("Missing closing address")]
    ClosingAddress,
    #[error("Missing channel key")]
    ChannelKey,
    #[error("Missing channel nonce")]
    ChannelNonce,
}
