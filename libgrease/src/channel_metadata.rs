use crate::amount::MoneroDelta;
use crate::balance::Balances;
use crate::channel_id::ChannelIdMetadata;
use crate::key_escrow_services::{KesConfiguration, KesImplementation};
use crate::payment_channel::ChannelRole;
use ciphersuite::{Ciphersuite, Ed25519};
use monero::Network;
use serde::{Deserialize, Serialize};

/// Information about the channel that stays constant throughout the channel's lifetime.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct StaticChannelMetadata<KC: Ciphersuite = Ed25519> {
    /// The Monero network this channel lives on
    #[serde(
        deserialize_with = "crate::monero::helpers::deserialize_network",
        serialize_with = "crate::monero::helpers::serialize_network"
    )]
    network: Network,
    /// Whether we are the merchant or the customer
    role: ChannelRole,
    /// The channel ID
    channel_id: ChannelIdMetadata<KC>,
    /// Which KES implementation this channel uses
    kes_type: KesImplementation,
}

impl<KC: Ciphersuite> StaticChannelMetadata<KC> {
    pub fn new(
        network: Network,
        role: ChannelRole,
        channel_id: ChannelIdMetadata<KC>,
        kes_type: KesImplementation,
    ) -> Self {
        Self { network, role, channel_id, kes_type }
    }

    pub fn channel_id(&self) -> &ChannelIdMetadata<KC> {
        &self.channel_id
    }

    pub fn role(&self) -> ChannelRole {
        self.role
    }

    pub fn network(&self) -> Network {
        self.network
    }

    pub fn kes_type(&self) -> &KesImplementation {
        &self.kes_type
    }

    /// Returns the KES configuration committed to in this channel's ID.
    pub fn kes_configuration(&self) -> &KesConfiguration<KC> {
        self.channel_id.kes_config()
    }

    /// Returns the initial balance from the channel ID metadata.
    pub fn initial_balance(&self) -> Balances {
        self.channel_id.initial_balance()
    }
}

/// Dynamic channel state that changes on every update.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DynamicChannelMetadata {
    /// The amount of money in the channel. For initial balances, see `channel_id.initial_balances()`
    pub current_balances: Balances,
    /// The number of updates that have been made to this channel
    pub update_count: u64,
}

impl DynamicChannelMetadata {
    pub fn new(current_balances: Balances, update_count: u64) -> Self {
        Self { current_balances, update_count }
    }

    pub fn apply_delta(&mut self, delta: MoneroDelta) -> bool {
        match self.current_balances.apply_delta(delta) {
            Some(new_balances) => {
                self.current_balances = new_balances;
                self.update_count += 1;
                true
            }
            None => false,
        }
    }
}
