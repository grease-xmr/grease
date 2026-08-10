use crate::amount::MoneroDelta;
use crate::arbiter::ArbiterConfiguration;
use crate::balance::Balances;
use crate::channel_id::ChannelIdMetadata;
use crate::payment_channel::ChannelRole;
use crate::Ed25519;
use ciphersuite::Ciphersuite;
use monero::Network;
use serde::{Deserialize, Serialize};
use std::time::Duration;

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
}

impl<KC: Ciphersuite> StaticChannelMetadata<KC> {
    pub fn new(network: Network, role: ChannelRole, channel_id: ChannelIdMetadata<KC>) -> Self {
        Self { network, role, channel_id }
    }

    pub fn channel_id(&self) -> &ChannelIdMetadata<KC> {
        &self.channel_id
    }

    /// Mutable access to the channel id metadata, so the establishing state can bind it to the funding output's
    /// linking tag. Nothing else in the channel's lifetime may change the id.
    pub(crate) fn channel_id_mut(&mut self) -> &mut ChannelIdMetadata<KC> {
        &mut self.channel_id
    }

    pub fn role(&self) -> ChannelRole {
        self.role
    }

    pub fn network(&self) -> Network {
        self.network
    }

    /// The arbiter the two parties agreed on when they negotiated this channel.
    pub fn arbiter_configuration(&self) -> &ArbiterConfiguration {
        self.channel_id.arbiter_config()
    }

    /// The adjudication window `dw` agreed with the arbiter.
    pub fn dispute_window(&self) -> Duration {
        self.arbiter_configuration().dispute_window()
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
