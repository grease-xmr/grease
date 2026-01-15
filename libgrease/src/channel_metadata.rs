use crate::amount::MoneroDelta;
use crate::balance::Balances;
use crate::channel_id::ChannelIdMetadata;
use crate::payment_channel::ChannelRole;
use monero::Network;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelMetadata {
    /// The Monero network this channel lives on
    #[serde(
        deserialize_with = "crate::monero::helpers::deserialize_network",
        serialize_with = "crate::monero::helpers::serialize_network"
    )]
    network: Network,
    /// Whether we are the merchant or the customer
    role: ChannelRole,
    /// The amount of money in the channel. For initial balances, see `channel_id.initial_balances()`
    current_balances: Balances,
    /// The number of updates that have been made to this channel
    update_count: u64,
    /// The channel ID
    channel_id: ChannelIdMetadata,
    /// The KES identifier.
    kes_public_key: String,
}

impl ChannelMetadata {
    pub fn new(network: Network, role: ChannelRole, channel_id: ChannelIdMetadata, kes_public_key: String) -> Self {
        Self {
            network,
            role,
            current_balances: channel_id.initial_balance(),
            channel_id,
            kes_public_key,
            update_count: 0,
        }
    }

    pub fn channel_id(&self) -> &ChannelIdMetadata {
        &self.channel_id
    }

    pub fn role(&self) -> ChannelRole {
        self.role
    }

    pub fn balances(&self) -> Balances {
        self.current_balances
    }

    pub fn update_count(&self) -> u64 {
        self.update_count
    }

    pub fn network(&self) -> Network {
        self.network
    }

    pub fn kes_public_key(&self) -> &str {
        &self.kes_public_key
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
