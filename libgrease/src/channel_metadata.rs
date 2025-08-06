use crate::balance::Balances;
use crate::channel_id::ChannelId;
use crate::payment_channel::ChannelRole;
use crate::{amount::MoneroDelta, crypto::zk_objects::GenericPoint, crypto::zk_objects::GenericScalar};
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
    channel_id: ChannelId,
    /// The KES identifier.
    kes_public_key: GenericPoint,
    /// The external identifier
    public_key_self: GenericPoint,
    /// The external identifier for interacting with the KES
    public_key_bjj_self: GenericPoint,
    /// Random nonce
    nonce_self: GenericScalar,
    /// The external identifier for the peer
    public_key_peer: GenericPoint,
    /// The external identifier for the peer for interacting with the KES
    public_key_bjj_peer: GenericPoint,
    /// Random nonce for the peer
    nonce_peer: GenericScalar,
}

impl ChannelMetadata {
    pub fn new(
        network: Network,
        role: ChannelRole,
        channel_id: ChannelId,
        kes_public_key: GenericPoint,
        public_key_self: GenericPoint,
        public_key_bjj_self: GenericPoint,
        nonce_self: GenericScalar,
        public_key_peer: GenericPoint,
        public_key_bjj_peer: GenericPoint,
        nonce_peer: GenericScalar,
    ) -> Self {
        Self {
            network,
            role,
            current_balances: channel_id.initial_balance(),
            channel_id,
            kes_public_key,
            update_count: 0,
            public_key_self,
            public_key_bjj_self,
            nonce_self,
            public_key_peer,
            public_key_bjj_peer,
            nonce_peer,
        }
    }

    pub fn channel_id(&self) -> &ChannelId {
        &self.channel_id
    }

    pub fn nonce_self(&self) -> &GenericScalar {
        &self.nonce_self
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

    pub fn kes_public_key(&self) -> &GenericPoint {
        &self.kes_public_key
    }

    pub fn public_key_self(&self) -> &GenericPoint {
        &self.public_key_self
    }

    pub fn public_key_bjj_self(&self) -> &GenericPoint {
        &self.public_key_bjj_self
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

    pub fn public_key_peer(&self) -> &GenericPoint {
        &self.public_key_peer
    }

    pub fn public_key_bjj_peer(&self) -> &GenericPoint {
        &self.public_key_bjj_peer
    }

    pub fn nonce_peer(&self) -> &GenericScalar {
        &self.nonce_peer
    }
}
