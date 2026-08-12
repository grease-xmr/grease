use crate::arbiter::ArbiterConfiguration;
use crate::balance::Balances;
use crate::Ed25519;
use ciphersuite::Ciphersuite;
use monero::{Address, Network};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// A record that (usually) the merchant will send out-of-band to the customer to give them the seed information they
/// need to complete a new channel proposal.
///
/// The fields are the channel seed metadata of `docs/src/12_new_channel.typ`: a random nonce id, the merchant's
/// closing address, the requested initial balances, the merchant's public key, and — as the protocol-specific
/// initialization data — the arbiters the merchant is willing to be judged by, each carrying its own dispute-window
/// duration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct MerchantSeedInfo<KC: Ciphersuite = Ed25519> {
    /// The Monero network this channel will run on
    #[serde(
        deserialize_with = "crate::monero::helpers::deserialize_network",
        serialize_with = "crate::monero::helpers::serialize_network"
    )]
    pub network: Network,
    /// The arbiters the merchant will accept for this channel, in order of preference. The customer picks exactly
    /// one of them for the proposal; a proposal naming anything else is rejected.
    ///
    /// The choice is agreed between the parties but deliberately **not** committed into the channel id: the arbiter
    /// sees the id only as an opaque label (see [`crate::channel_id::ChannelIdMetadata`]).
    pub accepted_arbiters: Vec<ArbiterConfiguration>,
    /// The initial set of channel balances
    pub initial_balances: Balances,
    /// The merchant's address that the closing transaction must pay into
    pub merchant_closing_address: Address,
    /// The merchant's public key, #Pm, the first field of the channel-id transcript.
    #[serde(serialize_with = "crate::helpers::serialize_ge", deserialize_with = "crate::helpers::deserialize_ge")]
    pub merchant_public_key: KC::G,
    /// The merchant nonce, which blinds the channel-id hash and lets the merchant recognise this proposal.
    pub merchant_nonce: u64,
}

// Hand-written rather than derived: a derived `PartialEq` would demand `KC: PartialEq`, and the ciphersuite
// marker types are unit structs that do not implement it. Equality is over the fields, none of which involve `KC`
// itself.
impl<KC: Ciphersuite> PartialEq for MerchantSeedInfo<KC> {
    fn eq(&self, other: &Self) -> bool {
        self.network == other.network
            && self.accepted_arbiters == other.accepted_arbiters
            && self.initial_balances == other.initial_balances
            && self.merchant_closing_address == other.merchant_closing_address
            && self.merchant_public_key == other.merchant_public_key
            && self.merchant_nonce == other.merchant_nonce
    }
}

impl<KC: Ciphersuite> Eq for MerchantSeedInfo<KC> {}

impl<KC: Ciphersuite> MerchantSeedInfo<KC> {
    /// Whether `arbiter` is one of the arbiters this seed offers.
    pub fn accepts_arbiter(&self, arbiter: &ArbiterConfiguration) -> bool {
        self.accepted_arbiters.contains(arbiter)
    }
}

/// The builder struct for the [`MerchantSeedInfo`].
/// See [`MerchantSeedInfo`] for more information about each field.
pub struct MerchantSeedBuilder<KC: Ciphersuite> {
    network: Network,
    accepted_arbiters: Vec<ArbiterConfiguration>,
    initial_balances: Option<Balances>,
    closing_address: Option<Address>,
    merchant_public_key: Option<KC::G>,
    channel_nonce: Option<u64>,
}

impl<KC: Ciphersuite> MerchantSeedBuilder<KC> {
    pub fn new(network: Network) -> Self {
        MerchantSeedBuilder {
            network,
            accepted_arbiters: Vec::new(),
            initial_balances: None,
            closing_address: None,
            merchant_public_key: None,
            channel_nonce: None,
        }
    }

    /// Offer one more arbiter to the customer. Order is preserved and read as the merchant's preference.
    pub fn with_arbiter(mut self, arbiter: ArbiterConfiguration) -> Self {
        self.accepted_arbiters.push(arbiter);
        self
    }

    /// Offer a whole set of arbiters, appended to any already added.
    pub fn with_arbiters(mut self, arbiters: impl IntoIterator<Item = ArbiterConfiguration>) -> Self {
        self.accepted_arbiters.extend(arbiters);
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

    /// The merchant's public key, #Pm.
    pub fn with_merchant_public_key(mut self, public_key: KC::G) -> Self {
        self.merchant_public_key = Some(public_key);
        self
    }

    /// The merchant's channel nonce. Draw it from a CSPRNG: together with the customer's nonce it blinds the
    /// channel-id hash, which is what stops a published id from revealing the funding output's linking tag.
    pub fn with_channel_nonce(mut self, nonce: u64) -> Self {
        self.channel_nonce = Some(nonce);
        self
    }

    pub fn build(self) -> Result<MerchantSeedInfo<KC>, MissingSeedInfo> {
        if self.accepted_arbiters.is_empty() {
            return Err(MissingSeedInfo::AcceptedArbiters);
        }
        let initial_balances = self.initial_balances.ok_or(MissingSeedInfo::InitialBalances)?;
        let closing_address = self.closing_address.ok_or(MissingSeedInfo::ClosingAddress)?;
        let merchant_public_key = self.merchant_public_key.ok_or(MissingSeedInfo::MerchantPublicKey)?;
        let channel_nonce = self.channel_nonce.ok_or(MissingSeedInfo::ChannelNonce)?;

        Ok(MerchantSeedInfo {
            network: self.network,
            accepted_arbiters: self.accepted_arbiters,
            initial_balances,
            merchant_closing_address: closing_address,
            merchant_public_key,
            merchant_nonce: channel_nonce,
        })
    }
}

#[derive(Debug, Clone, Error)]
pub enum MissingSeedInfo {
    #[error("A channel seed must offer at least one arbiter")]
    AcceptedArbiters,
    #[error("Missing initial balances")]
    InitialBalances,
    #[error("Missing closing address")]
    ClosingAddress,
    #[error("Missing merchant public key")]
    MerchantPublicKey,
    #[error("Missing channel nonce")]
    ChannelNonce,
}