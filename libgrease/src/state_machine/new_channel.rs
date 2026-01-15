use crate::balance::Balances;
use crate::channel_id::ChannelIdMetadata;
use crate::channel_metadata::ChannelMetadata;
use crate::cryptography::keys::Curve25519PublicKey;
use crate::lifecycle_impl;
use crate::payment_channel::ChannelRole;
use crate::state_machine::error::{InvalidProposal, LifeCycleError};
use crate::state_machine::establishing_channel::EstablishingState;
use crate::state_machine::lifecycle::{ChannelState, LifeCycle, LifecycleStage};
use crate::state_machine::timeouts::TimeoutReason;
use crate::state_machine::{ChannelClosedReason, ClosedChannelState};
use log::*;
use monero::{Address, Network};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NewChannelProposal {
    /// The Monero network this channel lives on
    #[serde(
        deserialize_with = "crate::monero::helpers::deserialize_network",
        serialize_with = "crate::monero::helpers::serialize_network"
    )]
    pub network: Network,
    pub channel_id: ChannelIdMetadata,
    /// The seed info that the (usually) merchant provided initially.
    pub seed: ChannelSeedInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RejectNewChannelReason(String);

impl RejectNewChannelReason {
    pub fn new(reason: impl Into<String>) -> Self {
        RejectNewChannelReason(reason.into())
    }

    pub fn reason(&self) -> &str {
        &self.0
    }
}

/// The internal state of the channel in the "new" phase.
#[derive(Clone, Serialize, Deserialize)]
pub struct NewChannelState {
    pub metadata: ChannelMetadata,
    pub seed_info: ChannelSeedInfo,
}

impl NewChannelState {
    /// Create a new `NewChannelState` from the accepted proposal.
    ///
    /// At this stage the proposal must have already been checked and validated, hence `accepted_proposal`.
    /// The `seed_info` is largely kept for record-keeping; if any values differ between the proposal and the seed info,
    /// the proposal values take precedence.
    pub fn new(role: ChannelRole, accepted_proposal: NewChannelProposal) -> Self {
        let metadata = ChannelMetadata::new(
            accepted_proposal.seed.network,
            role,
            accepted_proposal.channel_id,
            accepted_proposal.seed.kes_public_key.clone(),
        );
        NewChannelState { metadata, seed_info: accepted_proposal.seed }
    }
    /// A sanity check to make sure that information coming from the customer in the proposal matches what was shared
    /// initially.
    fn review_proposal(&self, proposal: &NewChannelProposal) -> Result<(), InvalidProposal> {
        debug!("Internal sanity check on proposal info");
        if self.metadata.balances().total().is_zero() {
            return Err(InvalidProposal::ZeroTotalValue);
        }
        if self.metadata.balances() != proposal.channel_id.initial_balance() {
            return Err(InvalidProposal::MismatchedBalances);
        }
        if self.metadata.kes_public_key() != proposal.seed.kes_public_key {
            return Err(InvalidProposal::MismatchedKesPublicKey);
        }
        if self.metadata.channel_id().name() != proposal.channel_id.name() {
            return Err(InvalidProposal::MismatchedChannelId);
        }
        Ok(())
    }

    /// Convert this state (which contains a secret key) into a proposal (which does not).
    pub fn for_proposal(&self) -> NewChannelProposal {
        NewChannelProposal {
            network: self.metadata.network(),
            channel_id: self.metadata.channel_id().clone(),
            seed: self.seed_info.clone(),
        }
    }

    pub fn multisig_address(&self, _: Network) -> Option<String> {
        None
    }

    pub fn to_channel_state(self) -> ChannelState {
        ChannelState::New(self)
    }

    /// Given the proposal (which MUST already have been vetted by any delegate workers), transition to the next state.
    ///
    /// This is typically `EstablishingState`, but if the sanity checks fail, it will immediately close the channel and
    /// return an error.
    #[allow(clippy::result_large_err)]
    pub fn next(self, proposal: NewChannelProposal) -> Result<EstablishingState, (ClosedChannelState, LifeCycleError)> {
        match self.review_proposal(&proposal) {
            Err(err) => {
                let msg = format!("New channel proposal failed basic sanity checks: {}", err);
                info!("{msg}. The channel will be closed");
                let closed = ClosedChannelState::new(
                    ChannelClosedReason::Rejected(RejectNewChannelReason::new(msg)),
                    self.metadata,
                );
                Err((closed, err.into()))
            }
            Ok(()) => {
                debug!("Transitioning from New to Establishing state");
                let establishing_state = self.into();
                Ok(establishing_state)
            }
        }
    }

    /// Close the channel due to invalid or unacceptable terms in the proposal. The reason for the rejection is
    /// included so that it can be logged or displayed to the user.
    pub fn reject(self, reason: RejectNewChannelReason) -> ClosedChannelState {
        let msg = format!("New channel proposal was explicitly rejected: {}", reason.reason());
        info!("{msg}. The channel will be closed");
        ClosedChannelState::new(ChannelClosedReason::Rejected(reason), self.metadata)
    }

    /// Close the channel due to a lack of response from the peer.
    pub fn timeout(self, reason: TimeoutReason) -> ClosedChannelState {
        let msg = format!("New channel proposal has timed out: {}", reason.reason());
        info!("{msg}. The channel will be closed");
        ClosedChannelState::new(ChannelClosedReason::Timeout(reason), self.metadata)
    }
}

lifecycle_impl!(NewChannelState, New);

/// A record that (usually) the merchant will send offline to the customer to give them the seed information they
/// need to complete a new channel proposal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelSeedInfo {
    /// The Monero network this channel will run on
    #[serde(
        deserialize_with = "crate::monero::helpers::deserialize_network",
        serialize_with = "crate::monero::helpers::serialize_network"
    )]
    pub network: Network,
    /// Peer's role. Usually, this will be [`ChannelRole::Customer`]
    pub role: ChannelRole,
    /// The proposed KES public key. May or may not be accepted by the peer.
    pub kes_public_key: String,
    /// The proposed initial set of channel balances
    pub initial_balances: Balances,
    /// The address that the closing transaction must pay into
    pub merchant_closing_address: Address,
    /// The public key for channel ID derivation (from the seed provider, usually merchant)
    pub merchant_channel_key: Curve25519PublicKey,
    /// The merchant nonce for channel ID derivation, to help them identify this proposal.
    pub merchant_nonce: u64,
}

/// The builder struct for the [`ChannelSeedInfo`].
/// See [`ChannelSeedInfo`] for more information about each field.
pub struct ChannelSeedBuilder {
    role: ChannelRole,
    network: Network,
    kes_public_key: Option<String>,
    initial_balances: Option<Balances>,
    closing_address: Option<Address>,
    channel_key: Option<Curve25519PublicKey>,
    channel_nonce: Option<u64>,
}

impl ChannelSeedBuilder {
    pub fn new(peer_role: ChannelRole, network: Network) -> Self {
        ChannelSeedBuilder {
            network,
            role: peer_role,
            kes_public_key: None,
            initial_balances: None,
            closing_address: None,
            channel_key: None,
            channel_nonce: None,
        }
    }

    pub fn with_kes_public_key(mut self, kes_public_key: impl Into<String>) -> Self {
        self.kes_public_key = Some(kes_public_key.into());
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

    pub fn with_channel_key(mut self, key: Curve25519PublicKey) -> Self {
        self.channel_key = Some(key);
        self
    }

    pub fn with_channel_nonce(mut self, nonce: u64) -> Self {
        self.channel_nonce = Some(nonce);
        self
    }

    pub fn build(self) -> Result<ChannelSeedInfo, MissingSeedInfo> {
        let kes_public_key = self.kes_public_key.ok_or(MissingSeedInfo::KesPublicKey)?;
        let initial_balances = self.initial_balances.ok_or(MissingSeedInfo::InitialBalances)?;
        let closing_address = self.closing_address.ok_or(MissingSeedInfo::ClosingAddress)?;
        let channel_key = self.channel_key.ok_or(MissingSeedInfo::ChannelKey)?;
        let channel_nonce = self.channel_nonce.ok_or(MissingSeedInfo::ChannelNonce)?;

        Ok(ChannelSeedInfo {
            network: self.network,
            role: self.role,
            kes_public_key,
            initial_balances,
            merchant_closing_address: closing_address,
            merchant_channel_key: channel_key,
            merchant_nonce: channel_nonce,
        })
    }
}

impl Default for ChannelSeedBuilder {
    fn default() -> Self {
        ChannelSeedBuilder::new(ChannelRole::Customer, Network::Mainnet)
    }
}

#[derive(Debug, Clone, Error)]
pub enum MissingSeedInfo {
    #[error("Missing KES public key")]
    KesPublicKey,
    #[error("Missing initial balances")]
    InitialBalances,
    #[error("Missing closing address")]
    ClosingAddress,
    #[error("Missing channel key")]
    ChannelKey,
    #[error("Missing channel nonce")]
    ChannelNonce,
}
