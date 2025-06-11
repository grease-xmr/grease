use crate::amount::MoneroAmount;
use crate::balance::Balances;
use crate::channel_id::ChannelId;
use crate::channel_metadata::ChannelMetadata;
use crate::lifecycle_impl;
use crate::payment_channel::ChannelRole;
use crate::state_machine::error::{InvalidProposal, LifeCycleError};
use crate::state_machine::establishing_channel::EstablishingState;
use crate::state_machine::lifecycle::{ChannelState, LifeCycle, LifecycleStage};
use crate::state_machine::timeouts::TimeoutReason;
use crate::state_machine::{ChannelClosedReason, ClosedChannelState};
use digest::Digest;
use log::*;
use monero::Network;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Holds all information that needs to be collected before the merchant and client can begin the channel
/// establishment protocol. At the successful conclusion of this phase, we can emit an `OnNewChannelInfo` event with
/// all the information needed to start the channel establishment protocol.
///
/// There aren't any interaction events in this phase besides the initial call from the customer, so this phase is
/// structured around a builder pattern. Both merchant and customer get the necessary info from "somewhere". In
/// practice, it'll be a QR code or deep link, or a direct RPC call from the customer.
pub struct NewChannelBuilder {
    network: Option<Network>,
    channel_role: ChannelRole,
    // The KES public key used to encrypt the multisig spend key
    kes_public_key: Option<String>,
    merchant_amount: Option<MoneroAmount>,
    customer_amount: Option<MoneroAmount>,
    peer_label: Option<String>,
    my_label: Option<String>,
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

impl NewChannelBuilder {
    pub fn new(channel_role: ChannelRole) -> Self {
        NewChannelBuilder {
            network: None,
            channel_role,
            kes_public_key: None,
            my_label: None,
            peer_label: None,
            merchant_amount: None,
            customer_amount: None,
        }
    }

    pub fn build<D: Digest>(&self) -> Option<NewChannelState> {
        if self.my_label.is_none()
            || self.peer_label.is_none()
            || (self.merchant_amount.is_none() && self.customer_amount.is_none())
            || self.kes_public_key.is_none()
        {
            return None;
        }

        let merchant_initial = self.merchant_amount.unwrap_or_default();
        let customer_initial = self.customer_amount.unwrap_or_default();
        let initial_balances = Balances::new(merchant_initial, customer_initial);

        // Total balance may not be zero
        if initial_balances.total().is_zero() {
            return None;
        }

        let (merchant_label, customer_label) = match self.channel_role {
            ChannelRole::Merchant => (self.my_label.clone().unwrap(), self.peer_label.clone().unwrap()),
            ChannelRole::Customer => (self.peer_label.clone().unwrap(), self.my_label.clone().unwrap()),
        };
        let channel_id = ChannelId::new::<D>(merchant_label.clone(), customer_label.clone(), initial_balances);
        let channel_info = ChannelMetadata::new(
            self.network.unwrap_or(Network::Mainnet),
            self.channel_role,
            channel_id,
            self.kes_public_key.clone().unwrap(),
        );
        Some(NewChannelState { metadata: channel_info, customer_label, merchant_label })
    }

    pub fn with_peer_label(mut self, peer_label: &str) -> Self {
        self.peer_label = Some(peer_label.to_string());
        self
    }

    pub fn with_my_user_label(mut self, my_user_label: &str) -> Self {
        self.my_label = Some(my_user_label.to_string());
        self
    }

    pub fn with_merchant_initial_balance<A: Into<MoneroAmount>>(mut self, amount: A) -> Self {
        self.merchant_amount = Some(amount.into());
        self
    }

    pub fn with_customer_initial_balance<A: Into<MoneroAmount>>(mut self, amount: A) -> Self {
        self.customer_amount = Some(amount.into());
        self
    }

    pub fn with_kes_public_key(mut self, kes_public_key: impl Into<String>) -> Self {
        self.kes_public_key = Some(kes_public_key.into());
        self
    }
}

/// The internal state of the channel in the "new" phase.
#[derive(Clone, Serialize, Deserialize)]
pub struct NewChannelState {
    pub metadata: ChannelMetadata,
    pub customer_label: String,
    /// Salt used to derive the channel ID - merchant portion
    pub merchant_label: String,
}

impl NewChannelState {
    /// A sanity check to make sure that information coming from the customer in the proposal matches what was shared
    /// initially.
    fn review_proposal(&self, proposal: &ProposedChannelInfo) -> Result<(), InvalidProposal> {
        debug!("Internal sanity check on proposal info");
        if self.metadata.balances().total().is_zero() {
            return Err(InvalidProposal::ZeroTotalValue);
        }
        if self.metadata.balances() != proposal.initial_balances {
            return Err(InvalidProposal::MismatchedBalances);
        }
        if self.metadata.kes_public_key() != proposal.kes_public_key {
            return Err(InvalidProposal::MismatchedKesPublicKey);
        }
        if self.metadata.channel_id().name() != proposal.channel_name {
            return Err(InvalidProposal::MismatchedChannelId);
        }
        Ok(())
    }

    /// Convert this state (which contains a secret key) into a proposal (which does not).
    pub fn for_proposal(&self) -> ProposedChannelInfo {
        ProposedChannelInfo {
            role: self.metadata.role(),
            kes_public_key: self.metadata.kes_public_key().to_string(),
            initial_balances: self.metadata.balances(),
            customer_label: self.customer_label.clone(),
            merchant_label: self.merchant_label.clone(),
            channel_name: self.metadata.channel_id().name(),
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
    pub fn next(
        self,
        proposal: ProposedChannelInfo,
    ) -> Result<EstablishingState, (ClosedChannelState, LifeCycleError)> {
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

#[derive(Clone)]
pub struct ProposedChannelInfo {
    pub role: ChannelRole,
    pub kes_public_key: String,
    /// The amount of money in the channel
    pub initial_balances: Balances,
    /// Salt used to derive the channel ID - customer portion
    pub customer_label: String,
    /// Salt used to derive the channel ID - merchant portion
    pub merchant_label: String,
    /// The channel name, as given by `ChannelId::name()`
    pub channel_name: String,
}

/// A record that (usually) the merchant will send offline to the customer to give them the seed information they
/// need to complete a new channel proposal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelSeedInfo {
    /// Peer's role. Usually, this will be [`ChannelRole::Customer`]
    pub role: ChannelRole,
    /// The key id for the merchant, to help them identify this proposal.
    pub key_id: u64,
    /// The proposed KES public key. May or may not be accepted by the peer.
    pub kes_public_key: String,
    /// The proposed initial set of channel balances
    pub initial_balances: Balances,
    /// The user label for the (usually) merchant.
    pub user_label: String,
}

/// The builder struct for the [`ChannelSeedInfo`].
/// See [`ChannelSeedInfo`] for more information about each field.
pub struct ChannelSeedBuilder {
    role: ChannelRole,
    key_id: Option<u64>,
    kes_public_key: Option<String>,
    initial_balances: Option<Balances>,
    user_label: Option<String>,
}

impl ChannelSeedBuilder {
    pub fn new(peer_role: ChannelRole) -> Self {
        ChannelSeedBuilder {
            role: peer_role,
            key_id: None,
            kes_public_key: None,
            initial_balances: None,
            user_label: None,
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

    pub fn with_user_label(mut self, label: impl Into<String>) -> Self {
        self.user_label = Some(label.into());
        self
    }

    pub fn with_key_id(mut self, key_id: u64) -> Self {
        self.key_id = Some(key_id);
        self
    }

    pub fn build(self) -> Result<ChannelSeedInfo, MissingSeedInfo> {
        let key_id = self.key_id.ok_or(MissingSeedInfo::Missing)?;
        let kes_public_key = self.kes_public_key.ok_or(MissingSeedInfo::KesPublicKey)?;
        let initial_balances = self.initial_balances.ok_or(MissingSeedInfo::InitialBalances)?;
        let user_label = self.user_label.ok_or(MissingSeedInfo::PartialChannelId)?;

        Ok(ChannelSeedInfo { role: self.role, key_id, kes_public_key, initial_balances, user_label })
    }
}

impl Default for ChannelSeedBuilder {
    fn default() -> Self {
        ChannelSeedBuilder::new(ChannelRole::Customer)
    }
}

#[derive(Debug, Clone, Error)]
pub enum MissingSeedInfo {
    #[error("Missing public key")]
    PublicKey,
    #[error("Missing merchant key id")]
    Missing,
    #[error("Missing KES public key")]
    KesPublicKey,
    #[error("Missing initial balances")]
    InitialBalances,
    #[error("Missing partial channel ID")]
    PartialChannelId,
}
