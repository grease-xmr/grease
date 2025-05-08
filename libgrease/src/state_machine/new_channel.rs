use crate::amount::MoneroAmount;
use crate::channel_id::ChannelId;
use crate::crypto::traits::PublicKey;
use crate::payment_channel::ChannelRole;
use crate::state_machine::error::InvalidProposal;
use crate::state_machine::establishing_channel::Balances;
use crate::state_machine::traits::ChannelState;
use crate::state_machine::LifecycleStage;
use digest::Digest;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Holds all information that needs to be collected before the merchant and client can begin the channel
/// establishment protocol. At the successful conclusion of this phase, we can emit an `OnNewChannelInfo` event with
/// all the information needed to start the channel establishment protocol.
///
/// There aren't any interaction events in this phase besides the initial call from the customer, so this phase is
/// structured around a builder pattern. Both merchant and customer get the necessary info from "somewhere". In
/// practice, it'll be a QR code or deep link, or a direct RPC call from the customer.
pub struct NewChannelBuilder<P: PublicKey> {
    channel_role: ChannelRole,
    my_public_key: P,
    my_secret_key: P::SecretKey,
    kes_public_key: Option<P>,
    my_label: Option<String>,
    peer_public_key: Option<P>,
    peer_label: Option<String>,
    merchant_amount: Option<MoneroAmount>,
    customer_amount: Option<MoneroAmount>,
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

impl<P: PublicKey> NewChannelBuilder<P> {
    pub fn new(channel_role: ChannelRole, my_public_key: P, my_secret_key: P::SecretKey) -> Self {
        NewChannelBuilder {
            channel_role,
            my_public_key,
            my_secret_key,
            kes_public_key: None,
            my_label: None,
            peer_public_key: None,
            peer_label: None,
            merchant_amount: None,
            customer_amount: None,
        }
    }

    pub fn build<D: Digest>(&self) -> Option<NewChannelState<P>> {
        if self.my_label.is_none()
            || self.peer_label.is_none()
            || (self.merchant_amount.is_none() && self.customer_amount.is_none())
            || self.peer_public_key.is_none()
            || self.kes_public_key.is_none()
        {
            return None;
        }
        let my_salt = self.my_label.clone().unwrap();
        let their_salt = self.peer_label.clone().unwrap();

        let salt = match self.channel_role {
            ChannelRole::Merchant => [my_salt, their_salt].concat(),
            ChannelRole::Customer => [their_salt, my_salt].concat(),
        };
        let merchant_initial = self.merchant_amount.unwrap_or_default();
        let customer_initial = self.customer_amount.unwrap_or_default();
        let initial_balances = Balances::new(merchant_initial, customer_initial);

        let (merchant_label, customer_label) = match self.channel_role {
            ChannelRole::Merchant => (self.my_label.clone().unwrap(), self.peer_label.clone().unwrap()),
            ChannelRole::Customer => (self.peer_label.clone().unwrap(), self.my_label.clone().unwrap()),
        };
        let channel_id = ChannelId::new::<D, _, _, _>(merchant_label, customer_label, salt, initial_balances);
        let (merchant_pubkey, customer_pubkey) = match self.channel_role {
            ChannelRole::Merchant => (self.my_public_key.clone(), self.peer_public_key.clone().unwrap()),
            ChannelRole::Customer => (self.peer_public_key.clone().unwrap(), self.my_public_key.clone()),
        };
        Some(NewChannelState {
            role: self.channel_role,
            merchant_pubkey,
            customer_pubkey,
            kes_public_key: self.kes_public_key.clone().unwrap(),
            secret_key: self.my_secret_key.clone(),
            initial_balances,
            customer_label: self.my_label.clone().unwrap(),
            merchant_label: self.peer_label.clone().unwrap(),
            channel_id,
        })
    }

    pub fn with_peer_public_key(mut self, peer_public_key: P) -> Self {
        self.peer_public_key = Some(peer_public_key);
        self
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

    pub fn with_kes_public_key(mut self, kes_public_key: P) -> Self {
        self.kes_public_key = Some(kes_public_key);
        self
    }
}

/// The internal state of the channel in the "new" phase.
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(deserialize = "P: PublicKey  + for<'d> Deserialize<'d>"))]
pub struct NewChannelState<P>
where
    P: PublicKey,
{
    /// My role, whether customer or merchant
    pub role: ChannelRole,
    /// My secret key for the 2-of-2 multisig wallet
    pub(crate) secret_key: P::SecretKey,
    /// The public key of the merchant, for use in adaptor signatures
    pub merchant_pubkey: P,
    /// The public key of the customer, for use in adaptor signatures
    pub customer_pubkey: P,
    /// The public key of the KES key, for encrypting the secret share
    pub kes_public_key: P,
    /// The amount of money in the channel
    pub initial_balances: Balances,
    /// Salt used to derive the channel ID - customer portion
    pub customer_label: String,
    /// Salt used to derive the channel ID - merchant portion
    pub merchant_label: String,
    /// The channel ID
    pub channel_id: ChannelId,
}

impl<P: PublicKey> NewChannelState<P> {
    /// A sanity check to make sure that information coming from the peer in the proposal matches what I shared with
    /// her initially.
    pub fn review_proposal(&self, proposal: &ProposedChannelInfo<P>) -> Result<(), InvalidProposal> {
        if self.role == proposal.role {
            return Err(InvalidProposal::IncompatibleRoles);
        }
        if self.initial_balances != proposal.initial_balances {
            return Err(InvalidProposal::MismatchedBalances);
        }
        if self.merchant_pubkey != proposal.merchant_pubkey {
            return Err(InvalidProposal::MismatchedMerchantPublicKey);
        }
        if self.customer_pubkey != proposal.customer_pubkey {
            return Err(InvalidProposal::MismatchedCustomerPublicKey);
        }
        if self.kes_public_key != proposal.kes_public_key {
            return Err(InvalidProposal::MismatchedKesPublicKey);
        }
        if self.channel_id != proposal.channel_id {
            return Err(InvalidProposal::MismatchedChannelId);
        }
        Ok(())
    }

    /// Convert this state (which contains a secret key) into a proposal (which does not).
    pub fn for_proposal(&self) -> ProposedChannelInfo<P> {
        ProposedChannelInfo {
            role: self.role,
            merchant_pubkey: self.merchant_pubkey.clone(),
            customer_pubkey: self.customer_pubkey.clone(),
            kes_public_key: self.kes_public_key.clone(),
            initial_balances: self.initial_balances,
            customer_label: self.customer_label.clone(),
            merchant_label: self.merchant_label.clone(),
            channel_id: self.channel_id.clone(),
        }
    }
}

impl<P: PublicKey> ChannelState for NewChannelState<P> {
    fn channel_id(&self) -> &ChannelId {
        &self.channel_id
    }

    fn role(&self) -> ChannelRole {
        self.role
    }
}

#[derive(Clone)]
pub struct ProposedChannelInfo<P: PublicKey> {
    pub role: ChannelRole,
    pub merchant_pubkey: P,
    pub customer_pubkey: P,
    pub kes_public_key: P,
    /// The amount of money in the channel
    pub initial_balances: Balances,
    /// Salt used to derive the channel ID - customer portion
    pub customer_label: String,
    /// Salt used to derive the channel ID - merchant portion
    pub merchant_label: String,
    /// The channel ID
    pub channel_id: ChannelId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TimeoutReason {
    /// The reason for the timeout
    reason: String,
    /// The phase of the lifecycle when the timeout occurred
    stage: LifecycleStage,
}

impl TimeoutReason {
    pub fn new(reason: impl Into<String>, stage: LifecycleStage) -> Self {
        TimeoutReason { reason: reason.into(), stage }
    }

    /// Get the reason for the timeout
    pub fn reason(&self) -> &str {
        &self.reason
    }

    /// Get the stage of the lifecycle when the timeout occurred
    pub fn stage(&self) -> LifecycleStage {
        self.stage
    }
}

/// A record that (usually) the merchant will send offline to the customer to give them the seed information they
/// need to complete a new channel proposal.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(deserialize = "P: PublicKey  + for<'d> Deserialize<'d>"))]
pub struct ChannelSeedInfo<P>
where
    P: PublicKey,
{
    /// Peer's role. Usually, this will be [`ChannelRole::Customer`]
    pub role: ChannelRole,
    /// The public key of the merchant, for use in adaptor signatures
    pub pubkey: P,
    /// The key id for the merchant, to help them identify this proposal.
    pub key_id: u64,
    /// The proposed KES public key. May or may not be accepted by the peer.
    pub kes_public_key: P,
    /// The proposed initial set of channel balances
    pub initial_balances: Balances,
    /// The user label for the (usually) merchant.
    pub user_label: String,
}

/// The builder struct for the [`ChannelSeedInfo`].
/// See [`ChannelSeedInfo`] for more information about each field.
pub struct ChannelSeedBuilder<P>
where
    P: PublicKey,
{
    role: ChannelRole,
    pubkey: Option<P>,
    key_id: Option<u64>,
    kes_public_key: Option<P>,
    initial_balances: Option<Balances>,
    user_label: Option<String>,
}

impl<P: PublicKey> ChannelSeedBuilder<P> {
    pub fn new(peer_role: ChannelRole) -> Self {
        ChannelSeedBuilder {
            role: peer_role,
            pubkey: None,
            key_id: None,
            kes_public_key: None,
            initial_balances: None,
            user_label: None,
        }
    }

    pub fn with_pubkey(mut self, pubkey: P) -> Self {
        self.pubkey = Some(pubkey);
        self
    }

    pub fn with_kes_public_key(mut self, kes_public_key: P) -> Self {
        self.kes_public_key = Some(kes_public_key);
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

    pub fn build(self) -> Result<ChannelSeedInfo<P>, MissingSeedInfo> {
        let pubkey = self.pubkey.ok_or(MissingSeedInfo::MissingPublicKey)?;
        let key_id = self.key_id.ok_or(MissingSeedInfo::MissingKeyId)?;
        let kes_public_key = self.kes_public_key.ok_or(MissingSeedInfo::MissingKesPublicKey)?;
        let initial_balances = self.initial_balances.ok_or(MissingSeedInfo::MissingInitialBalances)?;
        let user_label = self.user_label.ok_or(MissingSeedInfo::MissingPartialChannelId)?;

        Ok(ChannelSeedInfo { role: self.role, pubkey, key_id, kes_public_key, initial_balances, user_label })
    }
}

impl<P: PublicKey> Default for ChannelSeedBuilder<P> {
    fn default() -> Self {
        ChannelSeedBuilder::new(ChannelRole::Customer)
    }
}

#[derive(Debug, Clone, Error)]
pub enum MissingSeedInfo {
    #[error("Missing public key")]
    MissingPublicKey,
    #[error("Missing merchant key id")]
    MissingKeyId,
    #[error("Missing KES public key")]
    MissingKesPublicKey,
    #[error("Missing initial balances")]
    MissingInitialBalances,
    #[error("Missing partial channel ID")]
    MissingPartialChannelId,
}
