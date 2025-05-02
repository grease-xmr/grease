use crate::amount::MoneroAmount;
use crate::channel_id::ChannelId;
use crate::crypto::traits::PublicKey;
use crate::payment_channel::ChannelRole;
use crate::state_machine::error::InvalidProposal;
use crate::state_machine::establishing_channel::Balances;
use crate::state_machine::traits::ChannelState;
use crate::state_machine::LifecycleStage;
use digest::Digest;

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
    my_partial_channel_id: Option<Vec<u8>>,
    peer_public_key: Option<P>,
    peer_partial_channel_id: Option<Vec<u8>>,
    merchant_amount: Option<MoneroAmount>,
    customer_amount: Option<MoneroAmount>,
}

#[derive(Debug, Clone)]
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
            my_partial_channel_id: None,
            peer_public_key: None,
            peer_partial_channel_id: None,
            merchant_amount: None,
            customer_amount: None,
        }
    }

    pub fn build<D: Digest>(&self) -> Option<NewChannelState<P>> {
        if self.my_partial_channel_id.is_none()
            || self.peer_partial_channel_id.is_none()
            || (self.merchant_amount.is_none() && self.customer_amount.is_none())
            || self.peer_public_key.is_none()
            || self.kes_public_key.is_none()
        {
            return None;
        }
        let my_salt = self.my_partial_channel_id.clone().unwrap();
        let their_salt = self.peer_partial_channel_id.clone().unwrap();

        let salt = match self.channel_role {
            ChannelRole::Merchant => [my_salt, their_salt].concat(),
            ChannelRole::Customer => [their_salt, my_salt].concat(),
        };
        let merchant_initial = self.merchant_amount.clone().unwrap_or_default();
        let customer_initial = self.customer_amount.clone().unwrap_or_default();
        let initial_balances = Balances::new(merchant_initial, customer_initial);
        let channel_id = ChannelId::new::<D, _, _, _>(
            self.my_partial_channel_id.clone().unwrap(),
            self.peer_partial_channel_id.clone().unwrap(),
            salt,
            initial_balances,
        );
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
            customer_partial_channel_id: self.my_partial_channel_id.clone().unwrap(),
            merchant_partial_channel_id: self.peer_partial_channel_id.clone().unwrap(),
            channel_id,
        })
    }

    pub fn with_peer_public_key(mut self, peer_public_key: P) -> Self {
        self.peer_public_key = Some(peer_public_key);
        self
    }

    pub fn with_peer_partial_channel_id(mut self, peer_partial_channel_id: Vec<u8>) -> Self {
        self.peer_partial_channel_id = Some(peer_partial_channel_id);
        self
    }

    pub fn with_my_partial_channel_id(mut self, my_partial_channel_id: Vec<u8>) -> Self {
        self.my_partial_channel_id = Some(my_partial_channel_id);
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
#[derive(Clone)]
pub struct NewChannelState<P: PublicKey> {
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
    pub customer_partial_channel_id: Vec<u8>,
    /// Salt used to derive the channel ID - merchant portion
    pub merchant_partial_channel_id: Vec<u8>,
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
    pub customer_partial_channel_id: Vec<u8>,
    /// Salt used to derive the channel ID - merchant portion
    pub merchant_partial_channel_id: Vec<u8>,
    /// The channel ID
    pub channel_id: ChannelId,
}

#[derive(Clone, Debug)]
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
