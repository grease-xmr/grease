use crate::amount::MoneroAmount;
use crate::balance::Balances;
use crate::channel_id::ChannelId;
use crate::channel_metadata::StaticChannelMetadata;
use crate::cryptography::dleq::Dleq;
use crate::payment_channel::ChannelRole;
use crate::state_machine::error::LifeCycleError;
use crate::state_machine::{
    ClosedChannelState, ClosingChannelState, DisputingChannelState, EstablishedChannelState, EstablishingState,
};
use ciphersuite::{Ciphersuite, Ed25519};
use grease_grumpkin::Grumpkin;
use modular_frost::curve::Curve as FrostCurve;
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Display, Formatter};
use thiserror::Error;

/// A lightweight type indicating which phase of the lifecycle we're in. Generally used for reporting purposes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LifecycleStage {
    /// The channel is being established.
    Establishing,
    /// The channel is open and ready to use.
    Open,
    /// The channel is being closed.
    Closing,
    /// The channel is closed and cannot be used anymore.
    Closed,
    /// The channel is in dispute.
    Disputing,
}

impl Display for LifecycleStage {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            LifecycleStage::Establishing => write!(f, "Establishing"),
            LifecycleStage::Open => write!(f, "Open"),
            LifecycleStage::Closing => write!(f, "Closing"),
            LifecycleStage::Closed => write!(f, "Closed"),
            LifecycleStage::Disputing => write!(f, "Disputing"),
        }
    }
}

#[derive(Clone, Debug, Error)]
#[error("Lifecycle error: {0}")]
pub struct StateStorageError(String);

impl StateStorageError {
    pub fn new<T: Into<String>>(msg: T) -> Self {
        StateStorageError(msg.into())
    }
}

pub trait LifeCycle<KC: Ciphersuite = Ed25519> {
    fn name(&self) -> ChannelId {
        self.metadata().channel_id().name()
    }

    fn role(&self) -> ChannelRole {
        self.metadata().role()
    }

    /// Returns the current channel balance. Each state sources this differently:
    /// - Proposing/Establishing: initial balance from channel ID
    /// - Open/Closing/Disputing: dynamic balance from DynamicChannelMetadata
    /// - Closed: stored final balance snapshot
    fn balance(&self) -> Balances;

    fn my_balance(&self) -> MoneroAmount {
        let balance = self.balance();
        match self.role() {
            ChannelRole::Customer => balance.customer,
            ChannelRole::Merchant => balance.merchant,
        }
    }

    /// Get the current lifecycle stage of the channel.
    fn stage(&self) -> LifecycleStage;

    fn metadata(&self) -> &StaticChannelMetadata<KC>;

    fn wallet_address(&self) -> Option<String>;
}

#[derive(Clone, Serialize, Deserialize)]
/// The channel state enum representing all possible lifecycle states.
///
/// The generic parameter `SF` specifies the SNARK-friendly curve used for DLEQ proofs and KES
/// operations for updating channel state.
///
/// `KC` refers to the curve employed by the KES.
#[serde(bound = "")]
pub enum ChannelState<SF = Grumpkin, KC = Ed25519>
where
    SF: FrostCurve,
    KC: FrostCurve,
    Ed25519: Dleq<SF> + Dleq<KC>,
{
    Establishing(EstablishingState<SF, KC>),
    Open(EstablishedChannelState<SF, KC>),
    Closing(ClosingChannelState<SF, KC>),
    Disputing(DisputingChannelState<SF, KC>),
    Closed(ClosedChannelState<SF, KC>),
}

/// Type alias for the default curve type (Grumpkin + Ed25519).
pub type DefaultChannelState = ChannelState<Grumpkin, Ed25519>;

impl<SF, KC> Debug for ChannelState<SF, KC>
where
    SF: FrostCurve,
    KC: FrostCurve,
    Ed25519: Dleq<SF> + Dleq<KC>,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.stage())
    }
}

impl<SF, KC> ChannelState<SF, KC>
where
    SF: FrostCurve,
    KC: FrostCurve,
    Ed25519: Dleq<SF> + Dleq<KC>,
{
    pub fn as_lifecycle(&self) -> &dyn LifeCycle<KC> {
        match self {
            ChannelState::Establishing(state) => state,
            ChannelState::Open(state) => state,
            ChannelState::Closing(state) => state,
            ChannelState::Disputing(state) => state,
            ChannelState::Closed(state) => state,
        }
    }

    #[allow(clippy::result_large_err)]
    pub fn to_establishing(self) -> Result<EstablishingState<SF, KC>, (Self, LifeCycleError)> {
        match self {
            ChannelState::Establishing(state) => Ok(state),
            _ => Err((self, LifeCycleError::invalid_state_for("Expected EstablishingState"))),
        }
    }

    pub fn as_establishing(&self) -> Result<&EstablishingState<SF, KC>, LifeCycleError> {
        match self {
            ChannelState::Establishing(ref state) => Ok(state),
            _ => Err(LifeCycleError::invalid_state_for("Expected EstablishingState")),
        }
    }

    pub fn as_open(&self) -> Result<&EstablishedChannelState<SF, KC>, LifeCycleError> {
        match self {
            ChannelState::Open(ref state) => Ok(state),
            _ => Err(LifeCycleError::invalid_state_for("Expected EstablishedState")),
        }
    }

    pub fn as_closing(&self) -> Result<&ClosingChannelState<SF, KC>, LifeCycleError> {
        match self {
            ChannelState::Closing(ref state) => Ok(state),
            _ => Err(LifeCycleError::invalid_state_for("Expected ClosingState")),
        }
    }

    #[allow(clippy::result_large_err)]
    pub fn to_open(self) -> Result<EstablishedChannelState<SF, KC>, (Self, LifeCycleError)> {
        match self {
            ChannelState::Open(state) => Ok(state),
            _ => Err((self, LifeCycleError::invalid_state_for("Expected EstablishedChannelState"))),
        }
    }

    #[allow(clippy::result_large_err)]
    pub fn to_closing(self) -> Result<ClosingChannelState<SF, KC>, (Self, LifeCycleError)> {
        match self {
            ChannelState::Closing(state) => Ok(state),
            _ => Err((self, LifeCycleError::invalid_state_for("Expected ClosingChannelState"))),
        }
    }

    pub fn as_disputing(&self) -> Result<&DisputingChannelState<SF, KC>, LifeCycleError> {
        match self {
            ChannelState::Disputing(ref state) => Ok(state),
            _ => Err(LifeCycleError::invalid_state_for("Expected DisputingState")),
        }
    }

    #[allow(clippy::result_large_err)]
    pub fn to_disputing(self) -> Result<DisputingChannelState<SF, KC>, (Self, LifeCycleError)> {
        match self {
            ChannelState::Disputing(state) => Ok(state),
            _ => Err((self, LifeCycleError::invalid_state_for("Expected DisputingChannelState"))),
        }
    }

    #[allow(clippy::result_large_err)]
    pub fn to_closed(self) -> Result<ClosedChannelState<SF, KC>, (Self, LifeCycleError)> {
        match self {
            ChannelState::Closed(state) => Ok(state),
            _ => Err((self, LifeCycleError::invalid_state_for("Expected ClosedChannelState"))),
        }
    }
}

impl<SF, KC> LifeCycle<KC> for ChannelState<SF, KC>
where
    SF: FrostCurve,
    KC: FrostCurve,
    Ed25519: Dleq<SF> + Dleq<KC>,
{
    fn stage(&self) -> LifecycleStage {
        self.as_lifecycle().stage()
    }

    fn metadata(&self) -> &StaticChannelMetadata<KC> {
        self.as_lifecycle().metadata()
    }

    fn balance(&self) -> Balances {
        self.as_lifecycle().balance()
    }

    fn wallet_address(&self) -> Option<String> {
        self.as_lifecycle().wallet_address()
    }
}

#[cfg(test)]
pub mod test {
    use crate::amount::{MoneroAmount, MoneroDelta};
    use crate::cryptography::adapter_signature::AdaptedSignature;
    use crate::cryptography::CrossCurveScalar;
    use crate::grease_protocol::multisig_wallet::LinkedMultisigWallets;
    use crate::payment_channel::multisig_negotiation::MultisigWalletKeyNegotiation;
    use crate::payment_channel::ChannelRole;
    use crate::state_machine::open_channel::{EstablishedChannelState, UpdateRecord};
    use crate::wallet::multisig_wallet::MultisigWallet;
    use crate::XmrScalar;
    use ciphersuite::group::ff::Field;
    use ciphersuite::Ed25519;
    use grease_grumpkin::Grumpkin;

    pub fn create_wallet(role: ChannelRole) -> MultisigWallet {
        let mut rng = rand_core::OsRng;
        let peer_role = role.other();
        let mut mine =
            MultisigWalletKeyNegotiation::random(&mut rng, role, monero::Network::Mainnet, "http://localhost:18082");
        let peer = MultisigWalletKeyNegotiation::random(
            &mut rng,
            peer_role,
            monero::Network::Mainnet,
            "http://localhost:18082",
        );
        let peer_key = peer.shared_public_key();
        mine.set_peer_public_key(peer_key).expect("set peer key");
        MultisigWallet::try_from(mine).expect("create wallet keyring")
    }

    pub fn payment(state: &mut EstablishedChannelState<Grumpkin>, amount: &str) -> u64 {
        let delta = MoneroDelta::from(MoneroAmount::from_xmr(amount).unwrap());
        let update_count = state.update_count() + 1;
        let k = XmrScalar::random(&mut rand_core::OsRng);
        let q = XmrScalar::random(&mut rand_core::OsRng);
        let update_info = UpdateRecord {
            my_offset: CrossCurveScalar::random(),
            my_adapted_signature: AdaptedSignature::<Ed25519>::sign(&k, &q, "", &mut rand_core::OsRng),
            peer_adapted_signature: AdaptedSignature::<Ed25519>::sign(&k, &q, "", &mut rand_core::OsRng),
            my_preprocess: vec![],
            peer_preprocess: vec![],
        };
        let updated_index = state.store_update(delta, update_info);
        assert_eq!(updated_index, update_count);
        update_count
    }
}
