use crate::amount::MoneroAmount;
use crate::balance::Balances;
use crate::channel_id::ChannelId;
use crate::channel_metadata::StaticChannelMetadata;
use crate::payment_channel::ChannelRole;
use crate::state_machine::error::LifeCycleError;
use crate::state_machine::{
    ClosedChannelState, ClosingChannelState, DisputingChannelState, EstablishedChannelState, EstablishingState,
};
use ciphersuite::{Ciphersuite, Ed25519};
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
/// `KC` refers to the curve the channel's adaptor signatures and offsets live on.
#[serde(bound = "")]
pub enum ChannelState<KC = Ed25519>
where
    KC: Ciphersuite,
{
    Establishing(EstablishingState<KC>),
    Open(EstablishedChannelState<KC>),
    Closing(ClosingChannelState<KC>),
    Disputing(DisputingChannelState<KC>),
    Closed(ClosedChannelState<KC>),
}

/// Type alias for the default channel curve (Ed25519).
pub type DefaultChannelState = ChannelState<Ed25519>;

impl<KC> Debug for ChannelState<KC>
where
    KC: Ciphersuite,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.stage())
    }
}

impl<KC> ChannelState<KC>
where
    KC: Ciphersuite,
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
    pub fn to_establishing(self) -> Result<EstablishingState<KC>, (Self, LifeCycleError)> {
        match self {
            ChannelState::Establishing(state) => Ok(state),
            _ => Err((self, LifeCycleError::invalid_state_for("Expected EstablishingState"))),
        }
    }

    pub fn as_establishing(&self) -> Result<&EstablishingState<KC>, LifeCycleError> {
        match self {
            ChannelState::Establishing(ref state) => Ok(state),
            _ => Err(LifeCycleError::invalid_state_for("Expected EstablishingState")),
        }
    }

    pub fn as_open(&self) -> Result<&EstablishedChannelState<KC>, LifeCycleError> {
        match self {
            ChannelState::Open(ref state) => Ok(state),
            _ => Err(LifeCycleError::invalid_state_for("Expected EstablishedState")),
        }
    }

    pub fn as_closing(&self) -> Result<&ClosingChannelState<KC>, LifeCycleError> {
        match self {
            ChannelState::Closing(ref state) => Ok(state),
            _ => Err(LifeCycleError::invalid_state_for("Expected ClosingState")),
        }
    }

    #[allow(clippy::result_large_err)]
    pub fn to_open(self) -> Result<EstablishedChannelState<KC>, (Self, LifeCycleError)> {
        match self {
            ChannelState::Open(state) => Ok(state),
            _ => Err((self, LifeCycleError::invalid_state_for("Expected EstablishedChannelState"))),
        }
    }

    #[allow(clippy::result_large_err)]
    pub fn to_closing(self) -> Result<ClosingChannelState<KC>, (Self, LifeCycleError)> {
        match self {
            ChannelState::Closing(state) => Ok(state),
            _ => Err((self, LifeCycleError::invalid_state_for("Expected ClosingChannelState"))),
        }
    }

    pub fn as_disputing(&self) -> Result<&DisputingChannelState<KC>, LifeCycleError> {
        match self {
            ChannelState::Disputing(ref state) => Ok(state),
            _ => Err(LifeCycleError::invalid_state_for("Expected DisputingState")),
        }
    }

    #[allow(clippy::result_large_err)]
    pub fn to_disputing(self) -> Result<DisputingChannelState<KC>, (Self, LifeCycleError)> {
        match self {
            ChannelState::Disputing(state) => Ok(state),
            _ => Err((self, LifeCycleError::invalid_state_for("Expected DisputingChannelState"))),
        }
    }

    #[allow(clippy::result_large_err)]
    pub fn to_closed(self) -> Result<ClosedChannelState<KC>, (Self, LifeCycleError)> {
        match self {
            ChannelState::Closed(state) => Ok(state),
            _ => Err((self, LifeCycleError::invalid_state_for("Expected ClosedChannelState"))),
        }
    }
}

impl<KC> LifeCycle<KC> for ChannelState<KC>
where
    KC: Ciphersuite,
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
    use crate::arbiter::client::statement_for;
    use crate::cryptography::adapter_signature::AdaptedSignature;
    use crate::cryptography::attestation::test_helpers::generate_master_keypair;
    use crate::cryptography::binding_proof::{prove_encrypted_offset, BindingProofParams};
    use crate::cryptography::pvss::SecondBase;
    use crate::cryptography::keys::Curve25519Secret;
    use crate::grease_protocol::multisig_wallet::LinkedMultisigWallets;
    use crate::payment_channel::multisig_negotiation::MultisigWalletKeyNegotiation;
    use crate::payment_channel::ChannelRole;
    use crate::channel_id::ChannelId;
    use crate::grease_protocol::update_record::{CloseHash, HalfSignedUpdateRecord, UpdateRecord, CLOSE_HASH_LEN};
    use crate::state_machine::open_channel::{AppliedUpdate, EstablishedChannelState};
    use crate::wallet::multisig_wallet::MultisigWallet;
    use crate::XmrScalar;
    use ciphersuite::group::ff::Field;
    use ciphersuite::Ed25519;

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

    /// A cross-signed record for `update_count` under throwaway keys. The state-machine plumbing tested here
    /// never re-verifies the signatures; the protocol tests in `tests::update_protocol` do that against the real
    /// channel keys.
    fn record(channel_id: ChannelId, update_count: u64) -> UpdateRecord {
        let mut rng = rand_core::OsRng;
        let close_hash = CloseHash::new([update_count as u8; CLOSE_HASH_LEN]);
        let halves = [ChannelRole::Customer, ChannelRole::Merchant].map(|role| {
            let secret = XmrScalar::random(&mut rng);
            HalfSignedUpdateRecord::sign(channel_id.clone(), update_count, close_hash, role, &secret, &mut rng)
        });
        UpdateRecord::from_halves(&halves[0], &halves[1]).expect("halves agree by construction")
    }

    pub fn payment(state: &mut EstablishedChannelState, amount: &str) -> u64 {
        let delta = MoneroDelta::from(MoneroAmount::from_xmr(amount).unwrap());
        let update_count = state.update_count() + 1;
        let channel_id = state.metadata.channel_id().name();
        let k = XmrScalar::random(&mut rand_core::OsRng);
        let peer_omega = XmrScalar::random(&mut rand_core::OsRng);
        let my_omega = XmrScalar::random(&mut rand_core::OsRng);
        // The retained proof seals the *peer's* offset, so it is sealed against the peer's adaptor point. A cheap
        // cut-and-choose profile keeps these plumbing tests fast; soundness is the binding proof's own concern.
        let peer_binding_proof = prove_encrypted_offset(
            &peer_omega,
            &statement_for(&channel_id, update_count),
            &generate_master_keypair(&mut rand_core::OsRng).1,
            SecondBase::grease_default(),
            BindingProofParams::new(6, 3).unwrap(),
        )
        .expect("sealing a fresh offset always succeeds");
        let update_info = AppliedUpdate {
            record: record(channel_id, update_count),
            my_offset: Curve25519Secret::from(my_omega),
            my_adapted_signature: AdaptedSignature::<Ed25519>::sign(&k, &my_omega, "", &mut rand_core::OsRng),
            peer_adapted_signature: AdaptedSignature::<Ed25519>::sign(&k, &peer_omega, "", &mut rand_core::OsRng),
            peer_binding_proof,
            my_preprocess: vec![],
            peer_preprocess: vec![],
        };
        assert!(update_info.proof_matches_presignature());
        let updated_index = state.store_update(delta, update_info);
        assert_eq!(updated_index, update_count);
        update_count
    }
}
