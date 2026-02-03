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
use monero::Network;
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

    fn wallet_address(&self, network: Network) -> Option<String>;
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

    fn wallet_address(&self, network: Network) -> Option<String> {
        self.as_lifecycle().wallet_address(network)
    }
}

#[cfg(test)]
pub mod test {
    use crate::amount::{MoneroAmount, MoneroDelta};
    use crate::cryptography::adapter_signature::AdaptedSignature;
    use crate::cryptography::keys::{Curve25519PublicKey, Curve25519Secret, PublicKey};
    use crate::cryptography::pok::KesPoK;
    use crate::cryptography::pok::KesPoKProofs;
    use crate::cryptography::ChannelWitness;
    use crate::impls::tests::propose_protocol;
    use crate::monero::data_objects::{TransactionId, TransactionRecord};
    use crate::multisig::MultisigWalletData;
    use crate::payment_channel::ChannelRole;
    use crate::state_machine::establishing_channel::EstablishingState;
    use crate::state_machine::lifecycle::{LifeCycle, LifecycleStage};
    use crate::state_machine::open_channel::{EstablishedChannelState, UpdateRecord};
    use crate::state_machine::ChannelCloseRecord;
    use crate::XmrScalar;
    use ciphersuite::group::ff::Field;
    use ciphersuite::{Ciphersuite, Ed25519};
    use grease_grumpkin::Grumpkin;
    use log::*;

    /// Creates a new EstablishingState by running the full proposal protocol (customer side).
    pub fn new_establishing_state() -> EstablishingState<Grumpkin> {
        let (_merchant, customer) = propose_protocol::establish_channel();
        customer
    }

    pub fn create_wallet(role: ChannelRole) -> MultisigWalletData {
        let some_secret =
            Curve25519Secret::from_hex("8eb8a1fd0f2c42fa7508a8883addb0860a0c5e44c1c14605abb385375c533609").unwrap();
        let some_pub = Curve25519PublicKey::from_secret(&some_secret);
        MultisigWalletData {
            my_spend_key: some_secret.clone(),
            my_public_key: some_pub.clone(),
            sorted_pubkeys: [some_pub.clone(), some_pub.clone()],
            joint_public_spend_key: some_pub.clone(),
            joint_private_view_key: Curve25519Secret::random(&mut rand_core::OsRng),
            birthday: 0,
            known_outputs: Default::default(),
            role,
        }
    }

    pub fn establish_channel(mut state: EstablishingState<Grumpkin>) -> EstablishedChannelState<Grumpkin> {
        let mut rng = rand_core::OsRng;

        // Initialize protocol context (generates DLEQ proof, encrypted offset, stores witness)
        state.generate_channel_secrets(&mut rng).expect("channel secret generation");

        // Generate init package to populate adapted_sig (deferred from init_protocol_context)
        let _pkg = state.generate_init_package(&mut rng).expect("generate init package");

        // The multisig wallet protocol is complete.
        let wallet = create_wallet(state.role());
        state.wallet_created(wallet);

        // Set peer data (use own data as placeholders for requirements_met)
        let own_dleq = state.dleq_proof.clone().unwrap();
        state.set_peer_dleq_proof(own_dleq);
        let own_sig = state.adapted_sig.clone().unwrap();
        state.set_peer_adapted_signature(own_sig);
        let own_chi = state.encrypted_offset.clone().unwrap();
        state.set_peer_encrypted_offset(own_chi);
        let own_payload_sig = state.payload_sig.clone().unwrap();
        state.peer_payload_sig = Some(own_payload_sig);
        state.peer_nonce_pubkey = Some(Ed25519::generator() * XmrScalar::random(&mut rng));
        state.save_funding_tx_pipe(vec![1]);

        // The funding transaction has been created and broadcast.
        let tx = TransactionRecord {
            channel_name: "channel".to_string(),
            transaction_id: TransactionId::new("fundingtx1"),
            amount: MoneroAmount::from_xmr("1.25").unwrap(),
            serialized: b"serialized_funding_tx".to_vec(),
        };
        state.funding_tx_confirmed(tx);

        // The KES details have been exchanged.
        let mut rng = rand_core::OsRng;
        let shard = XmrScalar::random(&mut rng);
        let private_key = XmrScalar::random(&mut rng);
        let kes_proof = KesPoKProofs {
            customer_pok: KesPoK::<Ed25519>::prove(&mut rng, &shard, &private_key),
            merchant_pok: KesPoK::<Ed25519>::prove(&mut rng, &shard, &private_key),
        };
        state.kes_created(kes_proof);

        match state.next() {
            Ok(open) => {
                assert_eq!(open.stage(), LifecycleStage::Open);
                assert_eq!(open.role(), ChannelRole::Customer);
                assert_eq!(open.my_balance(), MoneroAmount::from_xmr("1.25").unwrap());
                info!("Channel established successfully");
                open
            }
            Err((s, e)) => {
                error!("Failed to establish channel: {:?}", e);
                error!("state: {s:?}");
                panic!("Failed to transition to Established state: {:?}", s);
            }
        }
    }

    pub fn payment(state: &mut EstablishedChannelState<Grumpkin>, amount: &str) -> u64 {
        let delta = MoneroDelta::from(MoneroAmount::from_xmr(amount).unwrap());
        let update_count = state.update_count() + 1;
        let k = XmrScalar::random(&mut rand_core::OsRng);
        let q = XmrScalar::random(&mut rand_core::OsRng);
        let update_info = UpdateRecord {
            my_offset: ChannelWitness::random(),
            my_adapted_signature: AdaptedSignature::<Ed25519>::sign(&k, &q, "", &mut rand_core::OsRng),
            peer_adapted_signature: AdaptedSignature::<Ed25519>::sign(&k, &q, "", &mut rand_core::OsRng),
            my_preprocess: vec![],
            peer_preprocess: vec![],
        };
        let updated_index = state.store_update(delta, update_info);
        assert_eq!(updated_index, update_count);
        update_count
    }

    #[test]
    fn happy_path() {
        env_logger::try_init().ok();
        let state = new_establishing_state();
        let mut state = establish_channel(state);
        // first payment
        let count = payment(&mut state, "0.1");
        assert_eq!(count, 1);
        // second payment
        let count = payment(&mut state, "0.2");
        assert_eq!(count, 2);
        // 3rd payment
        let count = payment(&mut state, "0.3");
        assert_eq!(count, 3);
        assert_eq!(state.update_count(), 3);
        assert_eq!(state.role(), ChannelRole::Customer);
        assert_eq!(state.my_balance(), MoneroAmount::from_xmr("0.65").unwrap());
        let close = ChannelCloseRecord::<Grumpkin> {
            final_balance: state.balance(),
            update_count: state.update_count(),
            witness: ChannelWitness::random(),
        };
        let Ok(mut state) = state.close(close) else {
            panic!("Failed to transition to closing state");
        };
        state.with_final_tx(TransactionId::new("finaltx1"));
        let Ok(state) = state.next() else {
            panic!("Failed to close channel");
        };
        let final_balance = state.balance();
        assert_eq!(state.stage(), LifecycleStage::Closed);
        assert_eq!(final_balance.customer, MoneroAmount::from_xmr("0.65").unwrap());
        assert_eq!(final_balance.merchant, MoneroAmount::from_xmr("0.60").unwrap());
    }
}
