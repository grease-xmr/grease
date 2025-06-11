use crate::amount::MoneroAmount;
use crate::balance::Balances;
use crate::channel_metadata::ChannelMetadata;
use crate::payment_channel::ChannelRole;
use crate::state_machine::error::LifeCycleError;
use crate::state_machine::{
    ClosedChannelState, ClosingChannelState, EstablishedChannelState, EstablishingState, NewChannelState,
};
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Display, Formatter};
use thiserror::Error;

/// A lightweight type indicating which phase of the lifecycle we're in. Generally used for reporting purposes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LifecycleStage {
    /// The channel is being created.
    New,
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
            LifecycleStage::New => write!(f, "New"),
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

pub trait LifeCycle {
    fn name(&self) -> String {
        self.metadata().channel_id().name()
    }

    fn role(&self) -> ChannelRole {
        self.metadata().role()
    }

    fn balance(&self) -> Balances {
        self.metadata().balances()
    }

    fn my_balance(&self) -> MoneroAmount {
        let balance = self.balance();
        match self.role() {
            ChannelRole::Customer => balance.customer,
            ChannelRole::Merchant => balance.merchant,
        }
    }

    /// Get the current lifecycle stage of the channel.
    fn stage(&self) -> LifecycleStage;

    fn metadata(&self) -> &ChannelMetadata;
}

#[macro_export]
macro_rules! lifecycle_impl {
    ($stage:ty, $stage_variant:ident) => {
        impl LifeCycle for $stage {
            fn stage(&self) -> LifecycleStage {
                LifecycleStage::$stage_variant
            }

            fn metadata(&self) -> &ChannelMetadata {
                &self.metadata
            }
        }
    };
}

#[derive(Clone, Serialize, Deserialize)]
pub enum ChannelState {
    New(NewChannelState),
    Establishing(EstablishingState),
    Open(EstablishedChannelState),
    Closing(ClosingChannelState),
    Closed(ClosedChannelState),
}

impl Debug for ChannelState {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.stage())
    }
}

impl ChannelState {
    pub fn as_lifecycle(&self) -> &dyn LifeCycle {
        match self {
            ChannelState::New(state) => state,
            ChannelState::Establishing(state) => state,
            ChannelState::Open(state) => state,
            ChannelState::Closing(state) => state,
            ChannelState::Closed(state) => state,
        }
    }

    pub fn to_new(self) -> Result<NewChannelState, (Self, LifeCycleError)> {
        match self {
            ChannelState::New(state) => Ok(state),
            _ => Err((self, LifeCycleError::invalid_state_for("Expected NewChannelState"))),
        }
    }

    pub fn to_establishing(self) -> Result<EstablishingState, (Self, LifeCycleError)> {
        match self {
            ChannelState::Establishing(state) => Ok(state),
            _ => Err((self, LifeCycleError::invalid_state_for("Expected EstablishingState"))),
        }
    }

    pub fn as_establishing(&self) -> Result<&EstablishingState, LifeCycleError> {
        match self {
            ChannelState::Establishing(ref state) => Ok(state),
            _ => Err(LifeCycleError::invalid_state_for("Expected EstablishingState")),
        }
    }

    pub fn to_open(self) -> Result<EstablishedChannelState, (Self, LifeCycleError)> {
        match self {
            ChannelState::Open(state) => Ok(state),
            _ => Err((self, LifeCycleError::invalid_state_for("Expected EstablishedChannelState"))),
        }
    }

    pub fn to_closing(self) -> Result<ClosingChannelState, (Self, LifeCycleError)> {
        match self {
            ChannelState::Closing(state) => Ok(state),
            _ => Err((self, LifeCycleError::invalid_state_for("Expected ClosingChannelState"))),
        }
    }

    pub fn to_closed(self) -> Result<ClosedChannelState, (Self, LifeCycleError)> {
        match self {
            ChannelState::Closed(state) => Ok(state),
            _ => Err((self, LifeCycleError::invalid_state_for("Expected ClosedChannelState"))),
        }
    }
}

impl LifeCycle for ChannelState {
    fn stage(&self) -> LifecycleStage {
        self.as_lifecycle().stage()
    }

    fn metadata(&self) -> &ChannelMetadata {
        self.as_lifecycle().metadata()
    }
}

#[cfg(test)]
pub mod test {
    use crate::amount::{MoneroAmount, MoneroDelta};
    use crate::crypto::keys::{Curve25519PublicKey, Curve25519Secret, PublicKey};
    use crate::crypto::zk_objects::{KesProof, PartialEncryptedKey, ShardInfo};
    use crate::monero::data_objects::{ChannelUpdate, MultisigSplitSecrets, MultisigWalletData, TransactionId};
    use crate::payment_channel::ChannelRole;
    use crate::state_machine::commitment_tx::CommitmentTransaction;
    use crate::state_machine::establishing_channel::EstablishingState;
    use crate::state_machine::lifecycle::{LifeCycle, LifecycleStage};
    use crate::state_machine::new_channel::NewChannelBuilder;
    use crate::state_machine::open_channel::EstablishedChannelState;
    use crate::state_machine::NewChannelState;
    use blake2::Blake2b512;
    use log::*;

    pub fn new_channel_state() -> NewChannelState {
        // All this info is known, or can be scanned in from a QR code etc
        const SECRET: &str = "0b98747459483650bb0d404e4ccc892164f88a5f1f131cee9e27f633cef6810d";
        let (_, my_pubkey) = Curve25519PublicKey::keypair_from_hex(SECRET).unwrap();
        let my_pubkey = my_pubkey.as_hex();
        let merchant_pubkey = "61772c23631fa02db2fbe47515dda43fc28a471ee47719930e388d2ba5275016";
        let kes_pubkey = "4dd896d542721742aff8671ba42aff0c4c846bea79065cf39a191bbeb11ea634";
        let initial_customer_amount = MoneroAmount::from_xmr("1.25").unwrap();
        let initial_merchant_amount = MoneroAmount::from_xmr("0.0").unwrap();
        let initial_state = NewChannelBuilder::new(ChannelRole::Customer, &my_pubkey, SECRET);
        let initial_state = initial_state
            .with_kes_public_key(kes_pubkey)
            .with_customer_initial_balance(initial_customer_amount)
            .with_merchant_initial_balance(initial_merchant_amount)
            .with_peer_public_key(merchant_pubkey)
            .with_my_user_label("me")
            .with_peer_label("you")
            .build::<Blake2b512>()
            .expect("Failed to build initial state");
        // Create a new channel state machine
        assert_eq!(initial_state.stage(), LifecycleStage::New);
        info!("New channel state machine created");
        initial_state
    }

    pub fn accept_proposal(ic: NewChannelState) -> EstablishingState {
        // Data gets sent to merchant. They respond with an ack and a proposal.
        // Note that the role is role they want me to play.
        let proposal = ic.for_proposal();
        let Ok(establishing) = ic.next(proposal) else {
            panic!("Failed to transition to Establishing state");
        };
        assert_eq!(establishing.stage(), LifecycleStage::Establishing);
        establishing
    }

    pub fn create_wallet() -> MultisigWalletData {
        let some_secret =
            Curve25519Secret::from_hex("8eb8a1fd0f2c42fa7508a8883addb0860a0c5e44c1c14605abb385375c533609").unwrap();
        let some_pub = Curve25519PublicKey::from_secret(&some_secret);
        MultisigWalletData {
            my_spend_key: some_secret.clone(),
            my_public_key: some_pub.clone(),
            sorted_pubkeys: [some_pub.clone(), some_pub.clone()],
            joint_public_spend_key: some_pub.clone(),
            joint_private_view_key: Curve25519Secret::random(&mut rand::rng()),
            birthday: 0,
            known_outputs: String::default(),
        }
    }

    pub fn establish_channel(mut state: EstablishingState) -> EstablishedChannelState {
        // The multisig wallet protocol is complete.
        let wallet = create_wallet();
        state.wallet_created(wallet);
        // The KES shards have been exchanged.
        let my_shards = MultisigSplitSecrets {
            kes_shard: PartialEncryptedKey("kes_shard_from_customer".into()),
            peer_shard: PartialEncryptedKey("merchant_shard".into()),
        };
        let their_shards = MultisigSplitSecrets {
            kes_shard: PartialEncryptedKey("kes_shard_from_merchant".into()),
            peer_shard: PartialEncryptedKey("customer_shard".into()),
        };
        let shards = ShardInfo { my_shards, their_shards };
        state.save_kes_shards(shards);
        // The funding transaction has been created and broadcast.
        state.funding_tx_confirmed(TransactionId::new("fundingtx1"), MoneroAmount::from_xmr("1.25").unwrap());
        // The commitment transaction has been created.
        let txc0 = CommitmentTransaction {};
        state.commitment_transaction_created(txc0);
        // The commitment transaction proofs have been exchanged
        state.save_txc0_proof(b"commitment_proof0".to_vec());
        // The KES details have been exchanged.
        let kes_proof = KesProof { proof: "kes_0001".into() };
        state.kes_created(kes_proof);
        state.save_txc0_proof(b"commitment_proof1".to_vec());
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

    pub fn payment(state: &mut EstablishedChannelState, amount: &str) -> u64 {
        let delta = MoneroDelta::from(MoneroAmount::from_xmr(amount).unwrap());
        let proofs = b"transfer_proof".to_vec(); // Placeholder for actual proof data
        let update_count = state.update_count() + 1;
        let new_balances = state.balance().apply_delta(delta).unwrap();
        let update =
            ChannelUpdate { update_count, new_balances, delta, commitment_tx: CommitmentTransaction {}, proofs };
        state.new_transfer(update).unwrap()
    }

    #[test]
    fn happy_path() {
        env_logger::try_init().ok();
        let state = new_channel_state();
        let state = accept_proposal(state);
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
        let Ok(mut state) = state.close() else {
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
