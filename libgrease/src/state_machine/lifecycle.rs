use crate::amount::MoneroAmount;
use crate::balance::Balances;
use crate::channel_metadata::ChannelMetadata;
use crate::payment_channel::ChannelRole;
use crate::state_machine::error::LifeCycleError;
use crate::state_machine::{
    ClosedChannelState, ClosingChannelState, EstablishedChannelState, EstablishingState, NewChannelState,
};
use monero::Network;
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

    fn wallet_address(&self, network: Network) -> Option<String>;
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

            fn wallet_address(&self, network: Network) -> Option<String> {
                self.multisig_address(network)
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

    #[allow(clippy::result_large_err)]
    pub fn to_new(self) -> Result<NewChannelState, (Self, LifeCycleError)> {
        match self {
            ChannelState::New(state) => Ok(state),
            _ => Err((self, LifeCycleError::invalid_state_for("Expected NewChannelState"))),
        }
    }

    #[allow(clippy::result_large_err)]
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

    pub fn as_open(&self) -> Result<&EstablishedChannelState, LifeCycleError> {
        match self {
            ChannelState::Open(ref state) => Ok(state),
            _ => Err(LifeCycleError::invalid_state_for("Expected EstablishedState")),
        }
    }

    pub fn as_closing(&self) -> Result<&ClosingChannelState, LifeCycleError> {
        match self {
            ChannelState::Closing(ref state) => Ok(state),
            _ => Err(LifeCycleError::invalid_state_for("Expected ClosingState")),
        }
    }

    #[allow(clippy::result_large_err)]
    pub fn to_open(self) -> Result<EstablishedChannelState, (Self, LifeCycleError)> {
        match self {
            ChannelState::Open(state) => Ok(state),
            _ => Err((self, LifeCycleError::invalid_state_for("Expected EstablishedChannelState"))),
        }
    }

    #[allow(clippy::result_large_err)]
    pub fn to_closing(self) -> Result<ClosingChannelState, (Self, LifeCycleError)> {
        match self {
            ChannelState::Closing(state) => Ok(state),
            _ => Err((self, LifeCycleError::invalid_state_for("Expected ClosingChannelState"))),
        }
    }

    #[allow(clippy::result_large_err)]
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

    fn wallet_address(&self, network: Network) -> Option<String> {
        self.as_lifecycle().wallet_address(network)
    }
}

#[cfg(test)]
pub mod test {
    use crate::amount::{MoneroAmount, MoneroDelta};
    use crate::crypto::keys::{Curve25519PublicKey, Curve25519Secret, PublicKey};
    use crate::crypto::zk_objects::random_251_bits;
    use crate::crypto::zk_objects::{
        AdaptedSignature, KesProof, PartialEncryptedKey, PrivateUpdateOutputs, Proofs0, PublicUpdateOutputs, ShardInfo,
        UpdateProofs,
    };
    use crate::monero::data_objects::{
        ClosingAddresses, MultisigSplitSecrets, MultisigWalletData, TransactionId, TransactionRecord,
    };
    use crate::payment_channel::ChannelRole;
    use crate::state_machine::establishing_channel::EstablishingState;
    use crate::state_machine::lifecycle::{LifeCycle, LifecycleStage};
    use crate::state_machine::new_channel::NewChannelBuilder;
    use crate::state_machine::open_channel::{EstablishedChannelState, UpdateRecord};
    use crate::state_machine::{ChannelCloseRecord, NewChannelState};
    use blake2::Blake2b512;
    use circuits::*;
    use log::*;
    use num_bigint::BigUint;
    use rand::{CryptoRng, RngCore};

    const ALICE_ADDRESS: &str =
        "43i4pVer2tNFELvfFEEXxmbxpwEAAFkmgN2wdBiaRNcvYcgrzJzVyJmHtnh2PWR42JPeDVjE8SnyK3kPBEjSixMsRz8TncK";
    const BOB_ADDRESS: &str =
        "4BH2vFAir1iQCwi2RxgQmsL1qXmnTR9athNhpK31DoMwJgkpFUp2NykFCo4dXJnMhU7w9UZx7uC6qbNGuePkRLYcFo4N7p3";

    pub fn new_channel_state<R: CryptoRng + RngCore>(rng: &mut R) -> NewChannelState {
        // All this info is known, or can be scanned in from a QR code etc
        let (private_key_self, public_key_self) = make_keypair_bjj(rng);
        let (_, public_key_peer) = make_keypair_bjj(rng);
        let (_, public_key_kes) = make_keypair_bjj(rng);
        let nonce_self = BigUint::from_bytes_be(&random_251_bits(rng));
        let nonce_peer = BigUint::from_bytes_be(&random_251_bits(rng));

        let initial_customer_amount = MoneroAmount::from_xmr("1.25").unwrap();
        let initial_merchant_amount = MoneroAmount::from_xmr("0.0").unwrap();
        let initial_state = NewChannelBuilder::new(ChannelRole::Customer);
        let closing = ClosingAddresses::new(ALICE_ADDRESS, BOB_ADDRESS).expect("should be valid closing addresses");
        let initial_state = initial_state
            .with_kes_public_key(public_key_kes)
            .with_customer_initial_balance(initial_customer_amount)
            .with_merchant_initial_balance(initial_merchant_amount)
            .with_my_user_label("me")
            .with_peer_label("you")
            .with_merchant_closing_address(closing.merchant)
            .with_customer_closing_address(closing.customer)
            .with_public_key_self(public_key_self.into())
            .with_private_key_self(private_key_self.into())
            .with_nonce_self(nonce_self.into())
            .with_public_key_peer(public_key_peer.into())
            .with_nonce_peer(nonce_peer.into())
            .build::<Blake2b512, R>(rng)
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
            known_outputs: Default::default(),
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
        let tx = TransactionRecord {
            channel_name: "channel".to_string(),
            transaction_id: TransactionId::new("fundingtx1"),
            amount: MoneroAmount::from_xmr("1.25").unwrap(),
            serialized: b"serialized_funding_tx".to_vec(),
        };
        state.funding_tx_confirmed(tx);
        let proof0 = Proofs0 {
            public_input: Default::default(),
            public_outputs: Default::default(),
            private_outputs: Default::default(),
            proofs: b"my_proof0".to_vec(),
        };
        let peer_proof0 = proof0.public_only();
        let public_input = proof0.public_input.clone();
        state.save_proof0(proof0);
        // Received peer's proof0 data
        state.save_peer_proof0(peer_proof0, public_input);
        // The KES details have been exchanged.
        let kes_proof = KesProof { proof: "kes_0001".into() };
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

    pub fn payment(state: &mut EstablishedChannelState, amount: &str) -> u64 {
        let delta = MoneroDelta::from(MoneroAmount::from_xmr(amount).unwrap());
        let update_count = state.update_count() + 1;
        let my_proofs = UpdateProofs {
            public_outputs: PublicUpdateOutputs::default(),
            private_outputs: PrivateUpdateOutputs {
                update_count,
                witness_i: Default::default(),
                delta_bjj: Default::default(),
                delta_ed: Default::default(),
            },
            proof: b"my_update_proof".to_vec(),
        };
        let mut rng = &mut rand::rng();
        let (offset_self, statement_self) = circuits::make_keypair_ed25519_bjj_order(&mut rng);
        let offset_self = Curve25519Secret::from_generic_scalar(&offset_self.into()).unwrap();
        let (offset_peer, statement_peer) = circuits::make_keypair_ed25519_bjj_order(&mut rng);
        let offset_peer = Curve25519Secret::from_generic_scalar(&offset_peer.into()).unwrap();

        let update_info = UpdateRecord {
            my_signature: b"signature".to_vec(),
            my_adapted_signature: AdaptedSignature::new(&offset_self, &statement_self.into()),
            peer_adapted_signature: AdaptedSignature::new(&offset_peer, &statement_peer.into()),
            my_preprocess: vec![],
            peer_preprocess: vec![],
            my_proofs,
            peer_proofs: Default::default(),
        };
        let updated_index = state.store_update(delta, update_info);
        assert_eq!(updated_index, update_count);
        update_count
    }

    #[test]
    fn happy_path() {
        env_logger::try_init().ok();
        let state = new_channel_state(&mut rand::rng());
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
        let close = ChannelCloseRecord {
            final_balance: state.balance(),
            update_count: state.update_count(),
            witness: Default::default(),
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
