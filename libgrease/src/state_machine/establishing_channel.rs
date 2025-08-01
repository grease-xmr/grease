use crate::amount::MoneroAmount;
use crate::channel_metadata::ChannelMetadata;
use crate::crypto::zk_objects::Comm0PublicInputs;
use crate::crypto::zk_objects::{KesProof, PeerProof0, Proofs0, PublicProof0, ShardInfo};
use crate::lifecycle_impl;
use crate::monero::data_objects::{MultisigWalletData, TransactionId, TransactionRecord};
use crate::state_machine::error::LifeCycleError;
use crate::state_machine::lifecycle::ChannelState;
use crate::state_machine::new_channel::NewChannelState;
use crate::state_machine::open_channel::EstablishedChannelState;
use log::*;
use monero::Network;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

//------------------------------------   Establishing Channel State  ------------------------------------------------//

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EstablishingState {
    pub(crate) metadata: ChannelMetadata,
    pub(crate) multisig_wallet: Option<MultisigWalletData>,
    pub(crate) shards: Option<ShardInfo>,
    pub(crate) my_proof0: Option<Proofs0>,
    pub(crate) peer_proof0: Option<PeerProof0>,
    pub(crate) funding_transaction_ids: HashMap<TransactionId, TransactionRecord>,
    pub(crate) kes_proof: Option<KesProof>,
    /// Data used to watch for the funding transaction. Implementation agnostic.
    #[serde(
        serialize_with = "crate::helpers::option_to_hex",
        deserialize_with = "crate::helpers::option_from_hex",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub(crate) funding_tx_pipe: Option<Vec<u8>>,
}

impl EstablishingState {
    pub fn to_channel_state(self) -> ChannelState {
        ChannelState::Establishing(self)
    }
    pub fn requirements_met(&self) -> bool {
        let mut missing = Vec::with_capacity(6);
        if self.multisig_wallet.is_none() {
            missing.push("Multisig wallet")
        }
        if self.kes_proof.is_none() {
            missing.push("KES established")
        }
        if self.my_proof0.is_none() {
            missing.push("Witness0 generated")
        }
        if self.peer_proof0.is_none() {
            missing.push("Witness0 proof from peer")
        }
        if self.shards.is_none() {
            missing.push("Multisig shards shared");
        }
        if !self.is_fully_funded() {
            missing.push("Funding transaction fully funded");
        }
        if !missing.is_empty() {
            let msg = missing.join(", ");
            debug!("EstablishingState requirements not met: {msg}");
            false
        } else {
            debug!("EstablishingState requirements met");
            true
        }
    }

    pub fn multisig_address(&self, network: Network) -> Option<String> {
        self.multisig_wallet.as_ref().map(|w| w.address(network).to_string())
    }

    fn is_fully_funded(&self) -> bool {
        let required = self.metadata.balances().total();
        let result = self.funding_total() >= required;
        trace!(
            "is_fully_funded-- total {}, required {required}: {result}",
            self.funding_total()
        );
        result
    }

    pub fn funding_total(&self) -> MoneroAmount {
        self.funding_transaction_ids.values().map(|r| r.amount).sum()
    }

    pub fn wallet(&self) -> Option<&MultisigWalletData> {
        self.multisig_wallet.as_ref()
    }

    pub fn wallet_created(&mut self, wallet: MultisigWalletData) {
        debug!("Multisig wallet has been created.");
        let old = self.multisig_wallet.replace(wallet);
        if old.is_some() {
            warn!("Wallet state was already set and has been replaced.");
        }
    }

    pub fn save_kes_shards(&mut self, shards: ShardInfo) {
        debug!("Saving Multisig shards for KES");
        let old = self.shards.replace(shards);
        if old.is_some() {
            warn!("Multisig shards were already set and have been replaced.");
        }
    }

    /// Can be used to save (e.g. a unix pipe or filename) that will be used to watch for the funding transaction.
    /// Once the funding tx is broadcast, call `funding_tx_confirmed` to update the state.
    pub fn save_funding_tx_pipe(&mut self, funding_tx_pipe: Vec<u8>) {
        debug!("Saving funding transaction pipe data");
        let old = self.funding_tx_pipe.replace(funding_tx_pipe);
        if old.is_some() {
            warn!("Funding transaction pipe data was already set and has been replaced.");
        }
    }

    pub fn save_proof0(&mut self, proof: Proofs0) {
        debug!("Saving initial witness0 proof");
        let old = self.my_proof0.replace(proof);
        if old.is_some() {
            warn!("Initial witness0 proof was already set and has been replaced.");
        }
    }

    pub fn save_peer_proof0(&mut self, proof: PublicProof0, public_input: Comm0PublicInputs) {
        debug!("Saving peer's initial witness proof");
        let old = self.peer_proof0.replace(PeerProof0::new(proof, public_input));
        if old.is_some() {
            warn!("Peer's initial witness proof was already set and has been replaced.");
        }
    }

    pub fn kes_created(&mut self, kes_info: KesProof) {
        let old = self.kes_proof.replace(kes_info);
        if old.is_some() {
            warn!("KES proof was already set and has been replaced.");
        }
    }

    pub fn funding_tx_confirmed(&mut self, transaction: TransactionRecord) {
        debug!("Funding transaction broadcasted");
        self.funding_transaction_ids.insert(transaction.transaction_id.clone(), transaction);
    }

    #[allow(clippy::result_large_err)]
    pub fn next(self) -> Result<EstablishedChannelState, (Self, LifeCycleError)> {
        debug!("Trying to move from Establishing to Established state");
        if !self.requirements_met() {
            debug!("Cannot change from Establishing to Established because all requirements are not met");
            return Err((self, LifeCycleError::InvalidStateTransition));
        }
        debug!("Transitioning to Established wallet state");
        let open_channel = EstablishedChannelState {
            metadata: self.metadata,
            shards: self.shards.unwrap(),
            multisig_wallet: self.multisig_wallet.unwrap(),
            funding_transactions: self.funding_transaction_ids,
            my_proof0: self.my_proof0.unwrap(),
            peer_proof0: self.peer_proof0.unwrap(),
            kes_proof: self.kes_proof.unwrap(),
            current_update: None,
        };
        Ok(open_channel)
    }
}

impl From<NewChannelState> for EstablishingState {
    fn from(new_channel_state: NewChannelState) -> Self {
        EstablishingState {
            metadata: new_channel_state.metadata,
            multisig_wallet: None,
            shards: None,
            my_proof0: None,
            peer_proof0: None,
            funding_transaction_ids: HashMap::new(),
            kes_proof: None,
            funding_tx_pipe: None,
        }
    }
}

use crate::state_machine::lifecycle::{LifeCycle, LifecycleStage};
lifecycle_impl!(EstablishingState, Establishing);
