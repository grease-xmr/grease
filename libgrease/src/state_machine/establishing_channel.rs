use crate::amount::MoneroAmount;
use crate::channel_metadata::ChannelMetadata;
use crate::crypto::zk_objects::{KesProof, ShardInfo};
use crate::lifecycle_impl;
use crate::monero::data_objects::{MultisigWalletData, TransactionId};
use crate::state_machine::commitment_tx::CommitmentTransaction;
use crate::state_machine::error::LifeCycleError;
use crate::state_machine::lifecycle::ChannelState;
use crate::state_machine::new_channel::NewChannelState;
use crate::state_machine::open_channel::EstablishedChannelState;
use log::*;
use monero::Network;
use serde::{Deserialize, Serialize};
//------------------------------------   Establishing Channel State  ------------------------------------------------//

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EstablishingState {
    pub(crate) metadata: ChannelMetadata,
    pub(crate) multisig_wallet: Option<MultisigWalletData>,
    pub(crate) commitment_transaction0: Option<CommitmentTransaction>,
    pub(crate) shards: Option<ShardInfo>,
    #[serde(
        serialize_with = "crate::helpers::option_to_hex",
        deserialize_with = "crate::helpers::option_from_hex",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub(crate) commitment_tx_proof: Option<Vec<u8>>,
    pub(crate) funding_transaction_ids: Vec<TransactionId>,
    pub(crate) funding_total: MoneroAmount,
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
        self.multisig_wallet.is_some()
            && self.commitment_transaction0.is_some()
            && self.is_fully_funded()
            && self.kes_proof.is_some()
            && self.commitment_tx_proof.is_some()
            && self.shards.is_some()
    }

    pub fn multisig_address(&self, network: Network) -> Option<String> {
        self.multisig_wallet.as_ref().map(|w| w.address(network).to_string())
    }

    fn is_fully_funded(&self) -> bool {
        let required = self.metadata.balances().total();
        let result = self.funding_total >= required;
        trace!("is_fully_funded-- total {}, required {required}: {result}", self.funding_total);
        result
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

    pub fn commitment_transaction_created(&mut self, commitment_transaction: CommitmentTransaction) {
        debug!("Initial commitment transaction has been created.");
        let old = self.commitment_transaction0.replace(commitment_transaction);
        if old.is_some() {
            warn!("Commitment transaction was already set and has been replaced.");
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

    pub fn save_txc0_proof(&mut self, proof: Vec<u8>) {
        debug!("Saving commitment transaction proof");
        let old = self.commitment_tx_proof.replace(proof);
        if old.is_some() {
            warn!("Commitment transaction proof was already set and has been replaced.");
        }
    }

    pub fn kes_created(&mut self, kes_info: KesProof) {
        let old = self.kes_proof.replace(kes_info);
        if old.is_some() {
            warn!("KES proof was already set and has been replaced.");
        }
    }

    pub fn funding_tx_confirmed(&mut self, funding_tx_id: TransactionId, amount: MoneroAmount) {
        debug!("Funding transaction broadcasted");
        self.funding_transaction_ids.push(funding_tx_id);
        self.funding_total += amount;
    }

    #[allow(clippy::result_large_err)]
    pub fn next(self) -> Result<EstablishedChannelState, (Self, LifeCycleError)> {
        debug!("Trying to move from Establishing to Established state");
        if !self.requirements_met() {
            debug!("Cannot change from Establishing to Established because all requirements are not met");
            return Err((self, LifeCycleError::InvalidStateTransition));
        }
        let txc0 = self.commitment_transaction0.unwrap();
        let txc0_proof = self.commitment_tx_proof.unwrap();
        debug!("Transitioning to Established wallet state");
        let open_channel = EstablishedChannelState {
            metadata: self.metadata,
            shards: self.shards.unwrap(),
            multisig_wallet: self.multisig_wallet.unwrap(),
            funding_transactions: self.funding_transaction_ids,
            commitment_transaction0: txc0.clone(),
            commitment_tx_proof: txc0_proof.clone(),
            kes_proof: self.kes_proof.unwrap(),
            current_commitment_tx: txc0,
            current_commitment_tx_proof: txc0_proof,
            update_count: 0,
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
            commitment_transaction0: None,
            commitment_tx_proof: None,
            funding_transaction_ids: Vec::new(),
            funding_total: MoneroAmount::default(),
            kes_proof: None,
            funding_tx_pipe: None,
        }
    }
}

use crate::state_machine::lifecycle::{LifeCycle, LifecycleStage};
lifecycle_impl!(EstablishingState, Establishing);
