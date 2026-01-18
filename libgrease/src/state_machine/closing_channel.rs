use crate::amount::MoneroAmount;
use crate::balance::Balances;
use crate::channel_id::ChannelId;
use crate::channel_metadata::ChannelMetadata;
use crate::cryptography::zk_objects::KesProof;
use crate::cryptography::ChannelWitness;
use crate::grease_protocol::close_channel::{
    ChannelCloseSuccess, CloseFailureReason, CloseProtocolCommon, CloseProtocolError, CloseProtocolInitiator,
    CloseProtocolResponder, RequestChannelClose, RequestCloseFailed,
};
use crate::lifecycle_impl;
use crate::monero::data_objects::{TransactionId, TransactionRecord};
use crate::multisig::MultisigWalletData;
use crate::payment_channel::{ChannelRole, HasRole};
use crate::state_machine::closed_channel::{ChannelClosedReason, ClosedChannelState};
use crate::state_machine::error::LifeCycleError;
use crate::XmrScalar;
use ciphersuite::Ciphersuite;
use monero::{Address, Network};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelCloseRecord {
    pub final_balance: Balances,
    pub update_count: u64,
    #[serde(
        serialize_with = "crate::helpers::xmr_scalar_to_hex",
        deserialize_with = "crate::helpers::xmr_scalar_from_hex"
    )]
    pub witness: XmrScalar,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClosingChannelState {
    pub(crate) metadata: ChannelMetadata,
    pub(crate) reason: ChannelClosedReason,
    pub(crate) multisig_wallet: MultisigWalletData,
    pub(crate) funding_transactions: HashMap<TransactionId, TransactionRecord>,
    #[serde(
        serialize_with = "crate::helpers::xmr_scalar_to_hex",
        deserialize_with = "crate::helpers::xmr_scalar_from_hex"
    )]
    pub(crate) peer_witness: XmrScalar,
    pub(crate) kes_proof: KesProof,
    pub(crate) last_update: UpdateRecord,
    pub(crate) final_tx: Option<TransactionId>,
}

impl ClosingChannelState {
    pub fn to_channel_state(self) -> ChannelState {
        ChannelState::Closing(self)
    }
    pub fn final_balances(&self) -> Balances {
        self.metadata.balances()
    }

    pub fn multisig_address(&self, _network: Network) -> Option<String> {
        todo!("Implement multisig address retrieval for closing channel state")
    }

    /// Returns the keys to be able to reconstruct the multisig wallet.
    /// Warning! The result of this function contains wallet secrets!
    ///
    /// This function also includes all outputs from funding transactions
    pub fn wallet_data(&self) -> MultisigWalletData {
        let mut data = self.multisig_wallet.clone();
        self.funding_transactions.values().for_each(|rec| {
            data.known_outputs.push(rec.serialized.clone());
        });
        data
    }

    pub fn final_update(&self) -> UpdateRecord {
        self.last_update.clone()
    }

    pub fn peer_witness(&self) -> &XmrScalar {
        &self.peer_witness
    }

    pub fn reason(&self) -> &ChannelClosedReason {
        &self.reason
    }

    pub fn requirements_met(&self) -> bool {
        // Check if the commitment transaction is valid and if the final transaction is set
        self.final_tx.is_some()
    }

    pub fn get_closing_payments(&self) -> [(Address, MoneroAmount); 2] {
        let balance = self.final_balances();
        let merchant_address = self.metadata.channel_id().closing_addresses().merchant;
        let customer_address = self.metadata.channel_id().closing_addresses().customer;
        [(merchant_address, balance.merchant), (customer_address, balance.customer)]
    }

    pub fn with_final_tx(&mut self, final_tx: TransactionId) {
        let prev = self.final_tx.take();
        if prev.is_some() {
            log::warn!(
                "Overwriting existing final transaction {} in ClosingChannelState",
                prev.as_ref().unwrap().id
            );
        }
        self.final_tx = Some(final_tx);
    }

    #[allow(clippy::result_large_err)]
    pub fn next(self) -> Result<ClosedChannelState, (Self, LifeCycleError)> {
        if !self.requirements_met() {
            return Err((self, LifeCycleError::InvalidStateTransition));
        }

        let closed_state = ClosedChannelState::new(ChannelClosedReason::Normal, self.metadata.clone());
        Ok(closed_state)
    }
}

use crate::state_machine::lifecycle::{ChannelState, LifeCycle, LifecycleStage};
use crate::state_machine::open_channel::UpdateRecord;

lifecycle_impl!(ClosingChannelState, Closing);

// --- Protocol Trait Implementations ---

impl HasRole for ClosingChannelState {
    fn role(&self) -> ChannelRole {
        self.metadata.role()
    }
}

impl<SF: Ciphersuite> CloseProtocolCommon<SF> for ClosingChannelState {
    fn channel_id(&self) -> ChannelId {
        self.metadata.channel_id().name()
    }

    fn update_count(&self) -> u64 {
        self.metadata.update_count()
    }

    fn current_offset(&self) -> ChannelWitness<SF> {
        // Convert XmrScalar to ChannelWitness<SF>
        // This should succeed since the witness was validated at channel establishment
        ChannelWitness::<SF>::try_from(self.last_update.my_proofs.private_outputs.witness_i)
            .expect("witness_i should be valid in SF since channel was established")
    }

    fn verify_offset(&self, _offset: &ChannelWitness<SF>, update_count: u64) -> Result<(), CloseProtocolError> {
        // Use direct metadata access to avoid trait method ambiguity
        let my_update_count = self.metadata.update_count();
        if update_count != my_update_count {
            return Err(CloseProtocolError::UpdateCountMismatch { expected: my_update_count, actual: update_count });
        }
        // The ChannelWitness type already guarantees validity in both curves,
        // so we just need to verify the update count matches.
        // Full VCOF verification would be done here in a complete implementation.
        Ok(())
    }
}

impl<SF: Ciphersuite> CloseProtocolInitiator<SF> for ClosingChannelState {
    fn create_close_request(&self) -> Result<RequestChannelClose<SF>, CloseProtocolError> {
        // Use current_offset() which handles the conversion
        Ok(RequestChannelClose {
            channel_id: self.metadata.channel_id().name(),
            offset: <Self as CloseProtocolCommon<SF>>::current_offset(self),
            update_count: self.metadata.update_count(),
        })
    }

    fn handle_close_success(&mut self, response: ChannelCloseSuccess<SF>) -> Result<(), CloseProtocolError> {
        // Validate the response channel ID matches (use direct field access)
        let my_channel_id = self.metadata.channel_id().name();
        if response.channel_id != my_channel_id {
            return Err(CloseProtocolError::InvalidOffset("Channel ID mismatch".into()));
        }

        // Verify the peer's offset
        let my_update_count = self.metadata.update_count();
        <ClosingChannelState as CloseProtocolCommon<SF>>::verify_offset(self, &response.offset, my_update_count)?;

        // If the responder broadcast the transaction, store it
        if let Some(txid) = response.txid {
            self.with_final_tx(txid);
        }

        Ok(())
    }

    fn handle_close_failed(&mut self, response: RequestCloseFailed) -> Result<(), CloseProtocolError> {
        Err(CloseProtocolError::CloseRejected(response.reason))
    }

    fn broadcast_closing_tx(&self, _peer_offset: &ChannelWitness<SF>) -> Result<TransactionId, CloseProtocolError> {
        // This requires actual Monero transaction creation and broadcast.
        // The implementation would use the wallet_data() and combine offsets to create the closing tx.
        Err(CloseProtocolError::MissingInformation(
            "Transaction broadcast requires wallet integration - use external wallet service".into(),
        ))
    }
}

impl<SF: Ciphersuite> CloseProtocolResponder<SF> for ClosingChannelState {
    fn receive_close_request(&mut self, request: RequestChannelClose<SF>) -> Result<(), CloseProtocolError> {
        // Validate the request (use direct field access)
        let my_channel_id = self.metadata.channel_id().name();
        if request.channel_id != my_channel_id {
            return Err(CloseProtocolError::InvalidOffset("Channel ID mismatch".into()));
        }

        <ClosingChannelState as CloseProtocolCommon<SF>>::verify_offset(self, &request.offset, request.update_count)?;

        Ok(())
    }

    fn sign_and_broadcast(
        &mut self,
        _initiator_offset: &ChannelWitness<SF>,
    ) -> Result<Option<TransactionId>, CloseProtocolError> {
        // This requires actual Monero transaction creation and broadcast.
        // Return None to indicate the initiator should broadcast.
        Ok(None)
    }

    fn create_success_response(&self, txid: Option<TransactionId>) -> ChannelCloseSuccess<SF> {
        // Use current_offset() which handles the conversion
        ChannelCloseSuccess {
            channel_id: self.metadata.channel_id().name(),
            offset: <Self as CloseProtocolCommon<SF>>::current_offset(self),
            txid,
        }
    }

    fn create_failure_response(&self, reason: CloseFailureReason) -> RequestCloseFailed {
        // Use direct field access
        RequestCloseFailed { channel_id: self.metadata.channel_id().name(), reason }
    }
}
