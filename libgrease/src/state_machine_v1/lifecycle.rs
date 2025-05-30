use crate::amount::MoneroAmount;
use crate::balance::Balances;
use crate::channel_id::ChannelId;
use crate::channel_metadata::ChannelMetadata;
use crate::crypto::traits::PublicKey;
use crate::kes::{FundingTransaction, KesInitializationRecord, KesInitializationResult};
use crate::monero::data_objects::{ChannelSecrets, ChannelUpdate};
use crate::monero::{MultiSigWallet, WalletState};
use crate::payment_channel::ChannelRole;
use crate::state_machine::closed_channel::ClosedChannelState;
use crate::state_machine::closing_channel::{ClosingChannelState, StartCloseInfo, SuccessfulCloseInfo};
use crate::state_machine::disputing_channel::{DisputeResolvedInfo, DisputingChannelState, ForceCloseInfo};
use crate::state_machine::error::LifeCycleError;
use crate::state_machine::establishing_channel::EstablishingState;
use crate::state_machine::new_channel::{NewChannelState, ProposedChannelInfo, RejectNewChannelReason, TimeoutReason};
use crate::state_machine::open_channel::EstablishedChannelState;
use crate::state_machine::{ChannelClosedReason, ChannelInitSecrets};
use log::*;
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use crate::state_machine::kes_verified::KesVerifiedState;
use crate::state_machine::wallet_created::WalletCreatedState;


#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(deserialize = "P: PublicKey + for<'d> Deserialize<'d>, W: MultiSigWallet + for<'d> Deserialize<'d>"))]
pub enum ChannelLifeCycle<P, W>
where
    P: PublicKey,
    W: MultiSigWallet,
{
    New(Box<NewChannelState<P>>),
    /// The channel is in the process of being created.
    Establishing(Box<EstablishingState<P, W>>),
    WalletCreated(Box<WalletCreatedState<P, W>>),
    KesVerified(Box<KesVerifiedState<P, W>>),
    /// The channel is open and ready to use.
    Open(Box<EstablishedChannelState<P, W>>),
    /// The channel is closed and cannot be used anymore.
    Closing(Box<ClosingChannelState<P, W>>),
    Closed(Box<ClosedChannelState<P, W>>),
    Disputing(Box<DisputingChannelState<P, W>>),
}

impl<P, W> ChannelLifeCycle<P, W>
where
    P: PublicKey,
    W: MultiSigWallet,
{

    async fn new_to_establishing(self, proposal: ProposedChannelInfo<P>) -> Result<Self, (Self, LifeCycleError)> {
        let Self::New(new_state) = self else {
            return Err((self, LifeCycleError::InvalidStateTransition));
        };
        match new_state.review_proposal(&proposal) {
            Err(err) => Err((Self::New(new_state), err.into())),
            Ok(()) => {
                let wallet = W::new(&new_state.channel_info.channel_id).map_err(|e| {
                    let old_state = ChannelLifeCycle::New(new_state.clone());
                    (old_state, e.into())
                })?;
                let establishing_state = EstablishingState::new(new_state.channel_info, wallet);
                debug!("Transitioning from New to Establishing state");
                Ok(ChannelLifeCycle::Establishing(Box::new(establishing_state)))
            }
        }
    }

    fn reject_new_channel(self, reason: RejectNewChannelReason) -> Result<Self, (Self, LifeCycleError)> {
        let Self::New(new_state) = self else {
            return Err((self, LifeCycleError::InvalidStateTransition));
        };
        warn!("Channel proposal rejected: {}", reason.reason());
        let reason = ChannelClosedReason::Rejected(reason);
        let channel_id = new_state.channel_info.channel_id.clone();
        let channel_role = new_state.channel_info.role;
        let state = ClosedChannelState::empty(reason, channel_id, channel_role);
        Ok(ChannelLifeCycle::Closed(Box::new(state)))
    }

    /// Manage the transition from the Establishing state to the Open state. This is an elaborate process that involves
    /// multiple steps, and therefore makes use of a subordinate state machine.
    fn establishing_to_wallet_created(self) -> Result<Self, (Self, LifeCycleError)> {
        let Self::Establishing(establishing_state) = self else {
            return Err((self, LifeCycleError::InvalidStateTransition));
        };
        let state = *establishing_state;
        if !matches!(&state.wallet_state, Some(WalletState::Ready(_))) {
            warn!("Wallet not ready, cannot transition to WalletCreated");
            return Err((Self::Establishing(Box::new(state)), LifeCycleError::InvalidStateTransition));
        }
        let (wallet_secret, peer_shards, my_shards, wallet) =
            if let Some(WalletState::Ready(ready_state)) = state.wallet_state {
                let wallet_secret = ready_state.keypair;
                let peer_shards = ready_state.peer_shards;
                let my_shards = ready_state.my_shards;
                let wallet = ready_state.wallet;
                (wallet_secret, peer_shards, my_shards, wallet)
            } else {
                panic!("Wallet not ready, but we've just checked it");
            };
        let channel_info = state.channel_info;
        let wallet_created =
            WalletCreatedState { channel_info, wallet, wallet_secret, peer_shards, my_shards, kes_verify_info: None };
        let new_state = ChannelLifeCycle::WalletCreated(Box::new(wallet_created));
        debug!("Transitioning from Establishing to WalletCreated state");
        Ok(new_state)
    }

    fn wallet_created_to_kes_verified(
        self,
        kes_verify_info: KesInitializationResult,
    ) -> Result<Self, (Self, LifeCycleError)> {
        let Self::WalletCreated(wallet_created_state) = self else {
            warn!("Cannot save KES information before Wallet has been created");
            return Err((self, LifeCycleError::InvalidStateTransition));
        };
        let kes_info = wallet_created_state.kes_init_info();
        let kes_verified = KesVerifiedState {
            channel_info: wallet_created_state.channel_info,
            wallet_secret: wallet_created_state.wallet_secret,
            peer_shards: wallet_created_state.peer_shards.peer_shard,
            my_shards: wallet_created_state.my_shards.kes_shard,
            kes_info,
            kes_verify_info,
            wallet: wallet_created_state.wallet,
            merchant_funding_tx: None,
            customer_funding_tx: None,
            initial_witness: None,
        };
        let new_state = ChannelLifeCycle::KesVerified(Box::new(kes_verified));
        debug!("Transitioning from WalletCreated to KesVerified state");
        Ok(new_state)
    }

    fn kes_verified_to_open(self, tx: FundingTransaction) -> Result<Self, (Self, LifeCycleError)> {
        let Self::KesVerified(mut state) = self else {
            return Err((self, LifeCycleError::InvalidStateTransition));
        };

        state.save_funding_transaction(tx);
        if state.are_funding_txs_confirmed() {
            trace!("Funding transactions confirmed. Transitioning to EstablishedChannelState");
            let state = *state;

            let initial_witness =
                state.initial_witness.expect("Initial witness must be set before opening the channel");
            let open_state = EstablishedChannelState {
                channel_info: state.channel_info,
                latest: initial_witness.clone(),
                latest_proof: None,
                initial: initial_witness,
                wallet: state.wallet,
                customer_funding_tx: state.customer_funding_tx.map(|tx| tx.transaction_id),
                merchant_funding_tx: state.merchant_funding_tx.map(|tx| tx.transaction_id),
            };
            let name = open_state.channel_info.channel_id.name();
            let bal = open_state.channel_info.initial_balances();
            info!(
                "Channel {name} is now open and ready to transact payments. \
            Initial balances: Customer: {}, Merchant: {},  Total: {} ",
                bal.customer,
                bal.merchant,
                bal.total()
            );
            let new_state = ChannelLifeCycle::Open(Box::new(open_state));
            debug!("Transitioning from KesVerified to Open state");
            Ok(new_state)
        } else {
            debug!("Funding transactions not confirmed yet");
            Ok(Self::KesVerified(state))
        }
    }

    fn update_channel(self, info: ChannelUpdate) -> Result<Self, (Self, LifeCycleError)> {
        let Self::Open(current_state) = self else {
            return Err((self, LifeCycleError::InvalidStateTransition));
        };
        todo!("Update channel logic here");
    }

    fn open_to_closing(self, _info: StartCloseInfo) -> Result<Self, (Self, LifeCycleError)> {
        let Self::Open(open_state) = self else {
            return Err((self, LifeCycleError::InvalidStateTransition));
        };
        // Carry out the co-operative close channel protocol
        let closing_state = ClosingChannelState::from_open(*open_state);
        let new_state = ChannelLifeCycle::Closing(Box::new(closing_state));
        debug!("Transitioning from Open to Closing state");
        Ok(new_state)
    }

    fn closing_to_closed(self, _info: SuccessfulCloseInfo) -> Result<Self, (Self, LifeCycleError)> {
        let Self::Closing(closing_state) = self else {
            return Err((self, LifeCycleError::InvalidStateTransition));
        };
        //let reason = ChannelClosedReason::Normal;
        //let wallet = closing_state.wallet;
        //let closed_state = ClosedChannelState::new(reason, channel, wallet);
        // debug!("Transitioning from Closing to Closed state");
        todo!("Copy state to finalized");
        // Ok(ChannelLifeCycle::Closed(Box::new(closed_state)))
    }

    fn open_to_dispute(self, info: ForceCloseInfo) -> Result<Self, (Self, LifeCycleError)> {
        let Self::Open(open_state) = self else {
            return Err((self, LifeCycleError::InvalidStateTransition));
        };
        warn!(
            "Channel {} is force closing. Origin: {}. Reason: {}",
            open_state.channel_info.channel_id().name(),
            info.origin,
            info.reason
        );
        let dispute_state = DisputingChannelState::from_open(*open_state, info);
        debug!("Transitioning from Open to Disputing state");
        Ok(ChannelLifeCycle::Disputing(Box::new(dispute_state)))
    }

    fn closing_to_dispute(self, info: ForceCloseInfo) -> Result<Self, (Self, LifeCycleError)> {
        let Self::Closing(closing_state) = self else {
            return Err((self, LifeCycleError::InvalidStateTransition));
        };
        warn!(
            "Channel {} is force closing. Origin: {}. Reason: {}",
            closing_state.channel_info.channel_id.name(),
            info.origin,
            info.reason
        );
        let dispute_state = DisputingChannelState::from_closing(*closing_state, info);
        debug!("Transitioning from Closing to Disputing state");
        Ok(ChannelLifeCycle::Disputing(Box::new(dispute_state)))
    }

    fn timeout(self, reason: TimeoutReason) -> Result<Self, (Self, LifeCycleError)> {
        warn!(
            "Channel in stage ´{}´ timed out and is now closed. Reason: {}",
            reason.stage(),
            reason.reason()
        );
        let timeout = ChannelClosedReason::Timeout(reason);
        let channel_id = self.channel_id().clone();
        let channel_role = self.role();
        let state = ClosedChannelState::empty(timeout, channel_id, channel_role);
        debug!("Transitioning to Closed state");
        Ok(ChannelLifeCycle::Closed(Box::new(state)))
    }

    fn disputing_to_closed(self, info: DisputeResolvedInfo<P>) -> Result<Self, (Self, LifeCycleError)> {
        let Self::Disputing(disputing_state) = self else {
            return Err((self, LifeCycleError::InvalidStateTransition));
        };
        //let reason = ChannelClosedReason::Dispute(info.result);
        //let wallet = disputing_state.wallet;
        //let state = ClosedChannelState::new(reason, closed_channel, wallet);
        debug!("Transitioning from Disputing to Closed state");
        todo!("Disputing to closed state");
    }

    // Converts Result<Self, Self+> to Self, logging the error in the process
    pub fn log_and_consolidate(prev_stage: LifecycleStage, result: Result<Self, (Self, LifeCycleError)>) -> Self {
        match result {
            Ok(new_state) => {
                debug!("State transition from {prev_stage} to {} was successful", new_state.stage());
                new_state
            }
            Err((state, err)) => {
                warn!("State transition from {prev_stage} error: {err}");
                state
            }
        }
    }

    pub async fn handle_event(self, event: LifeCycleEvent<P>) -> Result<Self, (Self, LifeCycleError)> {
        use LifeCycleEvent::*;
        use LifecycleStage::*;
        match (self.stage(), event) {
            (New, OnAckNewChannel(prop)) => self.new_to_establishing(*prop).await,
            (New, OnRejectNewChannel(reason)) => self.reject_new_channel(*reason),
            (New | Establishing | WalletCreated | KesVerified, OnTimeout(reason)) => self.timeout(*reason),
            (Establishing, OnMultiSigWalletCreated) => self.establishing_to_wallet_created(),
            (WalletCreated, OnKesVerified(kes)) => self.wallet_created_to_kes_verified(*kes),
            (KesVerified, OnFundingTxConfirmed(tx)) => self.kes_verified_to_open(*tx),
            (Open, OnUpdateChannel(info)) => self.update_channel(*info),
            (Open, OnStartClose(info)) => self.open_to_closing(*info),
            (Open, OnForceClose(info)) => self.open_to_dispute(*info),
            (Closing, OnSuccessfulClose(info)) => self.closing_to_closed(*info),
            (Closing, OnForceClose(info)) => self.closing_to_dispute(*info),
            (Disputing, OnDisputeResolved(info)) => self.disputing_to_closed(*info),
            (_, ev) => {
                error!("Unhandled event / state combination: {ev} in {}", self.stage());
                Err((self, LifeCycleError::InvalidStateTransition))
            }
        }
    }

    /// If the channel is closed, this will return the reason for the closure
    pub fn closed_reason(&self) -> Option<&ChannelClosedReason<P>> {
        match self {
            ChannelLifeCycle::Closed(closed_state) => Some(closed_state.reason()),
            _ => None,
        }
    }

    /// Returns a reference to the 2-of-2 Monero multisig wallet, if available.
    pub fn wallet(&self) -> Option<&W> {
        match self {
            ChannelLifeCycle::Open(open_state) => Some(&open_state.wallet),
            ChannelLifeCycle::Closing(closing_state) => Some(&closing_state.wallet),
            ChannelLifeCycle::Closed(closed_state) => closed_state.wallet(),
            _ => None,
        }
    }

    pub fn vss_info(&self) -> Option<ChannelInitSecrets<P>> {
        trace!("VSS info retrieval");
        let (channel_name, peer_public_key, kes_public_key) = self.channel_info().map(|info| {
            let peer_pubkey = match info.role() {
                ChannelRole::Customer => info.merchant_pubkey.clone(),
                ChannelRole::Merchant => info.customer_pubkey.clone(),
            };
            (info.channel_id.name(), peer_pubkey, info.kes_public_key.clone())
        })?;
        trace!("VSS info retrieval: Channel info covered.");
        let wallet_secret = *match self {
            ChannelLifeCycle::Establishing(state) => state.wallet_state.as_ref().and_then(|w| w.keypair()),
            ChannelLifeCycle::WalletCreated(state) => Some(&state.wallet_secret),
            _ => {
                warn!("Trying to read VSS info and in particular, the wallet keypair from an incompatible state.");
                None
            }
        }?;
        Some(ChannelInitSecrets::new(
            channel_name,
            wallet_secret,
            peer_public_key,
            kes_public_key,
        ))
    }

    pub fn kes_init_info(&self) -> Option<KesInitializationRecord<P>> {
        match self {
            ChannelLifeCycle::WalletCreated(state) => Some(state.kes_init_info()),
            ChannelLifeCycle::KesVerified(state) => Some(state.kes_info()),
            _ => None,
        }
    }

    pub fn kes_result_info(&self) -> Option<KesInitializationResult> {
        match self {
            ChannelLifeCycle::New(_) => None,
            ChannelLifeCycle::Establishing(_) => None,
            ChannelLifeCycle::WalletCreated(state) => state.kes_verify_info().cloned(),
            ChannelLifeCycle::KesVerified(state) => Some(state.kes_verify_info()),
            ChannelLifeCycle::Open(_) => {
                todo!()
            }
            ChannelLifeCycle::Closing(_) => {
                todo!()
            }
            ChannelLifeCycle::Closed(_) => {
                todo!()
            }
            ChannelLifeCycle::Disputing(_) => {
                todo!()
            }
        }
    }

    pub fn last_update(&self) -> Option<ChannelUpdate> {
        match self {
            ChannelLifeCycle::New(_)
            | ChannelLifeCycle::Establishing(_)
            | ChannelLifeCycle::WalletCreated(_)
            | ChannelLifeCycle::KesVerified(_) => None,
            ChannelLifeCycle::Open(state) => state.latest_proof.clone(),
            ChannelLifeCycle::Closing(_state) => todo!(),
            ChannelLifeCycle::Closed(_state) => todo!(),
            ChannelLifeCycle::Disputing(_state) => todo!(),
        }
    }

    pub fn latest_secrets(&self) -> Option<ChannelSecrets> {
        match self {
            ChannelLifeCycle::New(_)
            | ChannelLifeCycle::Establishing(_)
            | ChannelLifeCycle::WalletCreated(_)
            | ChannelLifeCycle::KesVerified(_) => None,
            ChannelLifeCycle::Open(state) => Some(state.latest.clone()),
            ChannelLifeCycle::Closing(_state) => todo!(),
            ChannelLifeCycle::Closed(_state) => todo!(),
            ChannelLifeCycle::Disputing(_state) => todo!(),
        }
    }

    pub fn transaction_count(&self) -> u64 {
        match self {
            ChannelLifeCycle::New(_)
            | ChannelLifeCycle::Establishing(_)
            | ChannelLifeCycle::WalletCreated(_)
            | ChannelLifeCycle::KesVerified(_) => 0,
            ChannelLifeCycle::Open(state) => state.latest.update_count,
            ChannelLifeCycle::Closing(state) => todo!("Handle transaction count in Closing state"),
            ChannelLifeCycle::Closed(state) => todo!("Handle transaction count in Closed state"),
            ChannelLifeCycle::Disputing(state) => todo!("Handle transaction count in Disputing state"),
        }
    }

    pub fn my_balance(&self) -> MoneroAmount {
        let balances = self.balances();
        match self.role() {
            ChannelRole::Customer => balances.customer,
            ChannelRole::Merchant => balances.merchant,
        }
    }
}

#[cfg(test)]
pub mod test {
    use crate::amount::{MoneroAmount, MoneroDelta};
    use crate::crypto::keys::{Curve25519PublicKey, Curve25519Secret};
    use crate::crypto::traits::PublicKey;
    use crate::kes::{FundingTransaction, KesId, KesInitializationResult, PartialEncryptedKey};
    use crate::monero::data_objects::{ChannelSecrets, ChannelUpdate, MultiSigInitInfo, MultisigKeyInfo};
    use crate::monero::dummy_impl::DummyWallet;
    use crate::monero::WalletState;
    use crate::payment_channel::ChannelRole;
    use crate::state_machine::disputing_channel::DisputeResult;
    use crate::state_machine::lifecycle::LifeCycleEvent;
    use crate::state_machine::new_channel::{
        NewChannelState, ProposedChannelInfo, RejectNewChannelReason, TimeoutReason,
    };
    use crate::state_machine::{
        ChannelClosedReason, ChannelLifeCycle, DisputeResolvedInfo, ForceCloseInfo, LifecycleStage,
        NewChannelBuilder, VssOutput,
    };
    use crate::state_machine::{StartCloseInfo, SuccessfulCloseInfo};
    use blake2::Blake2b512;
    use log::*;
    use monero::Network;

    type DummyLifecycle = ChannelLifeCycle<Curve25519PublicKey, DummyWallet>;
    type DummyEvent = LifeCycleEvent<Curve25519PublicKey>;
    

    async fn lose_dispute(mut lc: DummyLifecycle) -> DummyLifecycle {
        // The force close was successful
        let info = DisputeResolvedInfo::lost("Provided more recent state to KES");
        let event = DummyEvent::OnDisputeResolved(Box::new(info));
        lc = ChannelLifeCycle::log_and_consolidate(lc.stage(), lc.handle_event(event).await);
        assert_eq!(lc.stage(), LifecycleStage::Closed);
        assert!(matches!(
            lc.closed_reason(),
            Some(ChannelClosedReason::Dispute(DisputeResult::DisputeLost(_)))
        ));
        lc
    }


    #[tokio::test]
    async fn timeout_new() {
        env_logger::try_init().ok();
        let (mut lc, _) = new_channel_state();
        // Merchant never responds
        let event = LifeCycleEvent::OnTimeout(Box::new(TimeoutReason::new("Merchant timeout", lc.stage())));
        lc = ChannelLifeCycle::log_and_consolidate(LifecycleStage::New, lc.handle_event(event).await);
        assert_eq!(lc.stage(), LifecycleStage::Closed);
        assert!(matches!(lc.closed_reason(), Some(ChannelClosedReason::Timeout(_))));
    }

    #[tokio::test]
    async fn timeout_establishing() {
        env_logger::try_init().ok();
        let (mut lc, initial_state) = new_channel_state();
        lc = accept_proposal(lc, &initial_state).await;
        // Merchant doesn't respond
        let event = LifeCycleEvent::OnTimeout(Box::new(TimeoutReason::new(
            "Merchant timeout during channel negotiation",
            lc.stage(),
        )));
        lc = ChannelLifeCycle::log_and_consolidate(LifecycleStage::Establishing, lc.handle_event(event).await);
        assert_eq!(lc.stage(), LifecycleStage::Closed);
        assert!(matches!(lc.closed_reason(), Some(ChannelClosedReason::Timeout(_))));
    }

    #[tokio::test]
    async fn reject_new_channel() {
        env_logger::try_init().ok();
        let (mut lc, _initial_state) = new_channel_state();
        // Merchant rejects the channel proposal
        let reason = RejectNewChannelReason::new("At capacity");
        let event = LifeCycleEvent::OnRejectNewChannel(Box::new(reason));
        lc = ChannelLifeCycle::log_and_consolidate(LifecycleStage::New, lc.handle_event(event).await);
        assert_eq!(lc.stage(), LifecycleStage::Closed);
        assert!(matches!(lc.closed_reason(), Some(ChannelClosedReason::Rejected(_))));
    }

    #[tokio::test]
    async fn try_invalid_new_to_payment() {
        // Test invalid state transition. You can´t make a payment (channel update) while still in the New state
        env_logger::try_init().ok();
        let (mut lc, initial_state) = new_channel_state();
        let new_balance = initial_state.channel_info.initial_balances;
        let (k, p) = Curve25519PublicKey::keypair(&mut rand::rng());
        let template = ChannelSecrets {
            update_count: 1,
            new_balances: new_balance,
            delta: MoneroDelta::from(MoneroAmount::from_xmr("0.1").unwrap()),
            witness: k.as_scalar().as_bytes().to_vec(),
            statement: p.as_compressed().as_bytes().to_vec(),
            secret: k,
            public_key: p,
        };
        let info = ChannelUpdate::from_template(&template, &[], &[], &[]);
        let update = DummyEvent::OnUpdateChannel(Box::new(info));
        lc = ChannelLifeCycle::log_and_consolidate(LifecycleStage::New, lc.handle_event(update).await);
        assert_eq!(lc.stage(), LifecycleStage::New);
    }

    #[tokio::test]
    async fn dispute_via_force_close() {
        env_logger::try_init().ok();
        let (mut lc, initial_state) = new_channel_state();
        lc = accept_proposal(lc, &initial_state).await;
        lc = create_wallet(lc).await;
        lc = verify_kes(lc).await;
        lc = open_channel(lc).await;
        lc = payment(lc, MoneroAmount::from_xmr("0.1").unwrap()).await;
        lc = payment(lc, MoneroAmount::from_xmr("0.2").unwrap()).await;
        lc = payment(lc, MoneroAmount::from_xmr("0.3").unwrap()).await;
        assert_eq!(lc.transaction_count(), 3);
        assert_eq!(lc.my_balance(), MoneroAmount::from_xmr("0.65").unwrap());
        lc = trigger_force_close(lc).await;
        lc = uncontested_force_close(lc).await;
        let final_balance = lc.balances();
        assert_eq!(final_balance.customer, MoneroAmount::from_xmr("0.65").unwrap());
        assert_eq!(final_balance.merchant, MoneroAmount::from_xmr("0.60").unwrap());
    }

    #[tokio::test]
    async fn punished_via_dispute() {
        env_logger::try_init().ok();
        let (mut lc, initial_state) = new_channel_state();
        lc = accept_proposal(lc, &initial_state).await;
        lc = create_wallet(lc).await;
        lc = verify_kes(lc).await;
        lc = open_channel(lc).await;
        lc = trigger_force_close(lc).await;
        lose_dispute(lc).await;
    }
}
