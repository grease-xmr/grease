use crate::crypto::traits::PublicKey;
use crate::kes::KeyEscrowService;
use crate::monero::data_objects::TransactionId;
use crate::monero::MultiSigWallet;
use crate::payment_channel::{ActivePaymentChannel, ChannelRole};
use crate::state_machine::closed_channel::ClosedChannelState;
use crate::state_machine::closing_channel::{ClosingChannelState, StartCloseInfo, SuccessfulCloseInfo};
use crate::state_machine::disputing_channel::{DisputeResolvedInfo, DisputingChannelState, ForceCloseInfo};
use crate::state_machine::error::LifeCycleError;
use crate::state_machine::establishing_channel::{
    ChannelMetadata, EstablishingState, KesVerifiedState, WalletCreatedState,
};
use crate::state_machine::new_channel::{NewChannelState, ProposedChannelInfo, RejectNewChannelReason, TimeoutReason};
use crate::state_machine::open_channel::{ChannelUpdateInfo, EstablishedChannelState, UpdateResult};
use crate::state_machine::traits::ChannelState;
use crate::state_machine::ChannelClosedReason;
use log::*;
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};

/// A lightweight type indicating which phase of the lifecycle we're in. Generally used for reporting purposes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LifecycleStage {
    /// The channel is being created.
    New,
    /// The channel is being established.
    Establishing,
    /// The MultiSig wallet has been co-operatively setup between peers
    WalletCreated,
    /// The KES has been set up and verified by both parties
    KesVerified,
    /// The channel is open and ready to use.
    Open,
    /// The channel is being closed.
    Closing,
    /// The channel is closed and cannot be used anymore.
    Closed,
    /// The channel is in dispute.
    Disputing,
}

pub enum LifeCycleEvent<P, C, W, KES>
where
    P: PublicKey,
    C: ActivePaymentChannel,
    W: MultiSigWallet,
    KES: KeyEscrowService,
{
    OnAckNewChannel(Box<ProposedChannelInfo<P>>),
    OnRejectNewChannel(Box<RejectNewChannelReason>),
    OnTimeout(Box<TimeoutReason>),
    OnMultiSigWalletCreated(Box<W>),
    OnKesVerified(Box<KES>),
    OnFundingTxConfirmed(Box<TransactionId>),
    OnUpdateChannel(Box<ChannelUpdateInfo<C>>),
    OnStartClose(Box<StartCloseInfo>),
    OnForceClose(Box<ForceCloseInfo>),
    OnDisputeResolved(Box<DisputeResolvedInfo<P>>),
    OnSuccessfulClose(Box<SuccessfulCloseInfo>),
}

impl<P, C, W, KES> Display for LifeCycleEvent<P, C, W, KES>
where
    P: PublicKey,
    C: ActivePaymentChannel,
    W: MultiSigWallet,
    KES: KeyEscrowService,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            LifeCycleEvent::OnAckNewChannel(_) => write!(f, "OnAckNewChannel"),
            LifeCycleEvent::OnTimeout(_) => write!(f, "OnTimeout"),
            LifeCycleEvent::OnMultiSigWalletCreated(_) => write!(f, "MultiSigWalletCreated"),
            LifeCycleEvent::OnKesVerified(_) => write!(f, "MultiSigWalletCreated"),
            LifeCycleEvent::OnFundingTxConfirmed(_) => write!(f, "OnChannelEstablished"),
            LifeCycleEvent::OnUpdateChannel(_) => write!(f, "OnUpdateChannel"),
            LifeCycleEvent::OnStartClose(_) => write!(f, "OnStartClose"),
            LifeCycleEvent::OnRejectNewChannel(_) => write!(f, "OnRejectNewChannel"),
            LifeCycleEvent::OnForceClose(_) => write!(f, "OnForceClose"),
            LifeCycleEvent::OnDisputeResolved(_) => write!(f, "OnDisputeResolved"),
            LifeCycleEvent::OnSuccessfulClose(_) => write!(f, "OnSuccessfulClose"),
        }
    }
}

impl Display for LifecycleStage {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            LifecycleStage::New => write!(f, "New"),
            LifecycleStage::Establishing => write!(f, "Establishing"),
            LifecycleStage::WalletCreated => write!(f, "WalletCreated"),
            LifecycleStage::KesVerified => write!(f, "KESVerified"),
            LifecycleStage::Open => write!(f, "Open"),
            LifecycleStage::Closing => write!(f, "Closing"),
            LifecycleStage::Closed => write!(f, "Closed"),
            LifecycleStage::Disputing => write!(f, "Disputing"),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(deserialize = "P: PublicKey + for<'d> Deserialize<'d>, W: MultiSigWallet + for<'d> Deserialize<'d>"))]
pub enum ChannelLifeCycle<P, C, W, KES>
where
    P: PublicKey,
    C: ActivePaymentChannel,
    W: MultiSigWallet,
    KES: KeyEscrowService,
{
    New(Box<NewChannelState<P>>),
    /// The channel is in the process of being created.
    Establishing(Box<EstablishingState<P, W>>),
    WalletCreated(Box<WalletCreatedState<P, W>>),
    KesVerified(Box<KesVerifiedState<P, W, KES>>),
    /// The channel is open and ready to use.
    Open(Box<EstablishedChannelState<P, C, W, KES>>),
    /// The channel is closed and cannot be used anymore.
    Closing(Box<ClosingChannelState<P, C, W, KES>>),
    Closed(Box<ClosedChannelState<P, W, C::Finalized>>),
    Disputing(Box<DisputingChannelState<P, C, W, KES>>),
}

impl<P, C, W, KES> ChannelLifeCycle<P, C, W, KES>
where
    P: PublicKey,
    C: ActivePaymentChannel,
    W: MultiSigWallet,
    KES: KeyEscrowService,
{
    pub fn new(state: NewChannelState<P>) -> Self {
        ChannelLifeCycle::New(Box::new(state))
    }

    /// Get the current lifecycle stage of the channel.
    pub fn stage(&self) -> LifecycleStage {
        match self {
            ChannelLifeCycle::New(_) => LifecycleStage::New,
            ChannelLifeCycle::Establishing(_) => LifecycleStage::Establishing,
            ChannelLifeCycle::WalletCreated(_) => LifecycleStage::WalletCreated,
            ChannelLifeCycle::KesVerified(_) => LifecycleStage::KesVerified,
            ChannelLifeCycle::Open(_) => LifecycleStage::Open,
            ChannelLifeCycle::Closing(_) => LifecycleStage::Closing,
            ChannelLifeCycle::Closed(_) => LifecycleStage::Closed,
            ChannelLifeCycle::Disputing(_) => LifecycleStage::Disputing,
        }
    }

    pub fn role(&self) -> ChannelRole {
        self.current_state().role()
    }

    pub fn current_state(&self) -> &dyn ChannelState {
        match self {
            ChannelLifeCycle::New(state) => state.as_ref(),
            ChannelLifeCycle::Establishing(state) => state.as_ref(),
            ChannelLifeCycle::WalletCreated(state) => state.as_ref(),
            ChannelLifeCycle::KesVerified(state) => state.as_ref(),
            ChannelLifeCycle::Open(state) => state.as_ref(),
            ChannelLifeCycle::Closing(state) => state.as_ref(),
            ChannelLifeCycle::Closed(state) => state.as_ref(),
            ChannelLifeCycle::Disputing(state) => state.as_ref(),
        }
    }

    async fn new_to_establishing(self, proposal: ProposedChannelInfo<P>) -> Result<Self, (Self, LifeCycleError)> {
        let Self::New(new_state) = self else {
            return Err((self, LifeCycleError::InvalidStateTransition));
        };
        match new_state.review_proposal(&proposal) {
            Err(err) => Err((Self::New(new_state), err.into())),
            Ok(()) => {
                let wallet = W::new(&new_state.channel_id).map_err(|e| {
                    let old_state = ChannelLifeCycle::New(new_state.clone());
                    (old_state, e.into())
                })?;
                let channel_info = ChannelMetadata {
                    role: new_state.role,
                    secret_key: new_state.secret_key,
                    merchant_pubkey: new_state.merchant_pubkey,
                    customer_pubkey: new_state.customer_pubkey,
                    kes_public_key: new_state.kes_public_key,
                    initial_balances: new_state.initial_balances,
                    channel_id: new_state.channel_id.clone(),
                };
                let establishing_state = EstablishingState::new(channel_info, wallet);
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
        let channel_id = new_state.channel_id.clone();
        let channel_role = new_state.role;
        let state = ClosedChannelState::empty(reason, channel_id, channel_role);
        Ok(ChannelLifeCycle::Closed(Box::new(state)))
    }

    /// Manage the transition from the Establishing state to the Open state. This is an elaborate process that involves
    /// multiple steps, and therefore makes use of a subordinate state machine.
    fn establishing_to_wallet_created(self, wallet: W) -> Result<Self, (Self, LifeCycleError)> {
        let Self::Establishing(establishing_state) = self else {
            return Err((self, LifeCycleError::InvalidStateTransition));
        };
        let state = *establishing_state;
        let channel_info = state.channel_info;
        let wallet = state.wallet_state.expect("wallet state MUST contain a wallet").to_wallet();
        let wallet_created = WalletCreatedState { channel_info, wallet };
        let new_state = ChannelLifeCycle::WalletCreated(Box::new(wallet_created));
        Ok(new_state)
    }

    fn wallet_created_to_kes_verified(self, kes: KES) -> Result<Self, (Self, LifeCycleError)> {
        let Self::WalletCreated(wallet_created_state) = self else {
            return Err((self, LifeCycleError::InvalidStateTransition));
        };
        let kes_verified = KesVerifiedState {
            channel_info: (*wallet_created_state).channel_info,
            wallet: wallet_created_state.wallet,
            kes,
        };
        let new_state = ChannelLifeCycle::KesVerified(Box::new(kes_verified));
        Ok(new_state)
    }

    fn kes_verified_to_open(self, txid: TransactionId) -> Result<Self, (Self, LifeCycleError)> {
        let Self::KesVerified(state) = self else {
            return Err((self, LifeCycleError::InvalidStateTransition));
        };
        let state = *state;
        let channel = C::new(
            state.channel_info.channel_id.clone(),
            state.channel_info.role,
            state.channel_info.initial_balances,
        );

        let open_state = EstablishedChannelState {
            channel_info: state.channel_info,
            payment_channel: channel,
            wallet: state.wallet,
            kes: state.kes,
            funding_tx: txid,
        };
        let new_state = ChannelLifeCycle::Open(Box::new(open_state));
        Ok(new_state)
    }

    fn update_channel(self, info: ChannelUpdateInfo<C>) -> Result<Self, (Self, LifeCycleError)> {
        let Self::Open(mut current_state) = self else {
            return Err((self, LifeCycleError::InvalidStateTransition));
        };
        match current_state.try_update(info) {
            UpdateResult::Success => debug!("Payment channel update was successful"),
            UpdateResult::Failure => debug!("Payment channel update failed"),
        }
        let updated_state = ChannelLifeCycle::Open(current_state);
        Ok(updated_state)
    }

    fn open_to_closing(self, _info: StartCloseInfo) -> Result<Self, (Self, LifeCycleError)> {
        let Self::Open(open_state) = self else {
            return Err((self, LifeCycleError::InvalidStateTransition));
        };
        // Carry out the co-operative close channel protocol
        let closing_state = ClosingChannelState::from_open(*open_state);
        let new_state = ChannelLifeCycle::Closing(Box::new(closing_state));
        Ok(new_state)
    }

    fn closing_to_closed(self, _info: SuccessfulCloseInfo) -> Result<Self, (Self, LifeCycleError)> {
        let Self::Closing(closing_state) = self else {
            return Err((self, LifeCycleError::InvalidStateTransition));
        };
        let reason = ChannelClosedReason::Normal;
        let wallet = closing_state.wallet;
        let channel = closing_state.payment_channel.finalize();
        let closed_state = ClosedChannelState::new(reason, channel, wallet);
        Ok(ChannelLifeCycle::Closed(Box::new(closed_state)))
    }

    fn open_to_dispute(self, info: ForceCloseInfo) -> Result<Self, (Self, LifeCycleError)> {
        let Self::Open(open_state) = self else {
            return Err((self, LifeCycleError::InvalidStateTransition));
        };
        warn!(
            "Channel {} is force closing. Origin: {}. Reason: {}",
            open_state.name(),
            info.origin,
            info.reason
        );
        let dispute_state = DisputingChannelState::from_open(*open_state, info);
        Ok(ChannelLifeCycle::Disputing(Box::new(dispute_state)))
    }

    fn closing_to_dispute(self, info: ForceCloseInfo) -> Result<Self, (Self, LifeCycleError)> {
        let Self::Closing(closing_state) = self else {
            return Err((self, LifeCycleError::InvalidStateTransition));
        };
        warn!(
            "Channel {} is force closing. Origin: {}. Reason: {}",
            closing_state.name(),
            info.origin,
            info.reason
        );
        let dispute_state = DisputingChannelState::from_closing(*closing_state, info);
        Ok(ChannelLifeCycle::Disputing(Box::new(dispute_state)))
    }

    fn timeout(self, reason: TimeoutReason) -> Result<Self, (Self, LifeCycleError)> {
        warn!(
            "Channel in stage ´{}´ timed out and is now closed. Reason: {}",
            reason.stage(),
            reason.reason()
        );
        let timeout = ChannelClosedReason::Timeout(reason);
        let channel_id = self.current_state().channel_id().clone();
        let channel_role = self.current_state().role();
        let state = ClosedChannelState::empty(timeout, channel_id, channel_role);
        Ok(ChannelLifeCycle::Closed(Box::new(state)))
    }

    fn disputing_to_closed(self, info: DisputeResolvedInfo<P>) -> Result<Self, (Self, LifeCycleError)> {
        let Self::Disputing(disputing_state) = self else {
            return Err((self, LifeCycleError::InvalidStateTransition));
        };
        let reason = ChannelClosedReason::Dispute(info.result);
        let wallet = disputing_state.wallet;
        let channel = disputing_state.payment_channel;
        let closed_channel = channel.finalize();
        let state = ClosedChannelState::new(reason, closed_channel, wallet);
        Ok(ChannelLifeCycle::Closed(Box::new(state)))
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

    pub async fn handle_event(self, event: LifeCycleEvent<P, C, W, KES>) -> Result<Self, (Self, LifeCycleError)> {
        use LifeCycleEvent::*;
        use LifecycleStage::*;
        match (self.stage(), event) {
            (New, OnAckNewChannel(prop)) => self.new_to_establishing(*prop).await,
            (New, OnRejectNewChannel(reason)) => self.reject_new_channel(*reason),
            (New | Establishing | WalletCreated | KesVerified, OnTimeout(reason)) => self.timeout(*reason),
            (Establishing, OnMultiSigWalletCreated(wallet)) => self.establishing_to_wallet_created(*wallet),
            (WalletCreated, OnKesVerified(kes)) => self.wallet_created_to_kes_verified(*kes),
            (KesVerified, OnFundingTxConfirmed(txid)) => self.kes_verified_to_open(*txid),
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

    pub fn payment_channel(&self) -> Option<&C> {
        match self {
            ChannelLifeCycle::Open(open_state) => Some(&open_state.payment_channel),
            ChannelLifeCycle::Closing(establishing_state) => Some(&establishing_state.payment_channel),
            _ => None,
        }
    }

    /// If the channel is closed, this will return the final state of the payment channel
    pub fn closed_channel(&self) -> Option<&C::Finalized> {
        match self {
            ChannelLifeCycle::Closed(closed_state) => closed_state.channel(),
            _ => None,
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
}

#[cfg(test)]
pub mod test {
    use crate::amount::MoneroAmount;
    use crate::crypto::keys::Curve25519PublicKey;
    use crate::kes::dummy_impl::DummyKes;
    use crate::monero::data_objects::TransactionId;
    use crate::monero::dummy_impl::DummyWallet;
    use crate::monero::MultiSigWallet;
    use crate::payment_channel::dummy_impl::{DummyActiveChannel, DummyUpdateInfo};
    use crate::payment_channel::{ActivePaymentChannel, ChannelRole, ClosedPaymentChannel};
    use crate::state_machine::disputing_channel::DisputeResult;
    use crate::state_machine::lifecycle::LifeCycleEvent;
    use crate::state_machine::new_channel::{
        NewChannelState, ProposedChannelInfo, RejectNewChannelReason, TimeoutReason,
    };
    use crate::state_machine::open_channel::ChannelUpdateInfo;
    use crate::state_machine::{
        ChannelClosedReason, ChannelLifeCycle, DisputeResolvedInfo, ForceCloseInfo, LifecycleStage, NewChannelBuilder,
    };
    use crate::state_machine::{StartCloseInfo, SuccessfulCloseInfo};
    use blake2::Blake2b512;
    use log::*;

    type DummyLifecycle = ChannelLifeCycle<Curve25519PublicKey, DummyActiveChannel, DummyWallet, DummyKes>;
    type DummyEvent = LifeCycleEvent<Curve25519PublicKey, DummyActiveChannel, DummyWallet, DummyKes>;

    pub fn new_channel_state() -> (DummyLifecycle, NewChannelState<Curve25519PublicKey>) {
        // All this info is known, or can be scanned in from a QR code etc
        let (my_secret, my_pubkey) =
            Curve25519PublicKey::keypair_from_hex("0b98747459483650bb0d404e4ccc892164f88a5f1f131cee9e27f633cef6810d")
                .unwrap();
        let merchant_pubkey =
            Curve25519PublicKey::from_hex("61772c23631fa02db2fbe47515dda43fc28a471ee47719930e388d2ba5275016").unwrap();
        let kes_pubkey =
            Curve25519PublicKey::from_hex("4dd896d542721742aff8671ba42aff0c4c846bea79065cf39a191bbeb11ea634").unwrap();
        let initial_customer_amount = MoneroAmount::from_xmr("1.25").unwrap();
        let initial_merchant_amount = MoneroAmount::from_xmr("0.25").unwrap();
        let initial_state = NewChannelBuilder::new(ChannelRole::Customer, my_pubkey.clone(), my_secret);
        let initial_state = initial_state
            .with_kes_public_key(kes_pubkey.clone())
            .with_customer_initial_balance(initial_customer_amount)
            .with_merchant_initial_balance(initial_merchant_amount)
            .with_peer_public_key(merchant_pubkey.clone())
            .with_my_user_label("me")
            .with_peer_label("you")
            .build::<Blake2b512>()
            .expect("Failed to build initial state");
        // Create a new channel state machine
        let lc = ChannelLifeCycle::new(initial_state.clone());
        assert_eq!(lc.stage(), LifecycleStage::New);
        info!("New channel state machine created");
        (lc, initial_state)
    }

    pub async fn accept_proposal(
        mut lc: DummyLifecycle,
        initial_state: &NewChannelState<Curve25519PublicKey>,
    ) -> DummyLifecycle {
        // Data gets sent to merchant. They respond with an ack and a proposal. Note that the role is role they want
        // me to play.
        let proposal = ProposedChannelInfo {
            role: ChannelRole::Customer,
            channel_id: initial_state.channel_id.clone(),
            merchant_pubkey: initial_state.merchant_pubkey.clone(),
            customer_pubkey: initial_state.customer_pubkey.clone(),
            kes_public_key: initial_state.kes_public_key.clone(),
            initial_balances: initial_state.initial_balances,
            customer_label: initial_state.customer_label.clone(),
            merchant_label: initial_state.merchant_label.clone(),
        };
        let event = LifeCycleEvent::OnAckNewChannel(Box::new(proposal));
        lc = ChannelLifeCycle::log_and_consolidate(LifecycleStage::New, lc.handle_event(event).await);
        // The channel is now in the establishing phase
        assert_eq!(lc.stage(), LifecycleStage::Establishing);
        lc
    }

    pub async fn create_wallet(mut lc: DummyLifecycle) -> DummyLifecycle {
        // The wallet negotiation is successful, and the wallet is created
        let wallet = DummyWallet::new(&lc.current_state().channel_id()).unwrap();
        let event = LifeCycleEvent::OnMultiSigWalletCreated(Box::new(wallet));
        lc = ChannelLifeCycle::log_and_consolidate(lc.stage(), lc.handle_event(event).await);
        assert_eq!(lc.stage(), LifecycleStage::WalletCreated);
        lc
    }

    pub async fn verify_kes(mut lc: DummyLifecycle) -> DummyLifecycle {
        // The KES creation is successful, and the KES is verified
        let kes = DummyKes;
        let event = LifeCycleEvent::OnKesVerified(Box::new(kes));
        lc = ChannelLifeCycle::log_and_consolidate(lc.stage(), lc.handle_event(event).await);
        assert_eq!(lc.stage(), LifecycleStage::KesVerified);
        lc
    }

    pub async fn open_channel(mut lc: DummyLifecycle) -> DummyLifecycle {
        // The funding tx has been broadcast
        let txid = TransactionId::new("DummyMoneroTx");
        let event = LifeCycleEvent::OnFundingTxConfirmed(Box::new(txid));
        lc = ChannelLifeCycle::log_and_consolidate(lc.stage(), lc.handle_event(event).await);
        assert_eq!(lc.stage(), LifecycleStage::Open);
        lc
    }

    pub async fn payment(mut lc: DummyLifecycle, amount: MoneroAmount) -> DummyLifecycle {
        // The channel can be used to send payments
        let balance = lc.payment_channel().unwrap().balances();
        let new_balance = balance.pay(amount).unwrap();
        let update = DummyUpdateInfo { new_balance };
        let channel_name = lc.current_state().name();
        let info = ChannelUpdateInfo::new(channel_name, update);
        let update = DummyEvent::OnUpdateChannel(Box::new(info));
        lc = ChannelLifeCycle::log_and_consolidate(lc.stage(), lc.handle_event(update).await);
        assert_eq!(lc.stage(), LifecycleStage::Open);
        lc
    }

    pub async fn start_close(mut lc: DummyLifecycle) -> DummyLifecycle {
        // A co-operative close channel request has been fired
        let close_info = StartCloseInfo {};
        let close_event = DummyEvent::OnStartClose(Box::new(close_info));
        lc = ChannelLifeCycle::log_and_consolidate(lc.stage(), lc.handle_event(close_event).await);
        lc
    }

    pub async fn trigger_force_close(mut lc: DummyLifecycle) -> DummyLifecycle {
        // We are triggering a force close
        let close_info = ForceCloseInfo::trigger("Some people want the world to burn");
        let close_event = DummyEvent::OnForceClose(Box::new(close_info));
        lc = ChannelLifeCycle::log_and_consolidate(lc.stage(), lc.handle_event(close_event).await);
        assert_eq!(lc.stage(), LifecycleStage::Disputing);
        lc
    }

    pub async fn successful_close(mut lc: DummyLifecycle) -> DummyLifecycle {
        // The channel closure was successfully negotiated
        let info = SuccessfulCloseInfo {};
        let event = DummyEvent::OnSuccessfulClose(Box::new(info));
        lc = ChannelLifeCycle::log_and_consolidate(lc.stage(), lc.handle_event(event).await);
        assert_eq!(lc.stage(), LifecycleStage::Closed);
        assert!(matches!(lc.closed_reason(), Some(ChannelClosedReason::Normal)));
        lc
    }

    async fn uncontested_force_close(mut lc: DummyLifecycle) -> DummyLifecycle {
        // The force close was successful
        let info = DisputeResolvedInfo::uncontested();
        let event = DummyEvent::OnDisputeResolved(Box::new(info));
        lc = ChannelLifeCycle::log_and_consolidate(lc.stage(), lc.handle_event(event).await);
        assert_eq!(lc.stage(), LifecycleStage::Closed);
        assert!(matches!(
            lc.closed_reason(),
            Some(ChannelClosedReason::Dispute(DisputeResult::UncontestedForceClose))
        ));
        lc
    }

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
    async fn happy_path() {
        env_logger::try_init().ok();
        let (mut lc, initial_state) = new_channel_state();
        lc = accept_proposal(lc, &initial_state).await;
        lc = create_wallet(lc).await;
        lc = verify_kes(lc).await;
        lc = open_channel(lc).await;
        lc = payment(lc, MoneroAmount::from_xmr("0.1").unwrap()).await;
        lc = payment(lc, MoneroAmount::from_xmr("0.2").unwrap()).await;
        lc = payment(lc, MoneroAmount::from_xmr("0.3").unwrap()).await;
        let channel = lc.payment_channel().expect("Failed to get payment channel");
        assert_eq!(channel.transaction_count(), 3);
        assert_eq!(channel.my_balance(), MoneroAmount::from_xmr("0.65").unwrap());
        lc = start_close(lc).await;
        lc = successful_close(lc).await;
        let final_balance = lc.closed_channel().unwrap().final_balance();
        assert_eq!(final_balance.customer, MoneroAmount::from_xmr("0.65").unwrap());
        assert_eq!(final_balance.merchant, MoneroAmount::from_xmr("0.85").unwrap());
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
        let new_balance = initial_state.initial_balances;
        let update = DummyUpdateInfo { new_balance };
        let channel_name = lc.current_state().name();
        let info = ChannelUpdateInfo::new(channel_name, update);
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
        let channel = lc.payment_channel().expect("Failed to get payment channel");
        assert_eq!(channel.transaction_count(), 3);
        assert_eq!(channel.my_balance(), MoneroAmount::from_xmr("0.65").unwrap());
        lc = trigger_force_close(lc).await;
        lc = uncontested_force_close(lc).await;
        let final_balance = lc.closed_channel().unwrap().final_balance();
        assert_eq!(final_balance.customer, MoneroAmount::from_xmr("0.65").unwrap());
        assert_eq!(final_balance.merchant, MoneroAmount::from_xmr("0.85").unwrap());
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
