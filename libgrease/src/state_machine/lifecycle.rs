use crate::crypto::traits::PublicKey;
use crate::kes::KeyEscrowService;
use crate::monero::MultiSigWallet;
use crate::payment_channel::ActivePaymentChannel;
use crate::state_machine::closed_channel::ClosedChannelState;
use crate::state_machine::closing_channel::{
    ClosingChannelState, InvalidCloseInfo, StartCloseInfo, SuccessfulCloseInfo,
};
use crate::state_machine::disputing_channel::{
    AbandonedChannelInfo, DisputeResolvedInfo, DisputingChannelState, ForceCloseInfo, ForceCloseResolvedInfo,
    TriggerForceCloseInfo,
};
use crate::state_machine::error::LifeCycleError;
use crate::state_machine::establishing_channel::{ChannelEstablishedInfo, EstablishingChannelState};
use crate::state_machine::new_channel::{NewChannelState, ProposedChannelInfo, RejectNewChannelReason, TimeoutReason};
use crate::state_machine::open_channel::{ChannelUpdateInfo, EstablishedChannelState, UpdateResult};
use crate::state_machine::ChannelClosedReason;
use log::{debug, warn};
use std::fmt::{Display, Formatter};

/// A lightweight type indicating which phase of the lifecycle we're in. Generally used for reporting purposes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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

pub enum LifeCycleEvent<P, C, W, KES>
where
    P: PublicKey,
    C: ActivePaymentChannel,
    W: MultiSigWallet,
    KES: KeyEscrowService,
{
    OnAckNewChannel(Box<ProposedChannelInfo<P>>),
    OnTimeout(Box<TimeoutReason>),
    OnChannelEstablished(Box<ChannelEstablishedInfo<C, W, KES>>),
    OnUpdateChannel(Box<ChannelUpdateInfo<C>>),
    OnStartClose(Box<StartCloseInfo>),
    OnRejectNewChannel(Box<RejectNewChannelReason>),
    OnForceClose(Box<ForceCloseInfo>),
    OnAbandonedChannel(Box<AbandonedChannelInfo>),
    OnTriggerForceClose(Box<TriggerForceCloseInfo>),
    OnInvalidClose(Box<InvalidCloseInfo>),
    OnDisputeResolved(Box<DisputeResolvedInfo>),
    OnForceCloseResolved(Box<ForceCloseResolvedInfo>),
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
            LifeCycleEvent::OnChannelEstablished(_) => write!(f, "OnChannelEstablished"),
            LifeCycleEvent::OnUpdateChannel(_) => write!(f, "OnUpdateChannel"),
            LifeCycleEvent::OnStartClose(_) => write!(f, "OnStartClose"),
            LifeCycleEvent::OnRejectNewChannel(_) => write!(f, "OnRejectNewChannel"),
            LifeCycleEvent::OnForceClose(_) => write!(f, "OnForceClose"),
            LifeCycleEvent::OnAbandonedChannel(_) => write!(f, "OnAbandonedChannel"),
            LifeCycleEvent::OnTriggerForceClose(_) => write!(f, "OnTriggerForceClose"),
            LifeCycleEvent::OnInvalidClose(_) => write!(f, "OnInvalidClose"),
            LifeCycleEvent::OnDisputeResolved(_) => write!(f, "OnDisputeResolved"),
            LifeCycleEvent::OnForceCloseResolved(_) => write!(f, "OnForceCloseResolved"),
            LifeCycleEvent::OnSuccessfulClose(_) => write!(f, "OnSuccessfulClose"),
        }
    }
}

impl Display for LifecycleStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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

pub enum ChannelLifeCycle<P, C, W, KES>
where
    P: PublicKey,
    C: ActivePaymentChannel,
    W: MultiSigWallet,
    KES: KeyEscrowService,
{
    New(Box<NewChannelState<P>>),
    /// The channel is in the process of being created.
    Establishing(Box<EstablishingChannelState<P>>),
    /// The channel is open and ready to use.
    Open(Box<EstablishedChannelState<P, C, W, KES>>),
    /// The channel is closed and cannot be used anymore.
    Closing(Box<ClosingChannelState<P, C, W, KES>>),
    Closed(Box<ClosedChannelState<W, C::Finalized>>),
    Disputing(Box<DisputingChannelState>),
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
            ChannelLifeCycle::Open(_) => LifecycleStage::Open,
            ChannelLifeCycle::Closing(_) => LifecycleStage::Closing,
            ChannelLifeCycle::Closed(_) => LifecycleStage::Closed,
            ChannelLifeCycle::Disputing(_) => LifecycleStage::Disputing,
        }
    }

    fn new_to_establishing(self, proposal: ProposedChannelInfo<P>) -> Result<Self, (Self, LifeCycleError)> {
        let Self::New(new_state) = self else {
            return Err((self, LifeCycleError::InvalidStateTransition));
        };
        match new_state.review_proposal(&proposal) {
            Err(err) => {
                return Err((Self::New(new_state), err.into()));
            }
            Ok(()) => {
                let establishing_state = EstablishingChannelState {
                    role: new_state.role,
                    secret_key: new_state.secret_key,
                    merchant_pubkey: new_state.merchant_pubkey,
                    customer_pubkey: new_state.customer_pubkey,
                    kes_public_key: new_state.kes_public_key,
                    initial_balances: new_state.initial_balances,
                    channel_id: new_state.channel_id.clone(),
                };
                let new_state = ChannelLifeCycle::Establishing(Box::new(establishing_state));
                Ok(new_state)
            }
        }
    }

    /// Manage the transition from the Establishing state to the Open state. This is an elaborate process that involves
    /// multiple steps, and therefore makes use of a subordinate state machine.
    fn establishing_to_open(self, info: ChannelEstablishedInfo<C, W, KES>) -> Result<Self, (Self, LifeCycleError)> {
        let Self::Establishing(establishing_state) = self else {
            return Err((self, LifeCycleError::InvalidStateTransition));
        };
        let secret = establishing_state.secret_key;
        let open_state = EstablishedChannelState::from_new_channel_info(info, secret);
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

    fn open_to_closing(self, info: StartCloseInfo) -> Result<Self, (Self, LifeCycleError)> {
        let Self::Open(open_state) = self else {
            return Err((self, LifeCycleError::InvalidStateTransition));
        };
        // Carry out the co-operative close channel protocol
        let closing_state = ClosingChannelState::from_open(*open_state);
        let new_state = ChannelLifeCycle::Closing(Box::new(closing_state));
        Ok(new_state)
    }

    fn closing_to_closed(self, info: SuccessfulCloseInfo) -> Result<Self, (Self, LifeCycleError)> {
        let Self::Closing(closing_state) = self else {
            return Err((self, LifeCycleError::InvalidStateTransition));
        };
        let reason = ChannelClosedReason::Normal;
        let wallet = closing_state.wallet;
        let channel = closing_state.payment_channel.finalize();
        let closed_state = ClosedChannelState::new(reason, channel, wallet);
        Ok(ChannelLifeCycle::Closed(Box::new(closed_state)))
    }

    // Converts Result<Self, Self+> to Self, logging the error in the process
    fn log_and_consolidate(prev_stage: LifecycleStage, result: Result<Self, (Self, LifeCycleError)>) -> Self {
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

    pub fn handle_event(self, event: LifeCycleEvent<P, C, W, KES>) -> Self {
        use LifeCycleEvent::*;
        use LifecycleStage::*;
        match (self.stage(), event) {
            (New, OnAckNewChannel(prop)) => Self::log_and_consolidate(New, self.new_to_establishing(*prop)),
            (New | Establishing, OnTimeout(reason)) => {
                let reason = ChannelClosedReason::Timeout(*reason);
                let state = ClosedChannelState::empty(reason);
                ChannelLifeCycle::Closed(Box::new(state))
            }
            (Establishing, OnChannelEstablished(info)) => {
                Self::log_and_consolidate(Establishing, self.establishing_to_open(*info))
            }
            (Open, OnUpdateChannel(info)) => Self::log_and_consolidate(Open, self.update_channel(*info)),
            (Open, OnStartClose(info)) => Self::log_and_consolidate(Open, self.open_to_closing(*info)),
            (Open, OnInvalidClose(_info)) => ChannelLifeCycle::Disputing(Box::new(DisputingChannelState::new())),
            (Closing, OnSuccessfulClose(info)) => Self::log_and_consolidate(Closing, self.closing_to_closed(*info)),
            (Closing, OnInvalidClose(_info)) => ChannelLifeCycle::Disputing(Box::new(DisputingChannelState::new())),
            (Disputing, OnDisputeResolved(_info)) => {
                let reason = ChannelClosedReason::Dispute;
                // todo: implement dispute resolution
                ChannelLifeCycle::Closed(Box::new(ClosedChannelState::empty(reason)))
            }
            (_, ev) => {
                debug!("Unhandled event / state combination: {ev} in {}", self.stage());
                self
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

    /// If the channel is close, this will return the final state of the payment channel
    pub fn closed_channel(&self) -> Option<&C::Finalized> {
        match self {
            ChannelLifeCycle::Closed(closed_state) => closed_state.channel(),
            _ => None,
        }
    }

    /// If the channel is closed, this will return the reason for the closure
    pub fn closed_reason(&self) -> Option<&ChannelClosedReason> {
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
mod test {
    use crate::amount::MoneroAmount;
    use crate::crypto::keys::Curve25519PublicKey;
    use crate::crypto::traits::PublicKey;
    use crate::kes::dummy_impl::DummyKes;
    use crate::monero::dummy_impl::DummyWallet;
    use crate::monero::MultiSigWallet;
    use crate::payment_channel::dummy_impl::{DummyActiveChannel, DummyUpdateInfo};
    use crate::payment_channel::{ActivePaymentChannel, ChannelRole, ClosedPaymentChannel};
    use crate::state_machine::establishing_channel::ChannelEstablishedInfo;
    use crate::state_machine::lifecycle::LifeCycleEvent;
    use crate::state_machine::new_channel::ProposedChannelInfo;
    use crate::state_machine::open_channel::ChannelUpdateInfo;
    use crate::state_machine::{ChannelClosedReason, ChannelLifeCycle, LifecycleStage, NewChannelBuilder};
    use crate::state_machine::{StartCloseInfo, SuccessfulCloseInfo};
    use blake2::Blake2b512;

    type DummyLifecycle = ChannelLifeCycle<Curve25519PublicKey, DummyActiveChannel, DummyWallet, DummyKes>;
    type DummyEvent = LifeCycleEvent<Curve25519PublicKey, DummyActiveChannel, DummyWallet, DummyKes>;
    fn lifecycle_flow_for_customer() -> DummyLifecycle {
        let mut rng = rand::rng();
        // All this info is known, or can be scanned in from a QR code etc
        let (my_secret, my_pubkey) = Curve25519PublicKey::keypair(&mut rng);
        let (_merchant_secret, merchant_pubkey) = Curve25519PublicKey::keypair(&mut rng);
        let (_kes_secret, kes_pubkey) = Curve25519PublicKey::keypair(&mut rng);
        let initial_customer_amount = MoneroAmount::from_xmr("1.25").unwrap();
        let initial_merchant_amount = MoneroAmount::from_xmr("0.25").unwrap();
        let initial_state = NewChannelBuilder::new(ChannelRole::Customer, my_pubkey.clone(), my_secret);
        let initial_state = initial_state
            .with_kes_public_key(kes_pubkey.clone())
            .with_customer_initial_balance(initial_customer_amount)
            .with_merchant_initial_balance(initial_merchant_amount)
            .with_peer_public_key(merchant_pubkey.clone())
            .with_my_partial_channel_id(b"me".to_vec())
            .with_peer_partial_channel_id(b"you".to_vec())
            .build::<Blake2b512>()
            .expect("Failed to build initial state");
        let channel_id = initial_state.channel_id.clone();
        // Create a new channel state machine
        let mut lc = ChannelLifeCycle::new(initial_state.clone());
        assert_eq!(lc.stage(), LifecycleStage::New);
        // Data gets sent to merchant. They respond with an ack and a proposal
        let proposal = ProposedChannelInfo {
            role: ChannelRole::Merchant,
            channel_id: channel_id.clone(),
            merchant_pubkey: merchant_pubkey.clone(),
            customer_pubkey: my_pubkey.clone(),
            kes_public_key: kes_pubkey.clone(),
            initial_balances: initial_state.initial_balances,
            customer_partial_channel_id: initial_state.customer_partial_channel_id.clone(),
            merchant_partial_channel_id: initial_state.merchant_partial_channel_id.clone(),
        };
        let event = LifeCycleEvent::OnAckNewChannel(Box::new(proposal));
        lc = lc.handle_event(event);
        // The channel is now in the establishing phase
        assert_eq!(lc.stage(), LifecycleStage::Establishing);
        // All the comms in the Establishing state machine are negotiated, and eventually are successful
        let channel =
            DummyActiveChannel::new(channel_id.clone(), ChannelRole::Customer, initial_state.initial_balances);
        let wallet = DummyWallet::create(2, 2);
        let kes = DummyKes;
        let established = ChannelEstablishedInfo { wallet, kes, channel };
        let event = LifeCycleEvent::OnChannelEstablished(Box::new(established));
        lc = lc.handle_event(event);
        assert_eq!(lc.stage(), LifecycleStage::Open);
        // The channel can be used to send payments
        let balance = lc.payment_channel().unwrap().balances();
        let new_balance = balance.pay(MoneroAmount::from_xmr("0.1").unwrap()).unwrap();
        let update = DummyUpdateInfo { new_balance };
        let info = ChannelUpdateInfo::new(channel_id.hash().to_vec(), update);
        let update = DummyEvent::OnUpdateChannel(Box::new(info));
        lc = lc.handle_event(update);
        assert_eq!(lc.stage(), LifecycleStage::Open);
        let channel = lc.payment_channel().expect("Failed to get payment channel");
        assert_eq!(channel.transaction_count(), 1);
        assert_eq!(channel.my_balance(), MoneroAmount::from_xmr("1.15").unwrap());
        // A co-operative close channel request has been fired
        let close_info = StartCloseInfo {};
        let close_event = DummyEvent::OnStartClose(Box::new(close_info));
        lc = lc.handle_event(close_event);
        // The channel closure was successfully negotiated
        let info = SuccessfulCloseInfo {};
        let event = DummyEvent::OnSuccessfulClose(Box::new(info));
        lc = lc.handle_event(event);
        assert_eq!(lc.stage(), LifecycleStage::Closed);
        assert!(matches!(lc.closed_reason(), Some(ChannelClosedReason::Normal)));
        let final_balance = lc.closed_channel().unwrap().final_balance();
        assert_eq!(final_balance.customer, MoneroAmount::from_xmr("1.15").unwrap());
        assert_eq!(final_balance.merchant, MoneroAmount::from_xmr("0.35").unwrap());
        lc
    }

    #[test]
    fn happy_path() {
        env_logger::try_init().ok();
        lifecycle_flow_for_customer();
    }
}
