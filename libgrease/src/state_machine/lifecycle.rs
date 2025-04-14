use crate::state_machine::closed_channel::ClosedChannelState;
use crate::state_machine::closing_channel::{
    ClosingChannelState, InvalidCloseInfo, StartCloseInfo, SuccessfulCloseInfo,
};
use crate::state_machine::disputing_channel::{DisputeResolvedInfo, DisputingChannelState};
use crate::state_machine::establishing_channel::{ChannelEstablishedInfo, EstablishingChannelState};
use crate::state_machine::new_channel::{NewChannelInfo, NewChannelState, TimeoutReason};
use crate::state_machine::open_channel::EstablishedChannelState;
use crate::state_machine::ChannelClosedReason;
use std::fmt::Display;

/// A lightweight type indicating which phase of the lifecycle we're in. Generally used for reporting purposes.
#[derive(Clone, Copy, Debug)]
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

#[derive(Clone, Copy, Debug)]
pub enum ChannelRole {
    Merchant,
    Customer,
}

pub enum LifeCycleEvent<P> {
    OnNewChannelInfo(Box<NewChannelInfo<P>>),
    OnTimeout(Box<TimeoutReason>),
    OnChannelEstablished(Box<ChannelEstablishedInfo>),
    OnStartClose(Box<StartCloseInfo>),
    OnInvalidClose(Box<InvalidCloseInfo>),
    OnDisputeResolved(Box<DisputeResolvedInfo>),
    OnSuccessfulClose(Box<SuccessfulCloseInfo>),
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

pub enum ChannelLifeCycle<P, S> {
    New(Box<NewChannelState<P, S>>),
    /// The channel is in the process of being created.
    Establishing(Box<EstablishingChannelState>),
    /// The channel is open and ready to use.
    Open(Box<EstablishedChannelState>),
    /// The channel is closed and cannot be used anymore.
    Closing(Box<ClosingChannelState>),
    Closed(Box<ClosedChannelState>),
    Disputing(Box<DisputingChannelState>),
}

impl<P, S> ChannelLifeCycle<P, S> {
    pub fn new(state: NewChannelState<P, S>) -> Self {
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

    pub fn handle_event(&mut self, event: LifeCycleEvent<P>) {
        use LifeCycleEvent::*;
        use LifecycleStage::*;
        match (self.stage(), event) {
            (New, OnNewChannelInfo(info)) => {
                *self = ChannelLifeCycle::Establishing(Box::new(EstablishingChannelState::new(*info)));
            }
            (New | Establishing, OnTimeout(reason)) => {
                let reason = ChannelClosedReason::Timeout(*reason);
                let state = ClosedChannelState::new(reason, self.stage());
                *self = ChannelLifeCycle::Closed(Box::new(state));
            }
            (Establishing, OnChannelEstablished(info)) => {
                let next_state = EstablishedChannelState::from_new_channel_info(*info);
                *self = ChannelLifeCycle::Open(Box::new(next_state));
            }
            (Open, OnStartClose(_info)) => {
                *self = ChannelLifeCycle::Closing(Box::new(ClosingChannelState::new()));
            }
            (Open, OnInvalidClose(_info)) => {
                *self = ChannelLifeCycle::Disputing(Box::new(DisputingChannelState::new()));
            }
            (Closing, OnSuccessfulClose(_info)) => {
                let reason = ChannelClosedReason::Normal;
                *self = ChannelLifeCycle::Closed(Box::new(ClosedChannelState::new(reason, self.stage())));
            }
            (Closing, OnInvalidClose(_info)) => {
                *self = ChannelLifeCycle::Disputing(Box::new(DisputingChannelState::new()));
            }
            (Disputing, OnDisputeResolved(_info)) => {
                let reason = ChannelClosedReason::Dispute;
                *self = ChannelLifeCycle::Closed(Box::new(ClosedChannelState::new(reason, self.stage())));
            }
            _ => {
                // Handle invalid state/event combinations if necessary
            }
        }
    }
}
