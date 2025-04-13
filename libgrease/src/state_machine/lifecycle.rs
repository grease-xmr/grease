use crate::state_machine::closed_channel::ClosedChannelState;
use crate::state_machine::closing_channel::ClosingChannelState;
use crate::state_machine::disputing_channel::DisputingChannelState;
use crate::state_machine::establishing_channel::EstablishingChannelState;
use crate::state_machine::new_channel::NewChannelState;
use crate::state_machine::open_channel::OpenChannelState;
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

pub enum ChannelLifeCycle {
    New(Box<NewChannelState>),
    /// The channel is in the process of being created.
    Establishing(Box<EstablishingChannelState>),
    /// The channel is open and ready to use.
    Open(Box<OpenChannelState>),
    /// The channel is closed and cannot be used anymore.
    Closing(Box<ClosingChannelState>),
    Closed(Box<ClosedChannelState>),
    Disputing(Box<DisputingChannelState>),
}

impl ChannelLifeCycle {
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
}
