//! Finite state machine for Grease payment channels
//!
#![doc = include_str!("../../../docs/channel_lifecycle.md")]

mod closed_channel;
mod closing_channel;
mod disputing_channel;
mod establishing_channel;
mod lifecycle;
mod new_channel;
mod open_channel;

pub use closed_channel::{ChannelClosedReason, ClosedChannelState};
pub use closing_channel::ClosingChannelState;
pub use disputing_channel::DisputingChannelState;
pub use establishing_channel::EstablishingChannelState;
pub use lifecycle::{ChannelLifeCycle, LifecycleStage};
pub use new_channel::NewChannelState;
pub use open_channel::OpenChannelState;
