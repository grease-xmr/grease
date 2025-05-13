//! Finite state machine for Grease payment channels
//!
#![doc = include_str!("../../../docs/channel_lifecycle.md")]

mod closed_channel;
mod closing_channel;
mod disputing_channel;
pub mod error;
mod establishing_channel;
pub mod lifecycle;
mod new_channel;
mod open_channel;
pub mod traits;

pub use closed_channel::{ChannelClosedReason, ClosedChannelState};
pub use closing_channel::{ClosingChannelState, StartCloseInfo, SuccessfulCloseInfo};
pub use disputing_channel::{DisputeOrigin, DisputeResolvedInfo, DisputingChannelState, ForceCloseInfo};
pub use establishing_channel::{Balances, EstablishingChannelState};
pub use lifecycle::{ChannelLifeCycle, LifecycleStage};
pub use new_channel::{ChannelSeedBuilder, ChannelSeedInfo, NewChannelBuilder, NewChannelState, ProposedChannelInfo};
pub use open_channel::EstablishedChannelState;
