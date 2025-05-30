//! Finite state machine for Grease payment channels
//!
#![doc = include_str!("../../../docs/channel_lifecycle.md")]

//mod closed_channel;
//mod closing_channel;
mod disputing_channel;
// mod establishing_channel;
mod kes_verified;
//mod new_channel;
//mod open_channel;
mod wallet_created;
//pub mod lifecycle;
pub mod error;
pub mod traits;
pub mod wallet_state_machine;

//pub use closed_channel::{ChannelClosedReason, ClosedChannelState};
//pub use closing_channel::{ClosingChannelState, StartCloseInfo, SuccessfulCloseInfo};
pub use disputing_channel::{DisputeOrigin, DisputeResolvedInfo, DisputingChannelState, ForceCloseInfo};
// pub use establishing_channel::{ChannelInitSecrets, VssOutput};
//pub use lifecycle::{ChannelLifeCycle, LifecycleStage};
//pub use new_channel::{ChannelSeedBuilder, ChannelSeedInfo, NewChannelBuilder, NewChannelState, ProposedChannelInfo};
//pub use open_channel::EstablishedChannelState;
