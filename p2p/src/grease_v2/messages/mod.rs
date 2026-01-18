//! Protocol-specific message types for Grease v2.
//!
//! Each protocol phase has its own request/response enum, enabling:
//! - Type-safe message handling per protocol
//! - Separate libp2p behaviors per protocol
//! - Cleaner coordinator implementations
//!
//! # Protocol Phases
//!
//! - [`proposal`] - Channel proposal negotiation
//! - [`establish`] - Wallet setup, KES, and funding
//! - [`update`] - Payment state updates
//! - [`close`] - Cooperative channel closing

pub mod close;
pub mod establish;
pub mod proposal;
pub mod update;

pub use close::{CloseRequest, CloseResponse};
pub use establish::{EstablishRequest, EstablishResponse};
pub use proposal::{ProposalRequest, ProposalResponse};
pub use update::{UpdateRequest, UpdateResponse};
