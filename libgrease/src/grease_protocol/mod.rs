//! The Grease Payment Channel Protocol
//!
//! This module contains the building blocks for the Grease Payment Channel Protocol.

pub mod adapter_signature;
pub mod error;
pub mod kes;
pub mod multisig_wallet;
pub mod utils;

// Protocol modules
pub mod close_channel;
pub mod establish_channel;
pub mod force_close_channel;
pub mod propose_channel;
pub mod update_channel;

// Re-exports
pub use close_channel::*;
pub use establish_channel::*;
pub use force_close_channel::*;
pub use propose_channel::*;
pub use update_channel::*;
