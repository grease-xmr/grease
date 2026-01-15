//! Network API traits for Grease v2 coordinators.
//!
//! Each protocol phase has its own network API trait, enabling:
//! - Clear separation of concerns between coordinators
//! - Easy mocking for unit tests
//! - Type-safe method signatures per protocol
//!
//! # Traits
//!
//! - [`ProposalNetworkAPI`] - Channel proposal methods
//! - [`EstablishNetworkAPI`] - Wallet setup and KES methods
//! - [`UpdateNetworkAPI`] - Payment update methods
//! - [`CloseNetworkAPI`] - Channel closing methods
//!
//! # Implementation
//!
//! [`NetworkClientV2`] implements all traits using the underlying libp2p infrastructure.

mod client;
mod close_api;
mod establish_api;
mod proposal_api;
mod update_api;

pub use client::NetworkClientV2;
pub use close_api::CloseNetworkAPI;
pub use establish_api::EstablishNetworkAPI;
pub use proposal_api::ProposalNetworkAPI;
pub use update_api::UpdateNetworkAPI;
