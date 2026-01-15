//! Grease v2 - Modular coordinator-based client architecture.
//!
//! This module provides a refactored implementation of the Grease P2P client with:
//! - Separate message types per protocol phase (proposal, establish, update, close)
//! - Protocol-specific network API traits
//! - Role-aware coordinators (initiator/responder patterns)
//!
//! # Module Structure
//!
//! - [`messages`] - Protocol-specific request/response enums
//! - [`network`] - Network API traits and implementation
//! - `coordinators` - Protocol phase coordinators (TODO)
//! - `client` - GreaseClientV2 orchestrator (TODO)

pub mod messages;
pub mod network;
