//! The Grease Payment Channel Protocol
//!
//! This module contains the building blocks for the Grease Payment Channel Protocol.
//!
//! The modules define the supporting data structures and traits used throughout the protocol, including:
//! - [`crate::crypto::dleq`]: Implements the DLEQ proofs to prove equivalence of two keys across different curves.
//! - [`witness`]: The witness is the key piece of information protecting users' funds in the Grease protocol. This module
//!   defines the traits and data structures for representing and generating witnesses. The witness has a representation
//!   on both the KES and in Monero and the traits and methods defined in [`witness`] reflect this duality.
//! - [`pok`]: Schnorr proof-of-knowledge utilities
//!
//! Ed25519 curve.
//!
//! There are also several utility modules:
//! - [`commit`]: Defines traits that indicate that a data structure can be committed to using a cryptographic hash function.
//! - [`error`]: Defines error types used throughout the Grease protocol.
//! - [`tests`]: Unit tests for the Grease protocol.

pub mod error;
pub mod open_channel;
pub mod utils;

pub use crate::crypto::witness::{BjjWitness, Witness};

#[cfg(test)]
mod tests;
