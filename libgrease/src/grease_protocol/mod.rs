//! The Grease Payment Channel Protocol
//!
//! This module contains the building blocks for the Grease Payment Channel Protocol, as well as the protocol itself.
//!
//! It is split into several modules. The [`protocol`] module contains generic procedures that describe the behaviour
//! for opening, updating, closing, force-closing, and disputing payment channels.
//!
//! The other modules define the supporting data structures and traits used throughout the protocol, including:
//! - [`dleq`]: Implements the DLEQ proofs to prove equivalence of two keys across different curves.
//! - [`witness`]: The witness is the key piece of information protecting users' funds in the Grease protocol. This module
//!   defines the traits and data structures for representing and generating witnesses. The witness has a representation
//!   on both the KES and in Monero and the traits and methods defined in [`witness`] reflect this duality.
//! Ed25519 curve.
//!
//! There are also several utility modules:
//! - [`commit`]: Defines traits that indicate that a data structure can be committed to using a cryptographic hash function.
//! - [`error`]: Defines error types used throughout the Grease protocol.
//! - ... TBC ...

pub mod protocol;

mod commit;
mod dleq;
pub mod error;
mod pok;
mod prover;
pub mod utils;
mod witness;

pub use commit::Commit;
pub use dleq::{Dleq, DleqMoneroBitcoin, DleqMoneroBjj, DleqProof};
pub use pok::{KesPoK, SchnorrPoK};
pub use prover::{ProveWitness, WitnessProofPreprocess};
pub use witness::{BjjWitness, Witness};

#[cfg(test)]
mod tests;
