//! Cryptographic primitives
//!
//! This module contains general structs and methods related to cryptography, proofs of knowledge and encryption.
//!
//! It is a fairly low-level module and as such, the types defined here are typically agnostic as to the specific
//! curves they are implemented on and are also generally ignorant of Grease Payment Channel protocols and
//! infrastructure.

mod commit;

pub mod adapter_signature;
pub mod dleq;
pub mod ecdh_encrypt;
pub mod keys;
#[cfg(feature = "mocks")]
pub mod mocks;
pub mod pok;
pub mod secret_encryption;
pub mod vcof;
mod vcof_snark_dleq;
mod witness;
pub mod zk_objects;

pub use commit::{Commit, HashCommitment256};
pub use witness::{ChannelWitness, WitnessError};
