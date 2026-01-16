//! Cryptographic primitives
//!
//! This module contains general structs and methods related to cryptography, proofs of knowledge and encryption.
//!
//! It is a fairly low-level module and as such, the types defined here are typically agnostic as to the specific
//! curves they are implemented on and are also generally ignorant of Grease Payment Channel protocols and
//! infrastructure.

mod commit;

pub mod adapter_signature;
pub mod common_types;
pub mod dleq;
pub mod hashes;
pub mod kes_functions;
pub mod keys;
pub mod pok;
pub mod secret_encryption;
pub mod vcof;
mod vcof_snark_dleq;
mod witness;
pub mod zk_objects;

pub use commit::Commit;
