//! Concrete VCOF implementations for Grease payment channels.
//!
//! This module provides production-ready implementations of the VCOF (Verifiable
//! Consecutive Oneway Function) abstraction, combining specific curve and hash
//! function choices optimized for the Grease protocol.
//!
//! # Available Implementations
//!
//! | Component     | Choice    | Rationale                                       |
//! |---------------|-----------|-------------------------------------------------|
//! | SNARK Curve   | Grumpkin  | BN254 cycle curve, native to Noir/Barretenberg  |
//! | Hash Function | Poseidon2 | ~8x fewer constraints than SHA256 in SNARKs     |
//! | Proof System  | Noir/ACIR | Compiles to UltraPlonk via Barretenberg         |
//!
//! # Module Structure
//!
//! - [`grease_noir`] - Noir circuit loading and input conversion
//! - [`grumpkin_poseidon2_next_witness`] - VCOF witness derivation using Poseidon2

mod grease_noir;
mod grumpkin_poseidon2_next_witness;

pub use grease_noir::{NoirUpdateCircuit, CHECKSUM_UPDATE, NOIR_UPDATE_CIRCUIT};
pub use grumpkin_poseidon2_next_witness::{GrumpkinPoseidonVcofError, PoseidonGrumpkinWitness};
