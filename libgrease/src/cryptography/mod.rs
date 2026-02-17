//! Cryptographic primitives for Grease payment channels.
//!
//! This module provides the cryptographic foundation for Grease, including zero-knowledge
//! proofs, cross-curve operations, and encryption primitives. Types are generally curve-agnostic
//! and protocol-independent where possible.
//!
//! # Architecture Overview
//!
//! ```text
//!                          ┌─────────────────────────────────────────────┐
//!                          │           Payment Channel Layer             │
//!                          └─────────────────────────────────────────────┘
//!                                              │
//!                                              ▼
//!     ┌──────────────────────────────────────────────────────────────────┐
//!     │                    VCOF (State Transitions)                      │
//!     │  ┌─────────────┐    ┌──────────────┐    ┌─────────────────────┐  │
//!     │  │    vcof     │───▶│  vcof_impls  │───▶│    noir_prover      │  │
//!     │  │  (traits)   │    │ (Grumpkin/   │    │  (circuit runner)   │  │
//!     │  │             │    │  Poseidon2)  │    │                     │  │
//!     │  └─────────────┘    └──────────────┘    └─────────────────────┘  │
//!     │         │                  │                      │              │
//!     │         ▼                  ▼                      ▼              │
//!     │  ┌─────────────────────────────────────────────────────────────┐ │
//!     │  │                      witness                                │ │
//!     │  │         (Cross-curve scalar representation)                 │ │
//!     │  │           Ed25519 ◀──────────────▶ SNARK curve              │ │
//!     │  └─────────────────────────────────────────────────────────────┘ │
//!     └──────────────────────────────────────────────────────────────────┘
//!                                              │
//!     ┌────────────────────────────────────────┼────────────────────────┐
//!     │              Cross-Curve Proofs        │                        │
//!     │  ┌─────────────┐    ┌──────────────┐   │   ┌─────────────────┐  │
//!     │  │    dleq     │    │vcf_snark_dleq│   │   │adapter_signature│  │
//!     │  │ (Ed25519 ↔  │    │ (SNARK-based │   │   │  (atomic swaps) │  │
//!     │  │  SF curve)  │    │  DLEQ VCOF)  │   │   │                 │  │
//!     │  └─────────────┘    └──────────────┘   │   └─────────────────┘  │
//!     └────────────────────────────────────────┴────────────────────────┘
//!                                              │
//!     ┌────────────────────────────────────────┼────────────────────────┐
//!     │              Encryption & Proofs       │                        │
//!     │  ┌─────────────┐    ┌──────────────┐   │   ┌─────────────────┐  │
//!     │  │ ecdh_encrypt│    │secret_encrypt│   │   │       pok       │  │
//!     │  │ (scalar     │    │ (role-tagged │   │   │ (Schnorr PoK,   │  │
//!     │  │  encryption)│    │  encryption) │   │   │  KES proofs)    │  │
//!     │  └─────────────┘    └──────────────┘   │   └─────────────────┘  │
//!     └────────────────────────────────────────┴────────────────────────┘
//!                                              │
//!     ┌────────────────────────────────────────┼────────────────────────┐
//!     │              Foundation                │                        │
//!     │  ┌─────────────┐    ┌──────────────┐   │   ┌─────────────────┐  │
//!     │  │    keys     │    │    commit    │   │                       │
//!     │  │ (Curve25519 │    │ (hash-based  │   │                       │
//!     │  │  keypairs)  │    │ commitments) │   │                       │
//!     │  └─────────────┘    └──────────────┘   │                       │
//!     └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Module Reference
//!
//! ## Core VCOF Infrastructure
//!
//! | Module           | Purpose                                                          |
//! |------------------|------------------------------------------------------------------|
//! | [`vcof`]         | Trait definitions for Verifiable Consecutive Oneway Functions    |
//! | [`vcof_impls`]   | Production implementations using Grumpkin curve + Poseidon2 hash |
//! | [`noir_prover`]  | Noir circuit execution and proof generation                      |
//! | [`witness`]      | [`CrossCurveScalar`] - scalars valid in both Ed25519 and SNARK fields |
//!
//! ## Cross-Curve Cryptography
//!
//! | Module                | Purpose                                                                      |
//! |-----------------------|------------------------------------------------------------------------------|
//! | [`dleq`]              | Discrete log equality proofs across curve pairs (Ed25519 ↔ BabyJubJub/Secp256k1/Grumpkin) |
//! | [`adapter_signature`] | Schnorr adapter signatures for atomic swap protocols                         |
//!
//! ## Encryption & Commitments
//!
//! | Module               | Purpose                                                      |
//! |----------------------|--------------------------------------------------------------|
//! | [`ecdh_encrypt`]     | Ephemeral ECDH encryption for scalar values                  |
//! | [`secret_encryption`]| Role-tagged secrets (Customer/Merchant) with ECDH encryption |
//! | [`pok`]              | Schnorr proofs of knowledge ([`SchnorrPoK`], [`KesPoK`])     |
//! | [`commit`]           | Hash-based commitments with configurable digest algorithms   |
//!
//! ## Key Management & Data Types
//!
//! | Module         | Purpose                                                        |
//! |----------------|----------------------------------------------------------------|
//! | [`keys`]       | Curve25519 secret/public key types for Monero wallet operations|
//!
//! # Curve Support
//!
//! The module supports multiple elliptic curves for different purposes:
//!
//! | Curve           | Field Size | Usage                                              |
//! |-----------------|------------|----------------------------------------------------|
//! | **Ed25519**     | ~253 bits  | Monero signatures, base curve for cross-curve proofs |
//! | **Grumpkin**    | ~254 bits  | SNARK-friendly curve (BN254 cycle), Noir circuits  |
//! | **BabyJubJub**  | ~251 bits  | SNARK-friendly curve (legacy support)              |
//! | **Secp256k1**   | ~256 bits  | Bitcoin/Ethereum compatibility                     |
//!
//! # Security Considerations
//!
//! - All secret scalars implement [`Zeroize`](zeroize::Zeroize) for secure memory cleanup
//! - Cross-curve scalar conversion requires careful handling of field order differences
//! - Identity point rejection prevents trivial forgery attacks in proofs

mod commit;
pub mod encryption_context;
pub mod secret_bytes;
pub mod serializable_secret;

pub mod adapter_signature;
pub mod dleq;
pub mod ecdh;
pub mod ecdh_encrypt;
pub mod keys;
#[cfg(feature = "mocks")]
pub mod mocks;
pub mod noir_prover;
pub mod pok;
pub mod secret_encryption;
pub mod vcof;
pub mod vcof_impls;
mod vcof_snark_dleq;
mod witness;
pub use commit::{Commit, HashCommitment256};
pub use witness::{convert_scalar_dleq, AsXmrPoint, CrossCurveError, CrossCurvePoints, CrossCurveScalar, Offset};
