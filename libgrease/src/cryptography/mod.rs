//! Cryptographic primitives for Grease payment channels.
//!
//! This module provides the cryptographic foundation for the v2 (arbiter) design: verifiable encryption of
//! adaptor offsets to a statement, the proof that binds a ciphertext to the adaptor point it claims to open,
//! and the BLS12-381 attestation the arbiter publishes to unlock it. Types are curve-agnostic and
//! protocol-independent where possible.
//!
//! # Architecture Overview
//!
//! ```text
//!                          ┌─────────────────────────────────────────────┐
//!                          │           Payment Channel Layer             │
//!                          │   update · cooperative close · dispute      │
//!                          └─────────────────────────────────────────────┘
//!                                              │
//!                       ω (fresh offset per state, per party)
//!                                              │
//!     ┌────────────────────────────────────────▼─────────────────────────┐
//!     │                Sealing an offset to a statement                  │
//!     │  ┌──────────────────┐    ┌──────────┐    ┌────────────────────┐  │
//!     │  │  binding_proof   │───▶│   pvss   │───▶│verifiable_encrypt. │  │
//!     │  │ (cut-and-choose: │    │ (dual-   │    │ (EncryptToStatement│  │
//!     │  │  ω ↔ Q = ω·G)    │    │  base    │    │  /DecryptWith-     │  │
//!     │  │                  │    │  Feldman)│    │   Attestation)     │  │
//!     │  └──────────────────┘    └──────────┘    └─────────┬──────────┘  │
//!     └────────────────────────────────────────────────────┼─────────────┘
//!                                                          │
//!                                    σ_m, the arbiter's attestation on m
//!                                                          │
//!     ┌────────────────────────────────────────────────────▼─────────────┐
//!     │                          attestation                             │
//!     │      BLS12-381 / vetKD-compatible: H_P, H_F, G_T, pairing check  │
//!     └──────────────────────────────────────────────────────────────────┘
//!
//!     ┌──────────────────────────────────────────────────────────────────┐
//!     │                    Signatures & proofs of knowledge              │
//!     │  ┌────────────────────┐             ┌──────────────────────────┐ │
//!     │  │ adapter_signature  │             │           pok            │ │
//!     │  │ (Schnorr adaptor;  │             │ (Schnorr proofs of       │ │
//!     │  │  ω completes it)   │             │  knowledge)              │ │
//!     │  └────────────────────┘             └──────────────────────────┘ │
//!     └──────────────────────────────────────────────────────────────────┘
//!
//!     ┌──────────────────────────────────────────────────────────────────┐
//!     │                            Foundation                            │
//!     │  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────────┐  │
//!     │  │   keys    │  │   commit  │  │    pok    │  │ecdh/ecdh_encr.│  │
//!     │  └───────────┘  └───────────┘  └───────────┘  └───────────────┘  │
//!     └──────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Module Reference
//!
//! ## Sealing an offset and opening it again
//!
//! | Module                    | Purpose                                                                          |
//! |---------------------------|----------------------------------------------------------------------------------|
//! | [`verifiable_encryption`] | `EncryptToStatement` / `DecryptWithAttestation` against the arbiter's master key  |
//! | [`pvss`]                  | Dual-base Feldman PVSS with per-coefficient DLEQs — the shares the seal carries   |
//! | [`binding_proof`]         | Cut-and-choose proof that the sealed shares open to ω with `Q = ω·G`, plus recovery |
//! | [`attestation`]           | BLS12-381 attestation plumbing (vetKD-compatible): H_P, H_F, G_T, pairing verify  |
//!
//! ## Signatures and proofs of knowledge
//!
//! | Module                | Purpose                                                                          |
//! |-----------------------|----------------------------------------------------------------------------------|
//! | [`adapter_signature`] | Schnorr adaptor signatures — the pre-signature an offset ω completes              |
//! | [`pok`]               | Schnorr proofs of knowledge                                                       |
//!
//! ## Encryption, commitments and keys
//!
//! | Module                 | Purpose                                                            |
//! |------------------------|--------------------------------------------------------------------|
//! | [`ecdh`]               | Shared-secret derivation between two parties                       |
//! | [`ecdh_encrypt`]       | Ephemeral ECDH encryption for scalar values                        |
//! | [`Commit`]             | Hash-based commitments with configurable digest algorithms         |
//! | [`keys`]               | Curve25519 secret/public key types for Monero wallet operations    |
//! | [`encryption_context`] | Ambient key material that encrypts secrets at rest on serialization |
//!
//! ## Binding the channel id to the shared wallet
//!
//! | Module          | Purpose                                                                             |
//! |-----------------|-------------------------------------------------------------------------------------|
//! | [`linking_tag`] | Proof that a party's contribution to the joint funding linking tag `L_F` is correct  |
//!
//! # Curve Support
//!
//! | Curve            | Usage                                                                       |
//! |------------------|-----------------------------------------------------------------------------|
//! | **Ed25519**      | Monero signatures, adaptor offsets, PVSS and the binding proof               |
//! | **BLS12-381**    | Arbiter master key, statement hashing and attestation verification (vetKD)   |
//!
//! # Security Considerations
//!
//! - All secret scalars implement [`Zeroize`](zeroize::Zeroize) for secure memory cleanup
//! - Identity point rejection prevents trivial forgery attacks in proofs
//! - Offsets are fresh and independent per state and per party; nothing is derived from a previous offset

mod commit;
pub mod ciphersuite_ext;
pub mod encryption_context;
pub mod secret_bytes;
mod secure_digest;
pub mod serializable_secret;

pub mod adapter_signature;
pub mod attestation;
pub mod binding_proof;
pub mod ecdh;
pub mod ecdh_encrypt;
pub mod keys;
pub mod linking_tag;
pub mod pok;
pub mod pvss;
pub mod verifiable_encryption;
pub use commit::{Commit, HashCommitment256, HashCommitment512};
pub use secure_digest::SecureDigest;
