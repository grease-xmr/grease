//! The v2 *arbiter*: the client-side abstraction over the off-chain dispute resolver, plus an in-process mock.
//!
//! The arbiter (see `docs/src/40_arbiter.typ`) is a deterministic state machine on a public consensus platform. It
//! holds no funds and no per-channel secret: all it does is accept cross-signed [`UpdateRecord`]s, track a
//! monotonically increasing high-water mark per channel behind an adjudication window, and — once that window
//! elapses — publish a threshold-BLS attestation of the *high-water statement* `m = (channel_id, high_water)`.
//! That attestation doubles as the decryption key for the offset each party sealed to `m`
//! (`cryptography/verifiable_encryption.rs`), which is why the arbiter can resolve a dispute while learning
//! nothing but an opaque id, an update count, and a close hash.
//!
//! This module ships three pieces:
//!
//! - [`config`] — [`ArbiterConfiguration`], the parameters the two parties agree on at proposal time: the
//!   committee's master public key `Z`, the canister/contract identity, and the dispute window.
//! - [`client`] — the [`ArbiterClient`] trait, the minimal surface the protocol layers need: submit a record, poll
//!   the per-channel dispute state and the public action log, and request the attestation. The production ICP
//!   client (an `ic-agent` implementation of this trait) is out of scope for the migration epic.
//! - [`mock`] — [`MockArbiter`], an in-process implementation of the dispute state machine (feature `mocks`), so
//!   the protocol tickets can test against real arbiter semantics without an ICP replica.
//!
//! [`UpdateRecord`]: crate::grease_protocol::update_record::UpdateRecord
//! [`ArbiterConfiguration`]: config::ArbiterConfiguration
//! [`ArbiterClient`]: client::ArbiterClient
//! [`MockArbiter`]: mock::MockArbiter

pub mod client;
pub mod config;
#[cfg(feature = "mocks")]
pub mod mock;

pub use client::{
    statement_for, ActionLogEntry, ArbiterClient, ArbiterError, DisputeStateView, LogAction, TransportPublicKey,
    WrappedAttestation,
};
pub use config::{ArbiterConfiguration, DEFAULT_DISPUTE_WINDOW};
#[cfg(feature = "mocks")]
pub use mock::{Clock, ManualClock, MockArbiter};
