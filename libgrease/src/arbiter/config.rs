//! The arbiter parameters the two parties agree on when they negotiate a channel.
//!
//! Deliberately *not* part of the channel id: the arbiter is agreed between the parties but never committed into
//! the id transcript (see `docs/src/12_new_channel.typ` §channelId), so switching arbiters does not change a
//! channel's identity and the arbiter itself cannot be inferred from it.

use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::cryptography::attestation::G2Point;

/// The default adjudication window: 24 hours.
///
/// This absorbs the role of the retired `key_escrow_services::DEFAULT_DISPUTE_WINDOW`. The window is the delay an
/// honest unilateral close pays, and the time a defendant has to answer a stale presentation with a higher record;
/// it is measured against the arbiter platform's *consensus* clock, never a host's wall-clock.
pub const DEFAULT_DISPUTE_WINDOW: Duration = Duration::from_secs(24 * 60 * 60);

/// The arbiter a channel is bound to.
///
/// `master_public_key` is the committee's threshold-BLS public key `Z = z·G_2` on BLS12-381 — the key offsets are
/// verifiably encrypted against and the key attestations verify under. `canister_id` identifies the deployed
/// arbiter (an ICP canister principal in the reference instantiation) so a party can find the log and the
/// attestation endpoint. `dispute_window` is the per-channel adjudication window `dw`.
///
/// Two parties must hold *identical* configurations: an offset sealed to a different `Z` is undecryptable by the
/// counterparty's attestation, and mismatched windows give one party a wrong expectation of when a stale close can
/// still be answered. The proposal phase compares these for equality.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArbiterConfiguration {
    /// The arbiter committee's threshold-BLS master public key `Z` (BLS12-381 G2).
    pub master_public_key: G2Point,
    /// The deployed arbiter's identity — an ICP canister principal in the reference instantiation.
    pub canister_id: String,
    /// The adjudication window `dw`: how long the arbiter waits after a presentation before attesting.
    pub dispute_window: Duration,
}

impl ArbiterConfiguration {
    /// An arbiter configuration with an explicit dispute window.
    pub fn new(master_public_key: G2Point, canister_id: impl Into<String>, dispute_window: Duration) -> Self {
        ArbiterConfiguration { master_public_key, canister_id: canister_id.into(), dispute_window }
    }

    /// An arbiter configuration using [`DEFAULT_DISPUTE_WINDOW`].
    pub fn new_with_defaults(master_public_key: G2Point, canister_id: impl Into<String>) -> Self {
        Self::new(master_public_key, canister_id, DEFAULT_DISPUTE_WINDOW)
    }

    /// The committee's master public key `Z`.
    pub fn master_public_key(&self) -> &G2Point {
        &self.master_public_key
    }

    /// The deployed arbiter's identity.
    pub fn canister_id(&self) -> &str {
        &self.canister_id
    }

    /// The adjudication window.
    pub fn dispute_window(&self) -> Duration {
        self.dispute_window
    }

    /// The adjudication window in whole seconds — the unit the arbiter's consensus clock counts in.
    pub fn dispute_window_secs(&self) -> u64 {
        self.dispute_window.as_secs()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cryptography::attestation::test_helpers::generate_master_keypair;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    fn config() -> ArbiterConfiguration {
        let mut rng = ChaCha20Rng::seed_from_u64(11);
        let (_, big_z) = generate_master_keypair(&mut rng);
        ArbiterConfiguration::new_with_defaults(big_z, "rdmx6-jaaaa-aaaaa-aaadq-cai")
    }

    #[test]
    fn default_window_is_24_hours() {
        assert_eq!(DEFAULT_DISPUTE_WINDOW, Duration::from_secs(86_400));
        assert_eq!(config().dispute_window_secs(), 86_400);
    }

    #[test]
    fn serde_round_trip() {
        let cfg = config();
        let json = serde_json::to_string(&cfg).unwrap();
        let back: ArbiterConfiguration = serde_json::from_str(&json).unwrap();
        assert_eq!(cfg, back);
    }

    #[test]
    fn configurations_compare_on_every_field() {
        let cfg = config();
        let mut other = cfg.clone();
        other.canister_id = "aaaaa-aa".to_string();
        assert_ne!(cfg, other);
        let mut other = cfg.clone();
        other.dispute_window = Duration::from_secs(3600);
        assert_ne!(cfg, other);
        let mut rng = ChaCha20Rng::seed_from_u64(12);
        let (_, other_z) = generate_master_keypair(&mut rng);
        let mut other = cfg.clone();
        other.master_public_key = other_z;
        assert_ne!(cfg, other);
    }
}
