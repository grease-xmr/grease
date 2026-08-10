//! Dual-base Feldman publicly verifiable secret sharing (PVSS) over Ed25519.
//!
//! This is the secret-sharing layer of the arbiter binding proof (`docs/src/40_arbiter.typ`, §"The binding proof" /
//! `ProveEncryptedOffset`). The offset `ω` is shared with a degree-`(t-1)` polynomial `f(x) = Σ a_j x^j` over `Z_ℓ`
//! with `a_0 = ω`, and the coefficients are committed on *two* Ed25519 bases at once:
//!
//! * `F_j = a_j·G` — the standard generator, so `F_0 = Q = ω·G` is the adaptor point by construction; and
//! * `F_j^B = a_j·B` — a second, independent base, so `F_0^B = Q^B = ω·B`.
//!
//! A Chaum–Pedersen `DLEQ_{G,B}(F_j, F_j^B)` per coefficient proves both commitment vectors carry the same
//! polynomial. Shares verify against either vector (`ω_k·G = Σ_j k^j F_j`, and likewise on `B`), and any `t`
//! consistent shares Lagrange-interpolate back to `f(0) = ω`.
//!
//! # The second base `B`
//!
//! [`SecondBase::grease_default`] derives a fixed, torsion-free, non-identity point with no known discrete-log
//! relation to `G`: hash `Blake2b-512(SECOND_BASE_DOMAIN_TAG || counter_le_u64)` for `counter = 0, 1, ...`, take the
//! first 32 bytes as a compressed Edwards y-coordinate, and accept the first decoding that is a canonical,
//! torsion-free point; the result is multiplied by the cofactor 8 (defence in depth — the decoder already rejects
//! torsion) and rejected if it is the identity. The constant is pinned by a known-answer test so it can never
//! silently change.
//!
//! **Open design item (deferred):** under FCMP++ the SA+L spend proof checks the offset against the re-randomized
//! key-image base, so the production `B` may become the key-image generator `I` itself or a per-broadcast
//! re-randomization. Which base is fixed, and how the offset composes with the FCMP++ spend proof, is explicitly out
//! of scope here; [`SecondBase::from_point`] exists so a caller can bind whichever `B` is fixed at update time.
//!
//! # Determinism
//!
//! [`share_from_seed`] derives every random choice (blinding coefficients and DLEQ nonces) from a caller-supplied
//! 32-byte seed via a domain-separated SHA-512 wide-reduction PRF, so re-running the prover reproduces the same
//! dealing byte-for-byte — the binding proof requires this, since a second proof over the same `ω` that opened a
//! different cut-and-choose subset would leak the offset. DLEQ nonces additionally bind the coefficient value
//! (RFC 6979 style), so reusing a seed with a different secret can never reuse a nonce. [`share_with_rng`] is the
//! non-deterministic path for tests: it samples a fresh seed and delegates.
//!
//! # DLEQ transcript
//!
//! The Fiat–Shamir challenge is taken from a `RecommendedTranscript` (Blake2b-based, every message length-prefixed
//! and labelled) with domain `b"Grease dual-base PVSS coefficient DLEQ v1"`, absorbing in order: `G`, `B`, the
//! coefficient index, `F_j`, `F_j^B`, and the nonce points `R_G = k·G`, `R_B = k·B`; the transcript challenge is then
//! wide-reduced to a scalar.

use blake2::{Blake2b512, Digest};
use ciphersuite::group::ff::{Field, PrimeField};
use ciphersuite::group::{Group, GroupEncoding};
use crate::Ed25519;
use ciphersuite::WrappedGroup;
use crate::cryptography::ciphersuite_ext::hash_to_F;
use dalek_ff_group::{EdwardsPoint, Scalar};
use flexible_transcript::{RecommendedTranscript, Transcript};
use rand_core::{CryptoRng, RngCore};
use std::collections::BTreeSet;
use std::sync::OnceLock;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

/// Domain tag for deriving the default second base `B`. Changing this changes the base — see the pinned
/// known-answer test.
pub const SECOND_BASE_DOMAIN_TAG: &[u8] = b"GREASE-PVSS-SECOND-BASE-v1";

/// Domain tag for the seed-expansion PRF used by [`share_from_seed`].
const PRF_DOMAIN_TAG: &[u8] = b"GREASE-PVSS-PRF-v1";

/// Transcript domain for the per-coefficient Chaum–Pedersen DLEQ.
const DLEQ_TRANSCRIPT_TAG: &[u8] = b"Grease dual-base PVSS coefficient DLEQ v1";

/// Domain tag for reducing the DLEQ transcript challenge to a scalar.
const DLEQ_CHALLENGE_TAG: &[u8] = b"GREASE-PVSS-DLEQ-CHALLENGE-v1";

#[derive(Debug, Error)]
pub enum PvssError {
    #[error("Invalid sharing parameters: need 1 <= t <= n, got t={threshold}, n={shares}")]
    InvalidThreshold { threshold: u32, shares: u32 },
    #[error("Share index {0} is invalid (indices run from 1)")]
    InvalidShareIndex(u32),
    #[error("Duplicate share index {0}")]
    DuplicateShareIndex(u32),
    #[error("At least one share is required for reconstruction")]
    NoShares,
    #[error("Point is the identity element")]
    IdentityPoint,
    #[error("Point is not torsion-free")]
    TorsionPoint,
    #[error("Share is inconsistent with the Feldman commitment vector")]
    ShareVerificationFailure,
    #[error("Coefficient DLEQ verification failed at index {0}")]
    DleqVerificationFailure(usize),
    #[error("Malformed commitments: {0}")]
    MalformedCommitments(String),
}

// ============================================================================
// Point and scalar hygiene helpers (reused by the binding-proof verifier)
// ============================================================================

/// True iff `P` lies in the prime-order subgroup, i.e. `ℓ·P = 0`.
pub fn is_torsion_free(point: &EdwardsPoint) -> bool {
    point.0.is_torsion_free()
}

/// True iff `bytes` is the canonical (least-residue mod `ℓ`) encoding of a scalar.
pub fn is_canonical_scalar(bytes: &[u8; 32]) -> bool {
    Option::<Scalar>::from(Scalar::from_repr(*bytes)).is_some()
}

/// Reject a point that is the identity or carries a torsion component.
pub fn check_point_hygiene(point: &EdwardsPoint) -> Result<(), PvssError> {
    if bool::from(point.is_identity()) {
        return Err(PvssError::IdentityPoint);
    }
    if !is_torsion_free(point) {
        return Err(PvssError::TorsionPoint);
    }
    Ok(())
}

// ============================================================================
// SecondBase
// ============================================================================

/// A second Ed25519 base `B`, independent of the standard generator `G`, that the Feldman commitments are
/// duplicated on. See the module docs for how the default is derived and why the FCMP++ base choice is deferred.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecondBase(EdwardsPoint);

impl SecondBase {
    /// The fixed Grease default base, derived once by domain-tagged hash-to-point and cached for the process
    /// lifetime. Torsion-free and non-identity by construction.
    pub fn grease_default() -> &'static SecondBase {
        static BASE: OnceLock<SecondBase> = OnceLock::new();
        BASE.get_or_init(|| SecondBase(derive_second_base(SECOND_BASE_DOMAIN_TAG)))
    }

    /// Wrap an externally fixed base (e.g. a future FCMP++ key-image base), enforcing point hygiene.
    pub fn from_point(point: EdwardsPoint) -> Result<Self, PvssError> {
        check_point_hygiene(&point)?;
        Ok(SecondBase(point))
    }

    pub fn point(&self) -> EdwardsPoint {
        self.0
    }
}

/// Hash-to-point: try `Blake2b-512(tag || counter)` for successive counters until 32 bytes decode to a canonical,
/// torsion-free, non-identity point. Runs once per process; the result is a fixed constant thereafter.
fn derive_second_base(domain_tag: &[u8]) -> EdwardsPoint {
    (0u64..u64::MAX)
        .find_map(|counter| candidate_base_point(domain_tag, counter))
        .expect("hash-to-point search terminates (each counter succeeds with probability ~1/8)")
}

fn candidate_base_point(domain_tag: &[u8], counter: u64) -> Option<EdwardsPoint> {
    let digest = Blake2b512::new().chain_update(domain_tag).chain_update(counter.to_le_bytes()).finalize();
    let mut repr = [0u8; 32];
    repr.copy_from_slice(&digest[..32]);
    // `from_bytes` already rejects non-canonical encodings and torsion; the cofactor multiplication is defence in
    // depth and keeps the derivation safe even under a laxer decoder.
    Option::<EdwardsPoint>::from(EdwardsPoint::from_bytes(&repr))
        .map(|p| EdwardsPoint(p.mul_by_cofactor()))
        .filter(|p| !bool::from(p.is_identity()))
}

// ============================================================================
// Dealing structures
// ============================================================================

/// A share `ω_k = f(k)` of the secret, indexed from 1.
#[derive(Clone, Debug, PartialEq, Eq, Zeroize)]
pub struct Share {
    pub index: u32,
    pub value: Scalar,
}

/// Feldman commitments to the polynomial coefficients on both bases: `g[j] = a_j·G` and `b[j] = a_j·B`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DualFeldmanCommitments {
    pub g: Vec<EdwardsPoint>,
    pub b: Vec<EdwardsPoint>,
}

impl DualFeldmanCommitments {
    /// The sharing threshold `t` (the number of committed coefficients).
    pub fn threshold(&self) -> u32 {
        self.g.len() as u32
    }

    /// `F_0 = ω·G` — the adaptor point `Q` the sharing is bound to.
    pub fn q(&self) -> &EdwardsPoint {
        &self.g[0]
    }

    /// `F_0^B = ω·B` — the second-base adaptor point `Q^B`.
    pub fn q_b(&self) -> &EdwardsPoint {
        &self.b[0]
    }

    /// The share point `Σ_j k^j F_j` a valid share at `index` must match on `G`.
    pub fn share_point_g(&self, index: u32) -> EdwardsPoint {
        evaluate_in_exponent(&self.g, index)
    }

    /// The share point `Σ_j k^j F_j^B` a valid share at `index` must match on `B`.
    pub fn share_point_b(&self, index: u32) -> EdwardsPoint {
        evaluate_in_exponent(&self.b, index)
    }
}

/// A Chaum–Pedersen proof that `F_j` (on `G`) and `F_j^B` (on `B`) commit to the same coefficient.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CoefficientDleq {
    pub challenge: Scalar,
    pub response: Scalar,
}

/// A complete dual-base Feldman dealing: both commitment vectors plus one DLEQ per coefficient.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PvssDealing {
    pub commitments: DualFeldmanCommitments,
    pub coefficient_dleqs: Vec<CoefficientDleq>,
}

impl PvssDealing {
    /// Verify the dealing's internal consistency: well-formed, hygienic commitment points on both bases and a valid
    /// `DLEQ_{G,B}(F_j, F_j^B)` for every coefficient. Target binding (`F_0 = Q_i`) is the caller's check.
    pub fn verify(&self, base: &SecondBase) -> Result<(), PvssError> {
        self.check_shape()?;
        self.commitments.g.iter().chain(self.commitments.b.iter()).try_for_each(check_point_hygiene)?;
        self.coefficient_dleqs
            .iter()
            .enumerate()
            .try_for_each(|(j, proof)| verify_coefficient_dleq(proof, j, &self.commitments.g[j], &self.commitments.b[j], base))
    }

    fn check_shape(&self) -> Result<(), PvssError> {
        let (g, b, d) = (self.commitments.g.len(), self.commitments.b.len(), self.coefficient_dleqs.len());
        if g == 0 {
            return Err(PvssError::MalformedCommitments("empty commitment vector".into()));
        }
        if g != b || g != d {
            return Err(PvssError::MalformedCommitments(format!("mismatched lengths: {g} on G, {b} on B, {d} DLEQs")));
        }
        Ok(())
    }
}

// ============================================================================
// Sharing
// ============================================================================

/// Deterministically share `secret` into `shares` shares with threshold `threshold`, deriving all randomness from
/// `seed`. Identical inputs reproduce the identical dealing byte-for-byte.
pub fn share_from_seed(
    secret: &Scalar,
    shares: u32,
    threshold: u32,
    seed: &[u8; 32],
    base: &SecondBase,
) -> Result<(PvssDealing, Vec<Share>), PvssError> {
    validate_parameters(shares, threshold)?;
    let coefficients = derive_coefficients(secret, threshold, seed);
    let g = coefficients.iter().map(|a| Ed25519::generator() * *a).collect::<Vec<_>>();
    let b = coefficients.iter().map(|a| base.point() * *a).collect::<Vec<_>>();
    let coefficient_dleqs = coefficients
        .iter()
        .enumerate()
        .map(|(j, a)| {
            let nonce = derive_dleq_nonce(seed, j as u64, a);
            prove_coefficient_dleq(a, j, base, &nonce)
        })
        .collect::<Vec<_>>();
    let share_values = (1..=shares)
        .map(|k| Share { index: k, value: evaluate_polynomial(&coefficients, k) })
        .collect::<Vec<_>>();
    let commitments = DualFeldmanCommitments { g, b };
    Ok((PvssDealing { commitments, coefficient_dleqs }, share_values))
}

/// RNG path for tests and non-reproducible callers: samples a fresh seed and delegates to [`share_from_seed`].
pub fn share_with_rng<R: RngCore + CryptoRng>(
    secret: &Scalar,
    shares: u32,
    threshold: u32,
    rng: &mut R,
    base: &SecondBase,
) -> Result<(PvssDealing, Vec<Share>), PvssError> {
    let mut seed = Zeroizing::new([0u8; 32]);
    rng.fill_bytes(seed.as_mut());
    share_from_seed(secret, shares, threshold, &seed, base)
}

/// Verify a share against both commitment vectors: `ω_k·G = Σ_j k^j F_j` and `ω_k·B = Σ_j k^j F_j^B`.
pub fn verify_share(share: &Share, commitments: &DualFeldmanCommitments, base: &SecondBase) -> Result<(), PvssError> {
    if share.index == 0 {
        return Err(PvssError::InvalidShareIndex(0));
    }
    let on_g = Ed25519::generator() * share.value == commitments.share_point_g(share.index);
    let on_b = base.point() * share.value == commitments.share_point_b(share.index);
    (on_g && on_b).then_some(()).ok_or(PvssError::ShareVerificationFailure)
}

/// Lagrange-interpolate `f(0)` from the given shares. Pass exactly `t` shares that verified against the commitment
/// vector; fewer shares interpolate a lower-degree polynomial and do not determine the secret.
pub fn reconstruct_secret(shares: &[Share]) -> Result<Scalar, PvssError> {
    validate_share_indices(shares)?;
    let secret = shares.iter().map(|s| s.value * lagrange_coefficient_at_zero(s.index, shares)).sum();
    Ok(secret)
}

fn validate_parameters(shares: u32, threshold: u32) -> Result<(), PvssError> {
    match threshold >= 1 && threshold <= shares {
        true => Ok(()),
        false => Err(PvssError::InvalidThreshold { threshold, shares }),
    }
}

fn validate_share_indices(shares: &[Share]) -> Result<(), PvssError> {
    if shares.is_empty() {
        return Err(PvssError::NoShares);
    }
    shares.iter().try_fold(BTreeSet::new(), |mut seen, s| match s.index {
        0 => Err(PvssError::InvalidShareIndex(0)),
        idx if !seen.insert(idx) => Err(PvssError::DuplicateShareIndex(idx)),
        _ => Ok(seen),
    })?;
    Ok(())
}

/// `λ_k(0) = Π_{m≠k} x_m / (x_m − x_k)` over the index set of `shares`.
fn lagrange_coefficient_at_zero(index: u32, shares: &[Share]) -> Scalar {
    let x_k = Scalar::from(index as u64);
    shares
        .iter()
        .filter(|s| s.index != index)
        .map(|s| Scalar::from(s.index as u64))
        .fold(Scalar::ONE, |acc, x_m| {
            // Spelled through `Field` because `curve25519_dalek::Scalar`'s inherent `invert` returns the
            // scalar directly and silently maps zero to zero.
            let inv = Field::invert(&(x_m - x_k)).expect("distinct share indices give a non-zero denominator");
            acc * x_m * inv
        })
}

/// Horner evaluation of `f(x) = Σ_j a_j x^j` at `x = index`.
fn evaluate_polynomial(coefficients: &[Scalar], index: u32) -> Scalar {
    let x = Scalar::from(index as u64);
    coefficients.iter().rev().fold(Scalar::ZERO, |acc, a| acc * x + a)
}

/// Horner evaluation "in the exponent": `Σ_j x^j F_j` for a commitment vector `{F_j}`.
fn evaluate_in_exponent(commitments: &[EdwardsPoint], index: u32) -> EdwardsPoint {
    let x = Scalar::from(index as u64);
    commitments.iter().rev().fold(EdwardsPoint::identity(), |acc, f| acc * x + *f)
}

/// Coefficients `a_0 = ω`, `a_j = PRF(seed, "coefficient", j)` for `j = 1..t`.
fn derive_coefficients(secret: &Scalar, threshold: u32, seed: &[u8; 32]) -> Zeroizing<Vec<Scalar>> {
    let blinding = (1..threshold as u64).map(|j| prf_scalar(seed, b"coefficient", j, &[]));
    Zeroizing::new(std::iter::once(*secret).chain(blinding).collect())
}

/// DLEQ nonce for coefficient `j`, bound to the coefficient's value (RFC 6979 style) so a reused seed with a
/// different secret can never reuse a nonce.
fn derive_dleq_nonce(seed: &[u8; 32], j: u64, coefficient: &Scalar) -> Zeroizing<Scalar> {
    Zeroizing::new(prf_scalar(seed, b"dleq-nonce", j, &coefficient.to_repr()))
}

/// Wide-reduction PRF: SHA-512 over a length-prefixed encoding of `(seed, label, counter, bound)`, reduced mod `ℓ`.
fn prf_scalar(seed: &[u8; 32], label: &[u8], counter: u64, bound: &[u8]) -> Scalar {
    let mut data = Vec::with_capacity(32 + 8 + label.len() + 8 + 8 + bound.len());
    data.extend_from_slice(seed);
    data.extend_from_slice(&(label.len() as u64).to_le_bytes());
    data.extend_from_slice(label);
    data.extend_from_slice(&counter.to_le_bytes());
    data.extend_from_slice(&(bound.len() as u64).to_le_bytes());
    data.extend_from_slice(bound);
    hash_to_F::<Ed25519>(PRF_DOMAIN_TAG, &data)
}

// ============================================================================
// Per-coefficient Chaum–Pedersen DLEQ
// ============================================================================

/// Prove `DLEQ_{G,B}(a·G, a·B)` for coefficient `a` at position `index`, using the supplied nonce (the deterministic
/// prover derives it via the seed PRF; it must be unique per `(secret, coefficient)` pair).
pub fn prove_coefficient_dleq(coefficient: &Scalar, index: usize, base: &SecondBase, nonce: &Scalar) -> CoefficientDleq {
    let f_g = Ed25519::generator() * *coefficient;
    let f_b = base.point() * *coefficient;
    let r_g = Ed25519::generator() * *nonce;
    let r_b = base.point() * *nonce;
    let challenge = dleq_challenge(index, base, &f_g, &f_b, &r_g, &r_b);
    CoefficientDleq { challenge, response: *nonce + challenge * coefficient }
}

/// Verify `DLEQ_{G,B}(f_g, f_b)`: recompute `R_G = z·G − e·F_j`, `R_B = z·B − e·F_j^B` and check the Fiat–Shamir
/// challenge matches.
pub fn verify_coefficient_dleq(
    proof: &CoefficientDleq,
    index: usize,
    f_g: &EdwardsPoint,
    f_b: &EdwardsPoint,
    base: &SecondBase,
) -> Result<(), PvssError> {
    let r_g = Ed25519::generator() * proof.response - *f_g * proof.challenge;
    let r_b = base.point() * proof.response - *f_b * proof.challenge;
    let expected = dleq_challenge(index, base, f_g, f_b, &r_g, &r_b);
    (expected == proof.challenge).then_some(()).ok_or(PvssError::DleqVerificationFailure(index))
}

/// Fiat–Shamir challenge over a length-prefixed, labelled transcript. See the module docs for the exact shape.
fn dleq_challenge(
    index: usize,
    base: &SecondBase,
    f_g: &EdwardsPoint,
    f_b: &EdwardsPoint,
    r_g: &EdwardsPoint,
    r_b: &EdwardsPoint,
) -> Scalar {
    let mut t = RecommendedTranscript::new(DLEQ_TRANSCRIPT_TAG);
    t.append_message(b"generator_g", Ed25519::generator().to_bytes());
    t.append_message(b"generator_b", base.point().to_bytes());
    t.append_message(b"coefficient_index", (index as u64).to_le_bytes());
    t.append_message(b"commitment_g", f_g.to_bytes());
    t.append_message(b"commitment_b", f_b.to_bytes());
    t.append_message(b"nonce_g", r_g.to_bytes());
    t.append_message(b"nonce_b", r_b.to_bytes());
    hash_to_F::<Ed25519>(DLEQ_CHALLENGE_TAG, &t.challenge(b"challenge"))
}

#[cfg(test)]
mod test {
    use super::*;
    use rand_core::OsRng;

    fn test_secret() -> Scalar {
        hash_to_F::<Ed25519>(b"GREASE-PVSS-TEST", b"secret")
    }

    fn seeded_dealing(shares: u32, threshold: u32) -> (PvssDealing, Vec<Share>) {
        share_from_seed(&test_secret(), shares, threshold, &[7u8; 32], SecondBase::grease_default()).unwrap()
    }

    #[test]
    fn second_base_is_pinned_hygienic_and_cached() {
        let base = SecondBase::grease_default();
        check_point_hygiene(&base.point()).expect("default second base must be hygienic");
        assert_ne!(base.point(), Ed25519::generator());
        // Known-answer pin: if this fails, the base derivation changed and every existing commitment breaks.
        insta_pin(&hex::encode(base.point().to_bytes()));
        // Cached: same reference on every call
        assert!(std::ptr::eq(base, SecondBase::grease_default()));
    }

    // The pinned constant for SECOND_BASE_DOMAIN_TAG. Computed once from the derivation loop; never update this
    // without a deliberate, versioned domain-tag change.
    fn insta_pin(actual: &str) {
        assert_eq!(actual, SECOND_BASE_HEX, "second base constant changed");
    }

    const SECOND_BASE_HEX: &str = "0bd8c5c72d4755427edfab917e9e919bae6d4ed5fa26a0f26823d9787d9fd733";

    #[test]
    fn share_verify_reconstruct_round_trip() {
        let secret = test_secret();
        let base = SecondBase::grease_default();
        let (dealing, shares) = seeded_dealing(7, 4);
        dealing.verify(base).expect("honest dealing verifies");
        shares.iter().for_each(|s| verify_share(s, &dealing.commitments, base).expect("honest share verifies"));
        // F_0 = ω·G and F_0^B = ω·B by construction
        assert_eq!(*dealing.commitments.q(), Ed25519::generator() * secret);
        assert_eq!(*dealing.commitments.q_b(), base.point() * secret);
        // Any t consistent shares reconstruct ω
        assert_eq!(reconstruct_secret(&shares[0..4]).unwrap(), secret);
        assert_eq!(reconstruct_secret(&shares[3..7]).unwrap(), secret);
        let scattered = [shares[0].clone(), shares[2].clone(), shares[4].clone(), shares[6].clone()];
        assert_eq!(reconstruct_secret(&scattered).unwrap(), secret);
    }

    #[test]
    fn below_threshold_does_not_determine_the_secret() {
        let secret = test_secret();
        let (_, shares) = seeded_dealing(7, 4);
        // t-1 shares interpolate a lower-degree polynomial; its value at 0 is not ω
        assert_ne!(reconstruct_secret(&shares[0..3]).unwrap(), secret);
    }

    #[test]
    fn rng_path_round_trips() {
        let secret = test_secret();
        let base = SecondBase::grease_default();
        let (dealing, shares) = share_with_rng(&secret, 5, 3, &mut OsRng, base).unwrap();
        dealing.verify(base).unwrap();
        assert_eq!(reconstruct_secret(&shares[1..4]).unwrap(), secret);
    }

    #[test]
    fn deterministic_seed_reproduces_dealing_byte_for_byte() {
        let (dealing_a, shares_a) = seeded_dealing(6, 3);
        let (dealing_b, shares_b) = seeded_dealing(6, 3);
        assert_eq!(dealing_a, dealing_b);
        assert_eq!(shares_a, shares_b);
        // A different seed produces a different dealing (same F_0, different blinding)
        let (dealing_c, _) =
            share_from_seed(&test_secret(), 6, 3, &[8u8; 32], SecondBase::grease_default()).unwrap();
        assert_eq!(dealing_a.commitments.q(), dealing_c.commitments.q());
        assert_ne!(dealing_a, dealing_c);
    }

    #[test]
    fn dleq_rejects_mismatched_pairs_and_tampering() {
        let base = SecondBase::grease_default();
        let (dealing, _) = seeded_dealing(5, 3);
        let (f_g, f_b) = (dealing.commitments.g[1], dealing.commitments.b[1]);
        let proof = dealing.coefficient_dleqs[1];
        verify_coefficient_dleq(&proof, 1, &f_g, &f_b, base).expect("honest DLEQ verifies");
        // Mismatched pair: B-side commitment carries a different exponent
        let wrong_b = f_b + base.point();
        assert!(matches!(
            verify_coefficient_dleq(&proof, 1, &f_g, &wrong_b, base),
            Err(PvssError::DleqVerificationFailure(1))
        ));
        // Wrong coefficient index (transcript binding)
        assert!(verify_coefficient_dleq(&proof, 2, &f_g, &f_b, base).is_err());
        // Tampered response
        let tampered = CoefficientDleq { challenge: proof.challenge, response: proof.response + Scalar::ONE };
        assert!(verify_coefficient_dleq(&tampered, 1, &f_g, &f_b, base).is_err());
        // A dealing whose B-vector is inconsistent fails wholesale
        let mut bad = dealing.clone();
        bad.commitments.b[1] = wrong_b;
        assert!(bad.verify(base).is_err());
    }

    #[test]
    fn bad_shares_and_parameters_are_rejected() {
        let base = SecondBase::grease_default();
        let (dealing, shares) = seeded_dealing(5, 3);
        let mut bad_share = shares[0].clone();
        bad_share.value += Scalar::ONE;
        assert!(matches!(
            verify_share(&bad_share, &dealing.commitments, base),
            Err(PvssError::ShareVerificationFailure)
        ));
        let zero_index = Share { index: 0, value: shares[0].value };
        assert!(matches!(verify_share(&zero_index, &dealing.commitments, base), Err(PvssError::InvalidShareIndex(0))));
        assert!(matches!(reconstruct_secret(&[]), Err(PvssError::NoShares)));
        let dupes = [shares[0].clone(), shares[0].clone()];
        assert!(matches!(reconstruct_secret(&dupes), Err(PvssError::DuplicateShareIndex(1))));
        assert!(matches!(
            share_from_seed(&test_secret(), 3, 4, &[0u8; 32], base),
            Err(PvssError::InvalidThreshold { threshold: 4, shares: 3 })
        ));
        assert!(matches!(
            share_from_seed(&test_secret(), 3, 0, &[0u8; 32], base),
            Err(PvssError::InvalidThreshold { threshold: 0, shares: 3 })
        ));
    }

    #[test]
    fn hygiene_helpers() {
        use ciphersuite::group::Group;
        check_point_hygiene(&Ed25519::generator()).unwrap();
        assert!(matches!(check_point_hygiene(&EdwardsPoint::identity()), Err(PvssError::IdentityPoint)));
        // A point with a torsion component: G plus an 8-torsion point
        let torsioned = EdwardsPoint(Ed25519::generator().0 + curve25519_dalek::constants::EIGHT_TORSION[1]);
        assert!(!is_torsion_free(&torsioned));
        assert!(matches!(check_point_hygiene(&torsioned), Err(PvssError::TorsionPoint)));
        // Canonical scalars round-trip; the group order (and anything above) is rejected
        assert!(is_canonical_scalar(&Scalar::ONE.to_repr()));
        assert!(!is_canonical_scalar(&[0xff; 32]));
        let ell = [
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
        ];
        assert!(!is_canonical_scalar(&ell));
    }
}
