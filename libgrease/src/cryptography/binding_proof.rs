//! The binding proof: `ProveEncryptedOffset` / `VerifyEncryptedOffset` (`docs/src/40_arbiter.typ`, §"The binding
//! proof", labels `proveOffset` / `verifyOffset`).
//!
//! A verifiably encrypted offset is worthless unless it is honest, so it travels with a non-interactive proof
//! establishing, as one statement, that
//!
//! 1. `(U, c)` is a well-formed [`EncryptedOffset`] under the arbiter's stable master key `Z`, addressed to
//!    *exactly* the statement `m = (channel_id, update_count)`; and
//! 2. the offset sealed inside is the discrete logarithm of the *very adaptor point* `Q` the recipient already
//!    holds in its pre-signature for that state.
//!
//! It must reveal nothing about `ω` — the recipient who learned `ω` at update time could complete the close
//! immediately, including one state later when it is stale. There is no cheap Σ-protocol for the relation (the
//! `H_F` mask destroys the algebraic structure a Σ-protocol would need, and proving the hash directly means a
//! pairing inside a SNARK over BLS12-381), so instead of proving the relation we *open a random, below-threshold
//! subset of an honest secret sharing* and recompute the hash in the clear on the opened shares.
//!
//! ```text
//! Prove(ω, m, Z, B; n, t):
//!   seed  ← PRF(ω, m, Z, B, n, t)                       -- no OS randomness anywhere
//!   f(x)  = ω + a_1 x + … + a_{t-1} x^{t-1}  over Z_ℓ    -- pvss::share_from_seed(seed)
//!   F_j   = a_j·G,  F_j^B = a_j·B,  DLEQ_{G,B}(F_j, F_j^B)
//!   (U_k, c_k) = EncryptToStatement(f(k), m, Z; r_k),    r_k = PRF(seed, "kem-exponent", k)
//!   I     = H_FS(dst, m, Z, B, {F_j}, {F_j^B}, {U_k}, {c_k}, n, t)   -- a (t−1)-subset of {1..n}
//!   open  = {(k, r_k, f(k))}_{k ∈ I}
//! ```
//!
//! # Determinism is a security property, not a convenience
//!
//! Every random choice is PRF-derived from `(ω, m, Z, B, n, t)`. Two proofs over the same offset that opened
//! *different* subsets would jointly reveal more than `t−1` shares and leak `ω`. [`prove_encrypted_offset`] takes
//! no RNG at all, and re-running it reproduces the same bytes. Note the second base is part of the seed input for
//! exactly this reason: a `B` change re-derives the whole polynomial, so the two proofs share only `a_0 = ω` and
//! each stays below its own threshold.
//!
//! # Parameters
//!
//! [`BindingProofParams::production`] is `(n, t) = (104, 53)`, so the opened subset has `t − 1 = 52` shares and a
//! dishonest bundle survives with probability `1/C(104, 52) ≈ 2^-100` (`q_H/C(n, t−1)` against a prover that
//! grinds Fiat–Shamir). Because a surviving cheat only *freezes* one update rather than stealing from it, that is
//! a deliberately generous margin — but `2^100` is the floor, not a nicety, precisely because the challenge is
//! grindable. [`BindingProofParams::soundness_bits`] reports `log2 C(n, t−1)` for any profile; tests use a small
//! profile for speed and pin the production one separately.
//!
//! # Verifier hygiene
//!
//! [`verify_encrypted_offset`] enforces, each rule independently observable through its own error:
//!
//! * every received Ed25519 point (`Q`, `Q^B`, all `F_j`, `F_j^B`) is non-identity and torsion-free;
//! * `B` is *recomputed locally* — it is never serialized into the proof and never taken from the wire;
//! * scalars are canonical (a `c_k ≥ ℓ` is rejected at the parse boundary, see [`BindingProof::from_bytes`]);
//! * **every** `U_k` is subgroup-checked, the `n − (t−1)` unopened ones included — cofactor torsion on a point
//!   nobody checks is Fiat–Shamir-grindable;
//! * no `U_k` repeats within a proof — a reused `r_k` would leak `ω_j − ω_k` and, across enough shares, `ω`.
//!
//! The checks run in an order chosen so that each rule fires its own error rather than being masked by a
//! downstream one: shape, then Ed25519 point hygiene, then target binding, then the DLEQs, then `U_k` hygiene,
//! then the Fiat–Shamir subset, and only then the openings (which are *not* absorbed into the challenge, so
//! tampering with an opening is observable on its own).
//!
//! # Wire size
//!
//! At `(104, 53)` the canonical encoding ([`BindingProof::to_bytes`]) is **23,641 bytes**, dominated by the 104
//! share ciphertexts at 128 bytes each (a 96-byte compressed G2 point plus a 32-byte scalar). That is somewhat
//! above the whitepaper's "≈20 KB" figure, which does not count the G2 encodings in full. The artifact travels on
//! *every* update, so the number is a standing per-update cost; a size regression test pins it, and
//! [`BindingProofParams::encoded_len`] gives the exact figure for any profile.

use ciphersuite::group::ff::{Field, PrimeField};
use ciphersuite::group::GroupEncoding;
use crate::Ed25519;
use ciphersuite::WrappedGroup;
use dalek_ff_group::{EdwardsPoint, Scalar};
use flexible_transcript::{RecommendedTranscript, Transcript};
use hex::ToHex;
use ic_bls12_381::Scalar as BlsScalar;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use std::collections::BTreeSet;
use thiserror::Error;
use zeroize::Zeroizing;

use super::attestation::{AttestationError, G1Point, G2Point, Statement, G2_COMPRESSED_LEN};
use super::pvss::{
    check_point_hygiene, reconstruct_secret, share_from_seed, verify_share, CoefficientDleq, DualFeldmanCommitments,
    PvssDealing, PvssError, SecondBase, Share,
};
use super::verifiable_encryption::{
    decrypt_with_attestation, encrypt_to_statement_with_r, EncryptedOffset, VerifiableEncryptionError,
};

/// Production share count `n` (`docs/src/40_arbiter.typ`, "Soundness budget").
pub const PRODUCTION_SHARES: u32 = 104;
/// Production threshold `t`; the opened subset has `t − 1 = 52` shares and `C(104, 52) ≈ 2^100`.
pub const PRODUCTION_THRESHOLD: u32 = 53;
/// Upper bound on `n`, so a hostile length header cannot make the parser allocate or hash unboundedly.
pub const MAX_SHARES: u32 = 4096;

/// Domain tag for the master seed PRF — the only source of randomness in the prover.
const SEED_DST: &[u8] = b"GREASE-BINDING-PROOF-SEED-v1";
/// Domain tag for seed expansion (PVSS sub-seed, per-share KEM exponents).
const PRF_DST: &[u8] = b"GREASE-BINDING-PROOF-PRF-v1";
/// Transcript domain for the Fiat–Shamir cut-and-choose challenge.
const FS_TRANSCRIPT_TAG: &[u8] = b"Grease binding proof cut-and-choose v1";
/// Domain tag for expanding the Fiat–Shamir challenge into subset draws.
const SUBSET_DST: &[u8] = b"GREASE-BINDING-PROOF-SUBSET-v1";
/// Version byte leading the canonical proof encoding.
const PROOF_ENCODING_VERSION: u8 = 1;

/// Bytes per Ed25519 point or scalar in the canonical encoding.
const ED_ELEMENT_LEN: usize = 32;
/// Bytes per encoded coefficient DLEQ: `challenge ‖ response`.
const DLEQ_LEN: usize = 2 * ED_ELEMENT_LEN;
/// Bytes per encoded opening: `u32-LE(index) ‖ r_k ‖ ω_k`.
const OPENING_LEN: usize = 4 + 32 + 32;
/// Bytes per encoded share ciphertext: `ser_G2(U_k) ‖ c_k`.
const CIPHERTEXT_LEN: usize = G2_COMPRESSED_LEN + ED_ELEMENT_LEN;
/// Bytes of fixed header: version, `n`, `t`.
const HEADER_LEN: usize = 1 + 4 + 4;

#[derive(Debug, Error)]
pub enum BindingProofError {
    #[error("invalid binding-proof parameters: need 2 <= t <= n <= {MAX_SHARES}, got n={shares}, t={threshold}")]
    InvalidParameters { shares: u32, threshold: u32 },
    #[error("the proof is malformed: {0}")]
    Malformed(String),
    #[error("the offset is zero, which would make the adaptor point the identity")]
    ZeroOffset,
    #[error(transparent)]
    Pvss(#[from] PvssError),
    #[error(transparent)]
    Encryption(#[from] VerifiableEncryptionError),
    #[error(transparent)]
    Attestation(#[from] AttestationError),
    #[error("target binding failed: F_0 is not the adaptor point Q")]
    TargetMismatch,
    #[error("target binding failed: F_0^B is not the second-base adaptor point Q^B")]
    TargetMismatchSecondBase,
    #[error("the opened subset does not match the Fiat-Shamir challenge")]
    SubsetMismatch,
    #[error("opened share {0} does not reproduce its ciphertext")]
    OpeningMismatch(u32),
    #[error("the KEM exponent revealed for opened share {0} is zero")]
    ZeroKemExponent(u32),
    #[error("the KEM point U for share {0} is the group identity")]
    IdentityKemPoint(u32),
    #[error("the KEM point U for share {0} is outside the prime-order G2 subgroup")]
    KemPointNotInSubgroup(u32),
    #[error("the KEM point U is repeated within the proof, which leaks the offset")]
    DuplicateKemPoint,
    #[error("opening indices must be strictly ascending and lie in 1..=n")]
    InvalidOpeningIndices,
    #[error("proof encoding has the wrong length: expected {expected} bytes, got {actual}")]
    InvalidLength { expected: usize, actual: usize },
    #[error("unsupported proof encoding version {0}")]
    UnsupportedVersion(u8),
    #[error("non-canonical scalar in the proof encoding")]
    NonCanonicalScalar,
    #[error("invalid Ed25519 point in the proof encoding (non-canonical, torsioned, or off-curve)")]
    InvalidPoint,
    #[error("invalid hex encoding: {0}")]
    InvalidHex(String),
    #[error("no sealed ciphertext decrypted to a share consistent with the commitments")]
    NoRecoverableShare,
    #[error("the interpolated offset does not satisfy omega.G = Q")]
    RecoveredOffsetMismatch,
}

//--------------------------------------------------------------------------------------------------------------------
//                                                    Parameters
//--------------------------------------------------------------------------------------------------------------------

/// The cut-and-choose profile `(n, t)`: `n` shares dealt, threshold `t`, `t − 1` of them opened.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BindingProofParams {
    shares: u32,
    threshold: u32,
}

impl BindingProofParams {
    /// The production profile `(104, 53)`: 52 opened shares, `C(104, 52) ≈ 2^100`.
    pub const fn production() -> Self {
        BindingProofParams { shares: PRODUCTION_SHARES, threshold: PRODUCTION_THRESHOLD }
    }

    /// A profile with an explicit `(n, t)`. Requires `2 <= t <= n <= MAX_SHARES`: `t >= 2` so at least one share is
    /// opened, and `n >= t` so at least one ciphertext stays sealed for the dispute path to decrypt.
    pub fn new(shares: u32, threshold: u32) -> Result<Self, BindingProofError> {
        let params = BindingProofParams { shares, threshold };
        params.validate()?;
        Ok(params)
    }

    pub fn shares(&self) -> u32 {
        self.shares
    }

    pub fn threshold(&self) -> u32 {
        self.threshold
    }

    /// The size of the opened subset, `t − 1`.
    pub fn opened(&self) -> u32 {
        self.threshold - 1
    }

    /// The number of ciphertexts that stay sealed, `n − (t − 1)` — the verifiably encrypted offset proper.
    pub fn sealed(&self) -> u32 {
        self.shares - self.opened()
    }

    /// `log2 C(n, t − 1)`: the bits of statistical soundness a Fiat–Shamir-grinding prover must overcome.
    pub fn soundness_bits(&self) -> f64 {
        (0..u64::from(self.opened()))
            .map(|i| ((f64::from(self.shares) - i as f64) / (i as f64 + 1.0)).log2())
            .sum()
    }

    /// The exact length of the canonical encoding of a proof with this profile: header, the two commitment
    /// vectors, one DLEQ per coefficient, `n` ciphertexts and `t − 1` openings.
    pub fn encoded_len(&self) -> usize {
        let (n, t) = (self.shares as usize, self.threshold as usize);
        let commitments = 2 * t * ED_ELEMENT_LEN;
        let dleqs = t * DLEQ_LEN;
        HEADER_LEN + commitments + dleqs + n * CIPHERTEXT_LEN + (t - 1) * OPENING_LEN
    }

    fn validate(&self) -> Result<(), BindingProofError> {
        let ok = self.threshold >= 2 && self.threshold <= self.shares && self.shares <= MAX_SHARES;
        ok.then_some(()).ok_or(BindingProofError::InvalidParameters { shares: self.shares, threshold: self.threshold })
    }
}

//--------------------------------------------------------------------------------------------------------------------
//                                                     The proof
//--------------------------------------------------------------------------------------------------------------------

/// One opened share: the index `k`, the KEM exponent `r_k` that produced `(U_k, c_k)`, and the share `ω_k = f(k)`.
///
/// Openings are *not* absorbed into the Fiat–Shamir challenge (they are derived from it), which is what makes a
/// tampered opening observable on its own rather than as a subset mismatch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShareOpening {
    index: u32,
    kem_exponent: BlsScalar,
    share: Scalar,
}

impl ShareOpening {
    pub fn index(&self) -> u32 {
        self.index
    }

    pub fn kem_exponent(&self) -> &BlsScalar {
        &self.kem_exponent
    }

    /// The revealed share `ω_k = f(k)`. Below-threshold and independent of `ω`, so publishing it is safe.
    pub fn share(&self) -> &Scalar {
        &self.share
    }
}

/// A complete binding proof: the dual-base dealing with its coefficient DLEQs, all `n` share ciphertexts, and the
/// `t − 1` openings the Fiat–Shamir challenge selected.
///
/// The second base `B` is deliberately absent: the verifier recomputes it locally.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BindingProof {
    params: BindingProofParams,
    dealing: PvssDealing,
    ciphertexts: Vec<EncryptedOffset>,
    openings: Vec<ShareOpening>,
}

impl BindingProof {
    pub fn params(&self) -> &BindingProofParams {
        &self.params
    }

    /// The dual-base Feldman dealing: commitments `{F_j}`, `{F_j^B}` and their coefficient DLEQs.
    pub fn dealing(&self) -> &PvssDealing {
        &self.dealing
    }

    /// The commitment vectors, against which a decrypted share is checked on the dispute path.
    pub fn commitments(&self) -> &DualFeldmanCommitments {
        &self.dealing.commitments
    }

    /// All `n` share ciphertexts, indexed so that share `k` sits at position `k − 1`.
    pub fn ciphertexts(&self) -> &[EncryptedOffset] {
        &self.ciphertexts
    }

    /// The `t − 1` opened shares, in ascending index order.
    pub fn openings(&self) -> &[ShareOpening] {
        &self.openings
    }

    /// `F_0 = ω·G` — the adaptor point this proof binds the sealed offset to.
    pub fn q(&self) -> &EdwardsPoint {
        self.dealing.commitments.q()
    }

    /// `F_0^B = ω·B` — the second-base adaptor point.
    pub fn q_b(&self) -> &EdwardsPoint {
        self.dealing.commitments.q_b()
    }

    /// The ciphertext for share `k` (indices run from 1).
    pub fn ciphertext(&self, index: u32) -> Option<&EncryptedOffset> {
        (index >= 1).then(|| self.ciphertexts.get((index - 1) as usize)).flatten()
    }

    /// The indices whose ciphertexts stayed sealed — the ones the dispute path decrypts.
    pub fn sealed_indices(&self) -> Vec<u32> {
        let opened = self.openings.iter().map(|o| o.index).collect::<BTreeSet<_>>();
        (1..=self.params.shares).filter(|k| !opened.contains(k)).collect()
    }

    /// Structural consistency: vector lengths against `(n, t)`, and opening indices strictly ascending within
    /// `1..=n` (which also rules out a repeated index).
    fn check_shape(&self) -> Result<(), BindingProofError> {
        self.params.validate()?;
        let (n, t, opened) = (self.params.shares as usize, self.params.threshold as usize, self.params.opened() as usize);
        let lengths = [
            ("commitments on G", self.dealing.commitments.g.len(), t),
            ("commitments on B", self.dealing.commitments.b.len(), t),
            ("coefficient DLEQs", self.dealing.coefficient_dleqs.len(), t),
            ("share ciphertexts", self.ciphertexts.len(), n),
            ("openings", self.openings.len(), opened),
        ];
        lengths.iter().try_for_each(|(what, actual, expected)| match actual == expected {
            true => Ok(()),
            false => Err(BindingProofError::Malformed(format!("{what}: expected {expected}, got {actual}"))),
        })?;
        let ascending = self.openings.windows(2).all(|w| w[0].index < w[1].index);
        let in_range = self.openings.first().is_none_or(|o| o.index >= 1)
            && self.openings.last().is_none_or(|o| o.index <= self.params.shares);
        (ascending && in_range).then_some(()).ok_or(BindingProofError::InvalidOpeningIndices)
    }

    /// Wire hygiene for the KEM points: non-identity, in the prime-order G2 subgroup, and pairwise distinct —
    /// applied to **all** `n` points, the unopened ones included.
    fn check_kem_points(&self) -> Result<(), BindingProofError> {
        let mut seen = BTreeSet::new();
        self.ciphertexts.iter().enumerate().try_for_each(|(i, ct)| {
            let index = i as u32 + 1;
            let u = ct.u();
            if u.is_identity() {
                return Err(BindingProofError::IdentityKemPoint(index));
            }
            if !bool::from(u.as_affine().is_torsion_free()) {
                return Err(BindingProofError::KemPointNotInSubgroup(index));
            }
            seen.insert(u.to_compressed()).then_some(()).ok_or(BindingProofError::DuplicateKemPoint)
        })
    }
}

//--------------------------------------------------------------------------------------------------------------------
//                                                      Prove
//--------------------------------------------------------------------------------------------------------------------

/// `ProveEncryptedOffset(ω, m, Z; n, t)` — seal `ω` to the statement `m` under `Z` and prove it is the discrete
/// logarithm of `ω·G` (and `ω·B`).
///
/// The adaptor points `Q = ω·G` and `Q^B = ω·B` are *derived*, not accepted as arguments: they are `F_0` and
/// `F_0^B` of the dealing by construction, so there is no way for a caller to produce a proof that binds a target
/// it does not actually know the discrete log of. Read them back with [`BindingProof::q`] / [`BindingProof::q_b`].
///
/// Takes no RNG: every choice is PRF-derived (see the module docs on why that is a security property).
pub fn prove_encrypted_offset(
    omega: &Scalar,
    statement: &Statement,
    master_pk: &G2Point,
    base: &SecondBase,
    params: BindingProofParams,
) -> Result<BindingProof, BindingProofError> {
    params.validate()?;
    if bool::from(omega.is_zero()) {
        return Err(BindingProofError::ZeroOffset);
    }
    let seed = derive_master_seed(omega, statement, master_pk, base, &params);
    let pvss_seed = expand_seed(&seed, b"pvss-seed");
    let (dealing, shares) = share_from_seed(omega, params.shares, params.threshold, &pvss_seed, base)?;
    let exponents = (1..=params.shares).map(|k| derive_kem_exponent(&seed, k)).collect::<Vec<_>>();
    let ciphertexts = shares
        .iter()
        .zip(exponents.iter())
        .map(|(share, r)| encrypt_to_statement_with_r(&share.value, statement, master_pk, r))
        .collect::<Result<Vec<_>, _>>()?;
    let challenge = fiat_shamir_challenge(statement, master_pk, base, &dealing, &ciphertexts, &params);
    let openings = derive_subset(&challenge, params.shares, params.opened())
        .into_iter()
        .map(|k| ShareOpening {
            index: k,
            kem_exponent: exponents[(k - 1) as usize],
            share: shares[(k - 1) as usize].value,
        })
        .collect::<Vec<_>>();
    Ok(BindingProof { params, dealing, ciphertexts, openings })
}

//--------------------------------------------------------------------------------------------------------------------
//                                                      Verify
//--------------------------------------------------------------------------------------------------------------------

/// `VerifyEncryptedOffset` — check a binding proof against the adaptor points the caller already holds.
///
/// `base` is supplied by the caller and recomputed locally ([`SecondBase::grease_default`] in production); it is
/// never read from the proof.
pub fn verify_encrypted_offset(
    proof: &BindingProof,
    statement: &Statement,
    master_pk: &G2Point,
    q: &EdwardsPoint,
    q_b: &EdwardsPoint,
    base: &SecondBase,
) -> Result<(), BindingProofError> {
    proof.check_shape()?;
    // Point hygiene on the caller-supplied targets first: a torsioned Q would otherwise be laundered into a
    // "target mismatch", hiding which rule actually failed.
    check_point_hygiene(q)?;
    check_point_hygiene(q_b)?;
    // 1. Target binding — unconditional.
    if proof.dealing.commitments.q() != q {
        return Err(BindingProofError::TargetMismatch);
    }
    if proof.dealing.commitments.q_b() != q_b {
        return Err(BindingProofError::TargetMismatchSecondBase);
    }
    // 2. Both bases: hygiene on every F_j / F_j^B, and every coefficient DLEQ.
    proof.dealing.verify(base)?;
    // 5. KEM point hygiene over all n ciphertexts, before the challenge so a duplicate or torsioned U reports
    //    itself rather than surfacing as a subset mismatch.
    proof.check_kem_points()?;
    // 3. Challenge: recompute I and confirm it is exactly the opened set.
    let challenge = fiat_shamir_challenge(statement, master_pk, base, &proof.dealing, &proof.ciphertexts, &proof.params);
    let expected = derive_subset(&challenge, proof.params.shares, proof.params.opened());
    let opened = proof.openings.iter().map(|o| o.index).collect::<BTreeSet<_>>();
    if opened != expected {
        return Err(BindingProofError::SubsetMismatch);
    }
    // 4. Opened shares.
    proof.openings.iter().try_for_each(|opening| verify_opening(proof, opening, statement, master_pk, base))
}

/// Recompute an opened share's ciphertext from the revealed `(r_k, ω_k)` and check the share against both
/// commitment vectors.
///
/// Re-running `EncryptToStatement` covers `U_k = r_k·G_2`, `y_k = e(H_P(m), Z)^{r_k}`, `s_k = H_F(y_k)` and
/// `c_k = (ω_k + s_k) mod ℓ` in one comparison; [`verify_share`] then covers `ω_k·G = Σ_j k^j F_j` on both bases.
fn verify_opening(
    proof: &BindingProof,
    opening: &ShareOpening,
    statement: &Statement,
    master_pk: &G2Point,
    base: &SecondBase,
) -> Result<(), BindingProofError> {
    if bool::from(opening.kem_exponent.is_zero()) {
        return Err(BindingProofError::ZeroKemExponent(opening.index));
    }
    let expected = proof.ciphertext(opening.index).ok_or(BindingProofError::InvalidOpeningIndices)?;
    let recomputed = encrypt_to_statement_with_r(&opening.share, statement, master_pk, &opening.kem_exponent)?;
    if &recomputed != expected {
        return Err(BindingProofError::OpeningMismatch(opening.index));
    }
    let share = Share { index: opening.index, value: opening.share };
    verify_share(&share, &proof.dealing.commitments, base).map_err(BindingProofError::from)
}

//--------------------------------------------------------------------------------------------------------------------
//                                                 Dispute recovery
//--------------------------------------------------------------------------------------------------------------------

/// The claimant-side dispute routine (`docs/src/40_arbiter.typ`, §"The dispute in practice"): turn the arbiter's
/// attestation `σ_m = z·H_P(m)` into the counterparty's offset `ω`.
///
/// The claimant already holds `t − 1` shares in the clear — the proof's openings — so it needs exactly *one* good
/// unopened ciphertext to reach the threshold. It decrypts sealed ciphertexts, `ω_k = (c_k − H_F(e(σ_m, U_k))) mod
/// ℓ`, keeps the first `ω_k` that satisfies `ω_k·G = Σ_j k^j F_j`, Lagrange-interpolates `f(0)` from the resulting
/// `t` points, and confirms `ω·G = Q`.
///
/// Iterating rather than trusting the first decryption is what makes recovery robust: a prover that survived the
/// cut-and-choose (probability `1/C(n, t−1)`) did so with *some* garbage unopened ciphertexts, and decryption
/// itself cannot report that — a wrong key or a doctored `c_k` yields a uniformly wrong scalar, never an error.
/// Only the share-consistency check separates the two, so it, not the decryption, is the filter.
///
/// Errors [`BindingProofError::NoRecoverableShare`] when every sealed ciphertext is garbage — the frozen-update
/// case, and equally what a `σ_m` for the wrong statement or the wrong master key produces — and
/// [`BindingProofError::RecoveredOffsetMismatch`] if the interpolation misses `Q`, which means the openings the
/// proof carries are not on the committed polynomial.
///
/// Call [`verify_encrypted_offset`] on the proof when it arrives, not here: recovery happens at dispute time on an
/// artifact accepted at update time, and its own two checks are against the commitments either way.
pub fn recover_offset(proof: &BindingProof, statement: &Statement, sigma: &G1Point) -> Result<Scalar, BindingProofError> {
    proof.check_shape()?;
    let threshold_point = proof
        .sealed_indices()
        .into_iter()
        .find_map(|k| decrypt_consistent_share(proof, k, statement, sigma))
        .ok_or(BindingProofError::NoRecoverableShare)?;
    let points = proof
        .openings()
        .iter()
        .map(|o| Share { index: o.index, value: o.share })
        .chain(std::iter::once(threshold_point))
        .collect::<Vec<_>>();
    let omega = reconstruct_secret(&points)?;
    match Ed25519::generator() * omega == *proof.q() {
        true => Ok(omega),
        false => Err(BindingProofError::RecoveredOffsetMismatch),
    }
}

/// Decrypt the ciphertext at `k` and return the share only if it lies on the committed polynomial.
///
/// The check is on the `G` vector alone, as the spec states: the dealing's coefficient DLEQs already tie the `B`
/// vector to the same polynomial, so a share consistent on `G` is consistent on `B` too.
fn decrypt_consistent_share(proof: &BindingProof, k: u32, statement: &Statement, sigma: &G1Point) -> Option<Share> {
    let value = decrypt_with_attestation(proof.ciphertext(k)?, statement, sigma).ok()?;
    let consistent = Ed25519::generator() * value == proof.commitments().share_point_g(k);
    consistent.then_some(Share { index: k, value })
}

//--------------------------------------------------------------------------------------------------------------------
//                                            Deterministic derivations
//--------------------------------------------------------------------------------------------------------------------

/// The master seed: `SHA-512(dst ‖ ω ‖ m ‖ Z ‖ B ‖ n ‖ t)` truncated to 32 bytes.
///
/// `B` is in the input so that re-proving the same `(ω, m, Z)` under a different second base re-derives an
/// *independent* polynomial; two proofs then share only `a_0 = ω` and each stays below its own threshold.
fn derive_master_seed(
    omega: &Scalar,
    statement: &Statement,
    master_pk: &G2Point,
    base: &SecondBase,
    params: &BindingProofParams,
) -> Zeroizing<[u8; 32]> {
    let m = statement.to_bytes();
    let digest = Sha512::new()
        .chain_update((SEED_DST.len() as u64).to_le_bytes())
        .chain_update(SEED_DST)
        .chain_update(omega.to_repr())
        .chain_update((m.len() as u64).to_le_bytes())
        .chain_update(m)
        .chain_update(master_pk.to_compressed())
        .chain_update(base.point().to_bytes())
        .chain_update(params.shares.to_le_bytes())
        .chain_update(params.threshold.to_le_bytes())
        .finalize();
    let mut seed = Zeroizing::new([0u8; 32]);
    seed.copy_from_slice(&digest[..32]);
    seed
}

/// Domain-separated seed expansion: `SHA-512(dst ‖ seed ‖ label ‖ a ‖ b)`.
fn prf_bytes(seed: &[u8; 32], label: &[u8], a: u64, b: u64) -> [u8; 64] {
    Sha512::new()
        .chain_update((PRF_DST.len() as u64).to_le_bytes())
        .chain_update(PRF_DST)
        .chain_update(seed)
        .chain_update((label.len() as u64).to_le_bytes())
        .chain_update(label)
        .chain_update(a.to_le_bytes())
        .chain_update(b.to_le_bytes())
        .finalize()
        .into()
}

/// A labelled 32-byte sub-seed (the PVSS dealing seed).
fn expand_seed(seed: &[u8; 32], label: &[u8]) -> Zeroizing<[u8; 32]> {
    let bytes = prf_bytes(seed, label, 0, 0);
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&bytes[..32]);
    out
}

/// The KEM exponent `r_k ∈ Z_q^*` for share `k`: wide reduction of 64 PRF bytes, re-derived on the (negligible)
/// chance of hitting zero.
fn derive_kem_exponent(seed: &[u8; 32], index: u32) -> BlsScalar {
    (0u64..)
        .map(|attempt| BlsScalar::from_bytes_wide(&prf_bytes(seed, b"kem-exponent", u64::from(index), attempt)))
        .find(|r| !bool::from(r.is_zero()))
        .expect("a wide-reduced sample is nonzero with overwhelming probability")
}

/// `H_FS(dst, m, Z, B, {F_j}, {F_j^B}, {U_k}, {c_k}, n, t)`.
///
/// `Q` and `Q^B` are `F_0` and `F_0^B`, absorbed once as part of the commitment vectors — target binding makes
/// them equal unconditionally, so a separate absorption would be the same bytes twice.
fn fiat_shamir_challenge(
    statement: &Statement,
    master_pk: &G2Point,
    base: &SecondBase,
    dealing: &PvssDealing,
    ciphertexts: &[EncryptedOffset],
    params: &BindingProofParams,
) -> Vec<u8> {
    let mut transcript = RecommendedTranscript::new(FS_TRANSCRIPT_TAG);
    transcript.append_message(b"statement", statement.to_bytes());
    transcript.append_message(b"master_key", master_pk.to_compressed());
    transcript.append_message(b"generator_g", Ed25519::generator().to_bytes());
    transcript.append_message(b"generator_b", base.point().to_bytes());
    transcript.append_message(b"shares", params.shares.to_le_bytes());
    transcript.append_message(b"threshold", params.threshold.to_le_bytes());
    dealing.commitments.g.iter().for_each(|f| transcript.append_message(b"commitment_g", f.to_bytes()));
    dealing.commitments.b.iter().for_each(|f| transcript.append_message(b"commitment_b", f.to_bytes()));
    ciphertexts.iter().for_each(|ct| {
        transcript.append_message(b"ciphertext_u", ct.u().to_compressed());
        transcript.append_message(b"ciphertext_c", ct.c().to_repr());
    });
    let challenge: &[u8] = &transcript.challenge(b"cut_and_choose");
    challenge.to_vec()
}

/// Expand the challenge into an unbiased stream of indices in `1..=shares`.
///
/// Rejection sampling, not a bare modulo: draws are taken from a range whose size is an exact multiple of
/// `shares`, so no index is over-represented. A biased selector would let a prover concentrate its cheating on the
/// less likely indices.
fn unbiased_draws(challenge: &[u8], shares: u32) -> impl Iterator<Item = u32> + '_ {
    let n = u64::from(shares);
    let zone = (u64::MAX / n) * n;
    (0u64..)
        .flat_map(move |block| {
            let bytes = subset_block(challenge, block);
            (0..8).map(move |i| u64::from_le_bytes(bytes[i * 8..(i + 1) * 8].try_into().expect("8-byte chunk")))
        })
        .filter(move |draw| *draw < zone)
        .map(move |draw| (draw % n) as u32 + 1)
}

fn subset_block(challenge: &[u8], block: u64) -> [u8; 64] {
    Sha512::new()
        .chain_update((SUBSET_DST.len() as u64).to_le_bytes())
        .chain_update(SUBSET_DST)
        .chain_update((challenge.len() as u64).to_le_bytes())
        .chain_update(challenge)
        .chain_update(block.to_le_bytes())
        .finalize()
        .into()
}

/// The `(t − 1)`-subset `I` of `{1..n}` selected by the challenge: distinct draws until the set is full, which is
/// uniform over subsets because the draws are uniform over indices.
fn derive_subset(challenge: &[u8], shares: u32, count: u32) -> BTreeSet<u32> {
    let mut chosen = BTreeSet::new();
    let mut draws = unbiased_draws(challenge, shares);
    while (chosen.len() as u32) < count {
        chosen.insert(draws.next().expect("the draw stream is infinite"));
    }
    chosen
}

//--------------------------------------------------------------------------------------------------------------------
//                                                  Serialization
//--------------------------------------------------------------------------------------------------------------------

impl BindingProof {
    /// The canonical byte encoding:
    ///
    /// ```text
    /// u8(version) ‖ u32-LE(n) ‖ u32-LE(t)
    ///   ‖ {F_j}_{j<t}      (32 bytes each)   ‖ {F_j^B}_{j<t}   (32 bytes each)
    ///   ‖ {DLEQ_j}_{j<t}   (challenge ‖ response, 64 bytes each)
    ///   ‖ {U_k ‖ c_k}_{k<=n}                 (96 + 32 bytes each)
    ///   ‖ {u32-LE(k) ‖ r_k ‖ ω_k}_{k ∈ I}    (4 + 32 + 32 bytes each, ascending k)
    /// ```
    ///
    /// The second base is not present — the verifier recomputes it.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.params.encoded_len());
        out.push(PROOF_ENCODING_VERSION);
        out.extend_from_slice(&self.params.shares.to_le_bytes());
        out.extend_from_slice(&self.params.threshold.to_le_bytes());
        self.dealing.commitments.g.iter().for_each(|f| out.extend_from_slice(f.to_bytes().as_ref()));
        self.dealing.commitments.b.iter().for_each(|f| out.extend_from_slice(f.to_bytes().as_ref()));
        self.dealing.coefficient_dleqs.iter().for_each(|d| {
            out.extend_from_slice(d.challenge.to_repr().as_ref());
            out.extend_from_slice(d.response.to_repr().as_ref());
        });
        self.ciphertexts.iter().for_each(|ct| {
            out.extend_from_slice(&ct.u().to_compressed());
            out.extend_from_slice(ct.c().to_repr().as_ref());
        });
        self.openings.iter().for_each(|o| {
            out.extend_from_slice(&o.index.to_le_bytes());
            out.extend_from_slice(&o.kem_exponent.to_bytes());
            out.extend_from_slice(o.share.to_repr().as_ref());
        });
        out
    }

    /// Parse the canonical encoding, rejecting anything malleable: wrong length, unknown version, out-of-range
    /// `(n, t)`, non-canonical or torsioned Ed25519 points, non-canonical Ed25519 or BLS scalars, `U_k` outside
    /// the G2 prime-order subgroup or equal to the identity, and opening indices that are not strictly ascending
    /// within `1..=n`.
    ///
    /// Parsing does **not** verify the proof — call [`verify_encrypted_offset`] for that.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BindingProofError> {
        let mut reader = Reader::new(bytes);
        match reader.u8()? {
            PROOF_ENCODING_VERSION => Ok(()),
            other => Err(BindingProofError::UnsupportedVersion(other)),
        }?;
        let params = BindingProofParams::new(reader.u32()?, reader.u32()?)?;
        let expected = params.encoded_len();
        if bytes.len() != expected {
            return Err(BindingProofError::InvalidLength { expected, actual: bytes.len() });
        }
        let t = params.threshold as usize;
        let g = (0..t).map(|_| reader.point()).collect::<Result<Vec<_>, _>>()?;
        let b = (0..t).map(|_| reader.point()).collect::<Result<Vec<_>, _>>()?;
        let coefficient_dleqs = (0..t)
            .map(|_| Ok(CoefficientDleq { challenge: reader.scalar()?, response: reader.scalar()? }))
            .collect::<Result<Vec<_>, BindingProofError>>()?;
        let ciphertexts = (0..params.shares as usize)
            .map(|_| {
                let u = reader.g2_point()?;
                let c = reader.scalar()?;
                EncryptedOffset::new(u, c).map_err(BindingProofError::from)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let openings = (0..params.opened() as usize)
            .map(|_| {
                Ok(ShareOpening { index: reader.u32()?, kem_exponent: reader.bls_scalar()?, share: reader.scalar()? })
            })
            .collect::<Result<Vec<_>, BindingProofError>>()?;
        let proof = BindingProof {
            params,
            dealing: PvssDealing { commitments: DualFeldmanCommitments { g, b }, coefficient_dleqs },
            ciphertexts,
            openings,
        };
        proof.check_shape()?;
        Ok(proof)
    }
}

/// A bounds-checked cursor over the canonical encoding.
struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Reader { bytes, pos: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], BindingProofError> {
        let end = self.pos.checked_add(len).ok_or(BindingProofError::InvalidLength { expected: len, actual: 0 })?;
        let slice = self
            .bytes
            .get(self.pos..end)
            .ok_or(BindingProofError::InvalidLength { expected: end, actual: self.bytes.len() })?;
        self.pos = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, BindingProofError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, BindingProofError> {
        let bytes: [u8; 4] = self.take(4)?.try_into().expect("4-byte slice");
        Ok(u32::from_le_bytes(bytes))
    }

    /// An Ed25519 point, canonical and torsion-free. `EdwardsPoint::from_bytes` rejects torsion; re-encoding and
    /// comparing pins the encoding itself, so a non-canonical `y` cannot smuggle in an alternative representation.
    fn point(&mut self) -> Result<EdwardsPoint, BindingProofError> {
        let repr: [u8; 32] = self.take(ED_ELEMENT_LEN)?.try_into().expect("32-byte slice");
        let point = Option::<EdwardsPoint>::from(EdwardsPoint::from_bytes(&repr)).ok_or(BindingProofError::InvalidPoint)?;
        (point.to_bytes() == repr).then_some(point).ok_or(BindingProofError::InvalidPoint)
    }

    /// A canonical Ed25519 scalar: the least residue mod `ℓ`, so `c_k >= ℓ` is rejected here.
    fn scalar(&mut self) -> Result<Scalar, BindingProofError> {
        let repr: [u8; 32] = self.take(ED_ELEMENT_LEN)?.try_into().expect("32-byte slice");
        Option::<Scalar>::from(Scalar::from_repr(repr)).ok_or(BindingProofError::NonCanonicalScalar)
    }

    /// A canonical BLS12-381 scalar: the least residue mod `q`.
    fn bls_scalar(&mut self) -> Result<BlsScalar, BindingProofError> {
        let repr: [u8; 32] = self.take(ED_ELEMENT_LEN)?.try_into().expect("32-byte slice");
        Option::<BlsScalar>::from(BlsScalar::from_bytes(&repr)).ok_or(BindingProofError::NonCanonicalScalar)
    }

    /// A G2 point; `G2Point::from_compressed` performs the canonical-encoding and subgroup checks.
    fn g2_point(&mut self) -> Result<G2Point, BindingProofError> {
        let repr: [u8; G2_COMPRESSED_LEN] = self.take(G2_COMPRESSED_LEN)?.try_into().expect("96-byte slice");
        G2Point::from_compressed(&repr).map_err(BindingProofError::from)
    }
}

impl Serialize for BindingProof {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_bytes().encode_hex::<String>())
    }
}

impl<'de> Deserialize<'de> for BindingProof {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let hex_str = String::deserialize(deserializer)?;
        let bytes = hex::decode(&hex_str).map_err(|e| serde::de::Error::custom(format!("invalid hex encoding: {e}")))?;
        BindingProof::from_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cryptography::attestation::test_helpers::{attest, generate_master_keypair, master_public_key};
    use crate::cryptography::pvss::{is_canonical_scalar, reconstruct_secret};
    use curve25519_dalek::constants::EIGHT_TORSION;
    use ciphersuite::group::Group;
    use ic_bls12_381::G2Affine;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    /// A cheap profile for everything that is not specifically about the production parameters: 4 of 12 shares
    /// opened. Soundness here is only ~9 bits — fine for exercising logic, never for production.
    fn fast() -> BindingProofParams {
        BindingProofParams::new(12, 5).unwrap()
    }

    struct Fixture {
        master_sk: BlsScalar,
        master_pk: G2Point,
        statement: Statement,
        omega: Scalar,
        base: &'static SecondBase,
    }

    impl Fixture {
        fn new(seed: u64) -> Self {
            let mut rng = ChaCha20Rng::seed_from_u64(seed);
            let (master_sk, master_pk) = generate_master_keypair(&mut rng);
            let statement = Statement::new(b"XGCtestchannel".to_vec(), 7);
            let omega = Scalar::random(&mut rng);
            Fixture { master_sk, master_pk, statement, omega, base: SecondBase::grease_default() }
        }

        /// The arbiter's attestation `σ_m = z·H_P(m)` on this fixture's statement, computed inline from the
        /// attestation helpers — the dispute-path tests deliberately do not go through the arbiter mock.
        fn sigma(&self) -> G1Point {
            attest(&self.master_sk, &self.statement)
        }

        fn prove(&self, params: BindingProofParams) -> BindingProof {
            prove_encrypted_offset(&self.omega, &self.statement, &self.master_pk, self.base, params)
                .expect("honest prover succeeds")
        }

        fn verify(&self, proof: &BindingProof) -> Result<(), BindingProofError> {
            self.verify_with_base(proof, self.base)
        }

        fn verify_with_base(&self, proof: &BindingProof, base: &SecondBase) -> Result<(), BindingProofError> {
            verify_encrypted_offset(proof, &self.statement, &self.master_pk, proof.q(), proof.q_b(), base)
        }
    }

    /// Byte offsets into the canonical encoding, recomputed here independently of `encoded_len`.
    fn layout(params: &BindingProofParams) -> (usize, usize, usize) {
        let (n, t) = (params.shares() as usize, params.threshold() as usize);
        let commitments = HEADER_LEN;
        let ciphertexts = commitments + 2 * t * 32 + t * 64;
        let openings = ciphertexts + n * 128;
        (commitments, ciphertexts, openings)
    }

    /// A BLS12-381 G2 point that is on the curve but outside the prime-order subgroup — the shape of point a
    /// prover would smuggle in if the verifier only subgroup-checked the shares it opens.
    fn non_subgroup_g2() -> G2Point {
        (0u64..1000)
            .find_map(|counter| {
                let hi = Sha512::digest((2 * counter).to_le_bytes());
                let lo = Sha512::digest((2 * counter + 1).to_le_bytes());
                let mut bytes = [0u8; G2_COMPRESSED_LEN];
                bytes[..48].copy_from_slice(&hi[..48]);
                bytes[48..].copy_from_slice(&lo[..48]);
                // Keep both Fp coordinates well below the modulus and set the compression flag.
                bytes[0] = (bytes[0] & 0x0f) | 0x80;
                bytes[48] &= 0x0f;
                Option::<G2Affine>::from(G2Affine::from_compressed_unchecked(&bytes))
                    .filter(|p| !bool::from(p.is_identity()) && !bool::from(p.is_torsion_free()))
                    .map(G2Point::from)
            })
            .expect("about half of the candidates are on the curve")
    }

    // ================================================================================================
    // Happy path, determinism, size
    // ================================================================================================

    #[test]
    fn prove_verify_round_trip() {
        let f = Fixture::new(1);
        let proof = f.prove(fast());
        f.verify(&proof).expect("an honest proof verifies");
        assert_eq!(*proof.q(), Ed25519::generator() * f.omega);
        assert_eq!(*proof.q_b(), f.base.point() * f.omega);
        assert_eq!(proof.ciphertexts().len(), 12);
        assert_eq!(proof.openings().len(), 4);
        assert_eq!(proof.sealed_indices().len(), 8);
    }

    #[test]
    fn prove_verify_round_trip_with_production_parameters() {
        let f = Fixture::new(2);
        let params = BindingProofParams::production();
        assert_eq!((params.shares(), params.threshold(), params.opened()), (104, 53, 52));
        let proof = f.prove(params);
        f.verify(&proof).expect("an honest production proof verifies");
        // A round trip through the wire must survive every parse-time check too.
        let parsed = BindingProof::from_bytes(&proof.to_bytes()).expect("canonical encoding parses");
        assert_eq!(parsed, proof);
        f.verify(&parsed).expect("the parsed proof verifies");
    }

    #[test]
    fn proof_is_byte_for_byte_deterministic() {
        let f = Fixture::new(3);
        // Two independent prove calls, no RNG in sight: identical bytes, or a re-proof would open a second subset
        // and push the union of revealed shares past the threshold.
        let first = f.prove(fast());
        let second = f.prove(fast());
        assert_eq!(first, second);
        assert_eq!(first.to_bytes(), second.to_bytes());
        // Any input moving moves the proof: a different statement, master key, offset, base or profile.
        let other_statement = Fixture { statement: Statement::new(b"XGCtestchannel".to_vec(), 8), ..Fixture::new(3) };
        assert_ne!(other_statement.prove(fast()).to_bytes(), first.to_bytes());
        let other_omega = Fixture { omega: f.omega + Scalar::ONE, ..Fixture::new(3) };
        assert_ne!(other_omega.prove(fast()).to_bytes(), first.to_bytes());
        let other_key = Fixture { master_pk: master_public_key(&BlsScalar::from(4242u64)), ..Fixture::new(3) };
        assert_ne!(other_key.prove(fast()).to_bytes(), first.to_bytes());
        assert_ne!(f.prove(BindingProofParams::new(12, 6).unwrap()).to_bytes(), first.to_bytes());
    }

    #[test]
    fn a_second_base_change_re_deals_the_whole_polynomial() {
        // The second base is part of the seed input precisely so that two proofs over the same offset under
        // different bases share only a_0 = ω and each stays below its own threshold.
        let f = Fixture::new(4);
        let other_base = SecondBase::from_point(Ed25519::generator() * Scalar::from(7u64)).unwrap();
        let default_proof = f.prove(fast());
        let other = prove_encrypted_offset(&f.omega, &f.statement, &f.master_pk, &other_base, fast()).unwrap();
        assert_eq!(default_proof.q(), other.q());
        assert_ne!(default_proof.commitments().g[1], other.commitments().g[1]);
        assert_ne!(
            default_proof.openings().iter().map(|o| o.share).collect::<Vec<_>>(),
            other.openings().iter().map(|o| o.share).collect::<Vec<_>>()
        );
    }

    #[test]
    fn opened_shares_stay_below_the_reconstruction_threshold() {
        let f = Fixture::new(5);
        let proof = f.prove(fast());
        let opened = proof
            .openings()
            .iter()
            .map(|o| Share { index: o.index, value: o.share })
            .collect::<Vec<_>>();
        assert_eq!(opened.len() as u32, fast().opened());
        // t-1 shares interpolate a lower-degree polynomial whose value at 0 is not the offset.
        assert_ne!(reconstruct_secret(&opened).unwrap(), f.omega);
    }

    #[test]
    fn production_proof_size_is_within_budget() {
        let f = Fixture::new(6);
        let params = BindingProofParams::production();
        let bytes = f.prove(params).to_bytes();
        // Independent recomputation of the layout: header + {F_j} + {F_j^B} + DLEQs + ciphertexts + openings.
        let expected = 9 + 53 * 32 + 53 * 32 + 53 * 64 + 104 * (96 + 32) + 52 * (4 + 32 + 32);
        assert_eq!(bytes.len(), expected);
        assert_eq!(bytes.len(), params.encoded_len());
        // Frozen size regression. The whitepaper's ≈20 KB estimate does not count the 96-byte G2 encodings in
        // full; the real figure at (104, 53) is 23,641 bytes. A material drift means the wire shape moved.
        assert_eq!(bytes.len(), PRODUCTION_ENCODED_LEN);
        assert!(bytes.len() <= 24 * 1024, "proof grew past the 24 KiB budget: {} bytes", bytes.len());
    }

    const PRODUCTION_ENCODED_LEN: usize = 23_641;

    #[test]
    fn production_soundness_clears_the_2_100_floor() {
        // C(104, 52) ≈ 2^100.3. The floor is 100 bits because a prover can grind the Fiat-Shamir challenge.
        let bits = BindingProofParams::production().soundness_bits();
        assert!(bits >= 100.0, "production soundness is only {bits} bits");
        assert!(bits < 101.0, "unexpectedly large: {bits}");
        assert!(fast().soundness_bits() < 10.0);
    }

    #[test]
    fn serde_round_trip() {
        let f = Fixture::new(7);
        let proof = f.prove(fast());
        let json = serde_json::to_string(&proof).unwrap();
        let back: BindingProof = serde_json::from_str(&json).unwrap();
        assert_eq!(back, proof);
        f.verify(&back).expect("a deserialized honest proof verifies");
        assert!(serde_json::from_str::<BindingProof>("\"not hex\"").is_err());
    }

    #[test]
    fn subset_selection_is_uniform_over_indices() {
        // A biased selector would let a prover concentrate its cheating on the under-drawn indices. 3000 draws of
        // a 4-subset of {1..12} put each index at an expected 1000 appearances.
        let counts = (0u64..3000).fold(vec![0usize; 13], |mut counts, seed| {
            let challenge = Sha512::digest(seed.to_le_bytes());
            derive_subset(&challenge, 12, 4).iter().for_each(|k| counts[*k as usize] += 1);
            counts
        });
        assert_eq!(counts[0], 0, "indices are 1-based");
        counts[1..].iter().enumerate().for_each(|(i, c)| {
            assert!((880..=1120).contains(c), "index {} drawn {c} times, expected ~1000", i + 1);
        });
    }

    // ================================================================================================
    // Parameter and input validation
    // ================================================================================================

    #[test]
    fn invalid_parameters_and_offsets_are_rejected() {
        assert!(matches!(BindingProofParams::new(10, 1), Err(BindingProofError::InvalidParameters { .. })));
        assert!(matches!(BindingProofParams::new(10, 11), Err(BindingProofError::InvalidParameters { .. })));
        assert!(matches!(BindingProofParams::new(MAX_SHARES + 1, 2), Err(BindingProofError::InvalidParameters { .. })));
        let f = Fixture::new(8);
        let zero = prove_encrypted_offset(&Scalar::ZERO, &f.statement, &f.master_pk, f.base, fast());
        assert!(matches!(zero, Err(BindingProofError::ZeroOffset)));
    }

    // ================================================================================================
    // Forgery and tamper: the targets
    // ================================================================================================

    #[test]
    fn rejects_a_proof_bound_to_a_different_adaptor_point() {
        let f = Fixture::new(9);
        let proof = f.prove(fast());
        let wrong_q = *proof.q() + Ed25519::generator();
        let err = verify_encrypted_offset(&proof, &f.statement, &f.master_pk, &wrong_q, proof.q_b(), f.base);
        assert!(matches!(err, Err(BindingProofError::TargetMismatch)));
        let wrong_q_b = *proof.q_b() + f.base.point();
        let err = verify_encrypted_offset(&proof, &f.statement, &f.master_pk, proof.q(), &wrong_q_b, f.base);
        assert!(matches!(err, Err(BindingProofError::TargetMismatchSecondBase)));
    }

    #[test]
    fn rejects_targets_that_fail_point_hygiene() {
        let f = Fixture::new(10);
        let proof = f.prove(fast());
        let torsioned = EdwardsPoint(proof.q().0 + EIGHT_TORSION[1]);
        let err = verify_encrypted_offset(&proof, &f.statement, &f.master_pk, &torsioned, proof.q_b(), f.base);
        assert!(matches!(err, Err(BindingProofError::Pvss(PvssError::TorsionPoint))));
        let identity = EdwardsPoint::identity();
        let err = verify_encrypted_offset(&proof, &f.statement, &f.master_pk, &identity, proof.q_b(), f.base);
        assert!(matches!(err, Err(BindingProofError::Pvss(PvssError::IdentityPoint))));
        let err = verify_encrypted_offset(&proof, &f.statement, &f.master_pk, proof.q(), &identity, f.base);
        assert!(matches!(err, Err(BindingProofError::Pvss(PvssError::IdentityPoint))));
    }

    #[test]
    fn rejects_a_proof_for_a_different_statement_or_master_key() {
        let f = Fixture::new(11);
        let proof = f.prove(fast());
        // The statement is absorbed into both the ciphertexts and the challenge, so a replay to state 8 fails.
        let stale = Statement::new(b"XGCtestchannel".to_vec(), 8);
        let err = verify_encrypted_offset(&proof, &stale, &f.master_pk, proof.q(), proof.q_b(), f.base);
        assert!(matches!(err, Err(BindingProofError::SubsetMismatch)));
        let other_key = master_public_key(&BlsScalar::from(99u64));
        let err = verify_encrypted_offset(&proof, &f.statement, &other_key, proof.q(), proof.q_b(), f.base);
        assert!(matches!(err, Err(BindingProofError::SubsetMismatch)));
    }

    // ================================================================================================
    // Forgery and tamper: commitments, DLEQs, ciphertexts, openings
    // ================================================================================================

    #[test]
    fn rejects_a_tampered_coefficient_commitment() {
        let f = Fixture::new(12);
        let mut proof = f.prove(fast());
        proof.dealing.commitments.g[1] += Ed25519::generator();
        assert!(matches!(f.verify(&proof), Err(BindingProofError::Pvss(PvssError::DleqVerificationFailure(1)))));

        let mut proof = f.prove(fast());
        proof.dealing.commitments.b[2] += f.base.point();
        assert!(matches!(f.verify(&proof), Err(BindingProofError::Pvss(PvssError::DleqVerificationFailure(2)))));
    }

    #[test]
    fn rejects_commitments_that_fail_point_hygiene() {
        let f = Fixture::new(13);
        let mut proof = f.prove(fast());
        proof.dealing.commitments.g[1] = EdwardsPoint(proof.dealing.commitments.g[1].0 + EIGHT_TORSION[1]);
        assert!(matches!(f.verify(&proof), Err(BindingProofError::Pvss(PvssError::TorsionPoint))));

        let mut proof = f.prove(fast());
        proof.dealing.commitments.b[1] = EdwardsPoint::identity();
        assert!(matches!(f.verify(&proof), Err(BindingProofError::Pvss(PvssError::IdentityPoint))));
    }

    #[test]
    fn rejects_a_tampered_coefficient_dleq() {
        let f = Fixture::new(14);
        let mut proof = f.prove(fast());
        // DLEQs are not absorbed into the challenge, so this surfaces as a DLEQ failure, not a subset mismatch.
        proof.dealing.coefficient_dleqs[3].response += Scalar::ONE;
        assert!(matches!(f.verify(&proof), Err(BindingProofError::Pvss(PvssError::DleqVerificationFailure(3)))));

        let mut proof = f.prove(fast());
        proof.dealing.coefficient_dleqs[0].challenge += Scalar::ONE;
        assert!(matches!(f.verify(&proof), Err(BindingProofError::Pvss(PvssError::DleqVerificationFailure(0)))));
    }

    #[test]
    fn rejects_a_tampered_share_ciphertext() {
        let f = Fixture::new(15);
        let proof = f.prove(fast());
        let sealed = proof.sealed_indices()[0];
        // Ciphertexts are absorbed into the challenge, so touching one — opened or sealed — re-rolls the subset.
        let mut tampered = proof.clone();
        let victim = &mut tampered.ciphertexts[(sealed - 1) as usize];
        *victim = EncryptedOffset::new(*victim.u(), *victim.c() + Scalar::ONE).unwrap();
        assert!(matches!(f.verify(&tampered), Err(BindingProofError::SubsetMismatch)));

        let mut tampered = proof.clone();
        let opened = proof.openings()[0].index;
        let victim = &mut tampered.ciphertexts[(opened - 1) as usize];
        *victim = EncryptedOffset::new(*victim.u(), *victim.c() + Scalar::ONE).unwrap();
        assert!(matches!(f.verify(&tampered), Err(BindingProofError::SubsetMismatch)));
    }

    #[test]
    fn rejects_a_tampered_opening() {
        let f = Fixture::new(16);
        let proof = f.prove(fast());
        // Openings are derived from the challenge rather than absorbed into it, so a doctored opening reports
        // itself instead of hiding behind a subset mismatch.
        let mut tampered = proof.clone();
        tampered.openings[1].share += Scalar::ONE;
        let index = tampered.openings[1].index;
        assert!(matches!(f.verify(&tampered), Err(BindingProofError::OpeningMismatch(k)) if k == index));

        let mut tampered = proof.clone();
        tampered.openings[0].kem_exponent += BlsScalar::from(1u64);
        let index = tampered.openings[0].index;
        assert!(matches!(f.verify(&tampered), Err(BindingProofError::OpeningMismatch(k)) if k == index));

        let mut tampered = proof.clone();
        tampered.openings[0].kem_exponent = BlsScalar::from(0u64);
        let index = tampered.openings[0].index;
        assert!(matches!(f.verify(&tampered), Err(BindingProofError::ZeroKemExponent(k)) if k == index));
    }

    #[test]
    fn rejects_the_wrong_opened_subset() {
        let f = Fixture::new(17);
        let proof = f.prove(fast());
        let mut tampered = proof.clone();
        // Swap one opened index for a sealed one, keeping the ascending-index invariant intact.
        let sealed = *proof.sealed_indices().last().unwrap();
        let last = tampered.openings.len() - 1;
        assert!(tampered.openings[last].index != sealed);
        tampered.openings[last].index = sealed;
        assert!(matches!(f.verify(&tampered), Err(BindingProofError::SubsetMismatch)));

        // Dropping an opening is a shape error before the challenge is even recomputed.
        let mut short = proof.clone();
        short.openings.pop();
        assert!(matches!(f.verify(&short), Err(BindingProofError::Malformed(_))));

        // Out-of-order indices are rejected outright.
        let mut unordered = proof.clone();
        unordered.openings.swap(0, 1);
        assert!(matches!(f.verify(&unordered), Err(BindingProofError::InvalidOpeningIndices)));
    }

    #[test]
    fn an_opened_share_inconsistent_with_the_commitments_is_rejected() {
        // The cheat the cut-and-choose exists to catch, isolated from Fiat-Shamir: a share that reproduces its
        // ciphertext but does not lie on the committed polynomial. Reached directly, since doctoring both the
        // share and its ciphertext re-rolls the challenge and would otherwise surface as a subset mismatch.
        let f = Fixture::new(18);
        let mut proof = f.prove(fast());
        let opening = proof.openings()[0];
        let bogus = opening.share + Scalar::ONE;
        let ciphertext =
            encrypt_to_statement_with_r(&bogus, &f.statement, &f.master_pk, opening.kem_exponent()).unwrap();
        proof.ciphertexts[(opening.index - 1) as usize] = ciphertext;
        let doctored = ShareOpening { index: opening.index, kem_exponent: opening.kem_exponent, share: bogus };
        let err = verify_opening(&proof, &doctored, &f.statement, &f.master_pk, f.base);
        assert!(matches!(err, Err(BindingProofError::Pvss(PvssError::ShareVerificationFailure))));
        // And the full verifier rejects the doctored bundle too, one step earlier.
        proof.openings[0] = doctored;
        assert!(f.verify(&proof).is_err());
    }

    // ================================================================================================
    // KEM point hygiene
    // ================================================================================================

    #[test]
    fn rejects_a_repeated_kem_point() {
        let f = Fixture::new(19);
        let mut proof = f.prove(fast());
        // A reused r_k makes ω_j − ω_k recoverable from c_j − c_k; enough of them recover ω itself.
        let borrowed = *proof.ciphertexts[0].u();
        proof.ciphertexts[5] = EncryptedOffset::new(borrowed, *proof.ciphertexts[5].c()).unwrap();
        assert!(matches!(f.verify(&proof), Err(BindingProofError::DuplicateKemPoint)));
    }

    #[test]
    fn rejects_a_kem_point_outside_the_g2_subgroup() {
        let f = Fixture::new(20);
        let proof = f.prove(fast());
        let outsider = non_subgroup_g2();
        // Both an opened and an unopened position: cofactor torsion on a point nobody checks is grindable.
        let sealed = proof.sealed_indices()[0];
        let opened = proof.openings()[0].index;
        [sealed, opened].iter().for_each(|&index| {
            let mut tampered = proof.clone();
            tampered.ciphertexts[(index - 1) as usize] =
                EncryptedOffset::new(outsider, *proof.ciphertexts[(index - 1) as usize].c()).unwrap();
            assert!(matches!(f.verify(&tampered), Err(BindingProofError::KemPointNotInSubgroup(k)) if k == index));
        });
        // The parse boundary rejects it as an invalid encoding before verification is ever reached.
        let mut bytes = proof.to_bytes();
        let (_, ciphertexts, _) = layout(proof.params());
        let at = ciphertexts + (sealed as usize - 1) * 128;
        bytes[at..at + 96].copy_from_slice(&outsider.to_compressed());
        assert!(matches!(BindingProof::from_bytes(&bytes), Err(BindingProofError::Attestation(_))));
    }

    #[test]
    fn rejects_an_identity_kem_point_on_the_wire() {
        let f = Fixture::new(21);
        let proof = f.prove(fast());
        let mut bytes = proof.to_bytes();
        let (_, ciphertexts, _) = layout(proof.params());
        bytes[ciphertexts..ciphertexts + 96].copy_from_slice(&G2Point::from(G2Affine::identity()).to_compressed());
        assert!(matches!(BindingProof::from_bytes(&bytes), Err(BindingProofError::Encryption(_))));
    }

    // ================================================================================================
    // The second base is never taken from the wire
    // ================================================================================================

    #[test]
    fn the_second_base_is_absent_from_the_encoding_and_cannot_be_substituted() {
        let f = Fixture::new(22);
        let proof = f.prove(fast());
        let bytes = proof.to_bytes();
        let base_bytes = f.base.point().to_bytes();
        assert!(!bytes.windows(32).any(|w| w == base_bytes), "the second base must not be on the wire");
        // Verifying the same proof against a different locally recomputed B fails on the coefficient DLEQs.
        let other_base = SecondBase::from_point(Ed25519::generator() * Scalar::from(9u64)).unwrap();
        let err = f.verify_with_base(&proof, &other_base);
        assert!(matches!(err, Err(BindingProofError::Pvss(PvssError::DleqVerificationFailure(0)))));
    }

    // ================================================================================================
    // Parse-boundary hygiene
    // ================================================================================================

    #[test]
    fn rejects_a_truncated_or_overlong_encoding() {
        let f = Fixture::new(23);
        let bytes = f.prove(fast()).to_bytes();
        assert!(matches!(BindingProof::from_bytes(&bytes[..bytes.len() - 1]), Err(BindingProofError::InvalidLength { .. })));
        assert!(matches!(BindingProof::from_bytes(&bytes[..9]), Err(BindingProofError::InvalidLength { .. })));
        assert!(matches!(BindingProof::from_bytes(&[]), Err(BindingProofError::InvalidLength { .. })));
        let mut long = bytes.clone();
        long.push(0);
        assert!(matches!(BindingProof::from_bytes(&long), Err(BindingProofError::InvalidLength { .. })));
    }

    #[test]
    fn rejects_a_bad_header() {
        let f = Fixture::new(24);
        let bytes = f.prove(fast()).to_bytes();
        let mut wrong_version = bytes.clone();
        wrong_version[0] = 2;
        assert!(matches!(BindingProof::from_bytes(&wrong_version), Err(BindingProofError::UnsupportedVersion(2))));
        // A hostile n in the header must be refused before any allocation, not trusted.
        let mut huge = bytes.clone();
        huge[1..5].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(BindingProof::from_bytes(&huge), Err(BindingProofError::InvalidParameters { .. })));
    }

    #[test]
    fn rejects_a_non_canonical_scalar_on_the_wire() {
        let f = Fixture::new(25);
        let proof = f.prove(fast());
        let (_, ciphertexts, openings) = layout(proof.params());
        // ℓ itself: congruent to zero but not the least residue.
        let ell = hex::decode("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010").unwrap();
        assert!(!is_canonical_scalar(&ell.clone().try_into().unwrap()));

        let mut bytes = proof.to_bytes();
        bytes[ciphertexts + 96..ciphertexts + 128].copy_from_slice(&ell);
        assert!(matches!(BindingProof::from_bytes(&bytes), Err(BindingProofError::NonCanonicalScalar)));

        // The revealed share is an Ed25519 scalar, the KEM exponent a BLS one; both are canonicity-checked.
        let mut bytes = proof.to_bytes();
        bytes[openings + 36..openings + 68].copy_from_slice(&ell);
        assert!(matches!(BindingProof::from_bytes(&bytes), Err(BindingProofError::NonCanonicalScalar)));

        let mut bytes = proof.to_bytes();
        bytes[openings + 4..openings + 36].copy_from_slice(&[0xff; 32]);
        assert!(matches!(BindingProof::from_bytes(&bytes), Err(BindingProofError::NonCanonicalScalar)));

        // And a DLEQ scalar.
        let mut bytes = proof.to_bytes();
        let dleqs = HEADER_LEN + 2 * 5 * 32;
        bytes[dleqs..dleqs + 32].copy_from_slice(&ell);
        assert!(matches!(BindingProof::from_bytes(&bytes), Err(BindingProofError::NonCanonicalScalar)));
    }

    #[test]
    fn rejects_a_torsioned_or_non_canonical_point_on_the_wire() {
        let f = Fixture::new(26);
        let proof = f.prove(fast());
        let (commitments, _, _) = layout(proof.params());

        let torsioned = EdwardsPoint(proof.commitments().g[1].0 + EIGHT_TORSION[1]).to_bytes();
        let mut bytes = proof.to_bytes();
        bytes[commitments + 32..commitments + 64].copy_from_slice(&torsioned);
        assert!(matches!(BindingProof::from_bytes(&bytes), Err(BindingProofError::InvalidPoint)));

        // A y-coordinate at or above the field prime is not a canonical encoding, whatever it decompresses to.
        let mut bytes = proof.to_bytes();
        bytes[commitments..commitments + 32].copy_from_slice(&[0xff; 32]);
        assert!(matches!(BindingProof::from_bytes(&bytes), Err(BindingProofError::InvalidPoint)));
    }

    #[test]
    fn rejects_openings_that_are_not_strictly_ascending_on_the_wire() {
        let f = Fixture::new(27);
        let proof = f.prove(fast());
        let (_, _, openings) = layout(proof.params());
        let mut bytes = proof.to_bytes();
        // Duplicate the first opening's index onto the second: no longer strictly ascending.
        let first = bytes[openings..openings + 4].to_vec();
        bytes[openings + OPENING_LEN..openings + OPENING_LEN + 4].copy_from_slice(&first);
        assert!(matches!(BindingProof::from_bytes(&bytes), Err(BindingProofError::InvalidOpeningIndices)));

        let mut bytes = proof.to_bytes();
        bytes[openings..openings + 4].copy_from_slice(&0u32.to_le_bytes());
        assert!(matches!(BindingProof::from_bytes(&bytes), Err(BindingProofError::InvalidOpeningIndices)));

        let mut bytes = proof.to_bytes();
        let last = openings + (fast().opened() as usize - 1) * OPENING_LEN;
        bytes[last..last + 4].copy_from_slice(&99u32.to_le_bytes());
        assert!(matches!(BindingProof::from_bytes(&bytes), Err(BindingProofError::InvalidOpeningIndices)));
    }

    // ================================================================================================
    // Dispute-path recovery
    // ================================================================================================

    /// Replace the ciphertext at `index` with one that decrypts to garbage, leaving `U_k` — and so the KEM point
    /// hygiene checks — intact. This is the shape of a bundle that squeaked through the cut-and-choose.
    fn corrupt_ciphertext(proof: &mut BindingProof, index: u32) {
        let victim = &mut proof.ciphertexts[(index - 1) as usize];
        *victim = EncryptedOffset::new(*victim.u(), *victim.c() + Scalar::ONE).unwrap();
    }

    #[test]
    fn recovers_the_offset_from_a_genuine_proof() {
        let f = Fixture::new(28);
        let proof = f.prove(fast());
        f.verify(&proof).expect("an honest proof verifies");
        // The claimant holds t-1 openings and needs exactly one sealed ciphertext to reach the threshold.
        assert_eq!(proof.openings().len() as u32, fast().opened());
        let recovered = recover_offset(&proof, &f.statement, &f.sigma()).expect("the honest offset is recoverable");
        assert_eq!(recovered, f.omega);
        assert_eq!(Ed25519::generator() * recovered, *proof.q());
    }

    #[test]
    fn recovery_survives_corrupted_unopened_ciphertexts() {
        // A prover that beat the cut-and-choose (probability 1/C(n, t-1)) did so with garbage in some unopened
        // slots. One surviving consistent share is all recovery needs, wherever in the order it sits.
        let f = Fixture::new(29);
        let honest = f.prove(fast());
        let sealed = honest.sealed_indices();
        assert_eq!(sealed.len(), 8);
        // Every sealed ciphertext but one, both with the survivor last and with it first.
        [*sealed.last().unwrap(), sealed[0]].iter().for_each(|survivor| {
            let mut proof = honest.clone();
            sealed.iter().filter(|k| *k != survivor).for_each(|k| corrupt_ciphertext(&mut proof, *k));
            let recovered = recover_offset(&proof, &f.statement, &f.sigma()).expect("one good share suffices");
            assert_eq!(recovered, f.omega);
        });
    }

    #[test]
    fn recovery_fails_when_every_unopened_ciphertext_is_garbage() {
        // The frozen update: the cheat's offset is unrecoverable, and recovery says so rather than returning a
        // scalar that would complete a wrong closing signature.
        let f = Fixture::new(30);
        let mut proof = f.prove(fast());
        proof.sealed_indices().into_iter().for_each(|k| corrupt_ciphertext(&mut proof, k));
        let err = recover_offset(&proof, &f.statement, &f.sigma());
        assert!(matches!(err, Err(BindingProofError::NoRecoverableShare)));
    }

    #[test]
    fn the_wrong_attestation_recovers_nothing() {
        let f = Fixture::new(31);
        let proof = f.prove(fast());
        // An attestation of a different statement — the neighbouring update, exactly what a stale close would
        // unseal if the statement binding were loose. Decryption cannot report this; share consistency does.
        let stale = Statement::new(b"XGCtestchannel".to_vec(), 6);
        let sigma_stale = attest(&f.master_sk, &stale);
        assert!(matches!(
            recover_offset(&proof, &f.statement, &sigma_stale),
            Err(BindingProofError::NoRecoverableShare)
        ));
        // ... and reading the whole thing under the stale statement fails just as cleanly.
        assert!(matches!(recover_offset(&proof, &stale, &sigma_stale), Err(BindingProofError::NoRecoverableShare)));
        // A signature under a different master key is equally useless.
        let other_z = BlsScalar::from(4242u64);
        assert!(matches!(
            recover_offset(&proof, &f.statement, &attest(&other_z, &f.statement)),
            Err(BindingProofError::NoRecoverableShare)
        ));
    }

    #[test]
    fn recovery_rejects_openings_that_are_off_the_polynomial() {
        // The final ω·G = Q check: a sealed ciphertext can decrypt consistently while a doctored opening drags the
        // interpolation off the committed polynomial.
        let f = Fixture::new(32);
        let mut proof = f.prove(fast());
        proof.openings[0].share += Scalar::ONE;
        let err = recover_offset(&proof, &f.statement, &f.sigma());
        assert!(matches!(err, Err(BindingProofError::RecoveredOffsetMismatch)));
    }

    #[test]
    fn recovery_round_trips_at_production_parameters() {
        let f = Fixture::new(33);
        let proof = f.prove(BindingProofParams::production());
        assert_eq!(recover_offset(&proof, &f.statement, &f.sigma()).unwrap(), f.omega);
    }

    #[test]
    fn the_subgroup_test_actually_separates_g2_points() {
        // Guards the assumption behind `check_kem_points`: `is_torsion_free` on the affine point is the subgroup
        // test, the honest generator passes it, and the adversarial fixture really is outside G2.
        assert!(bool::from(G2Affine::generator().is_torsion_free()));
        assert!(!bool::from(non_subgroup_g2().as_affine().is_torsion_free()));
    }
}
