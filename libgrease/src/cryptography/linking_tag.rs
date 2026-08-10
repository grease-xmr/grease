//! Proof of correct contribution to the joint funding linking tag `L_F`.
//!
//! The channel id is finalized against one tag per funding output: `L_j = (d_j + x)·H_p(K_j)`, the key image
//! that output's spend will publish, taken over its one-time key `K_j = d_j·G + P` for the shared wallet's joint
//! spend key `P = x·G` (`docs/src/14_establishing_channel.typ` §linkingTagExchange). Neither party holds `x`, so
//! neither can compute a tag alone: each contributes `T_j^i = λ_i·s_i·H_p(K_j)` for its interpolated MuSig share
//! — offset by `d_j`, which both parties derive independently from the shared view key — and the two partials
//! sum to `L_j`.
//!
//! # Why the exchange needs a proof
//!
//! A bare sum of two partials is unverifiable. The honest party knows the base `H = H_p(K_j)` but not `x`, so it
//! has no public check that the sum is the output's true key image — and the tags are absorbed into the
//! finalized channel id, which [`ChannelIdMetadata::finalize`](crate::channel_id::ChannelIdMetadata::finalize)
//! refuses to re-bind. Worse than a wrong tag, the exchange is not ordered: whoever sends second can set
//! `T_2 = L* − T_1` for any `L*` it likes and *steer* the tag, since that difference is a perfectly well-formed
//! group element. Every other field of the channel-id transcript can be repeated across two channels (the
//! merchant's half comes from a reusable out-of-band seed, the customer's half is its own), so a steered tag
//! collides the two final ids, hence the arbiter statements `m = (id, i)` — and an attestation earned by
//! disputing one channel then opens the counterparty's sealed offset in the other. See
//! `docs/src/14_establishing_channel.typ` §linkingTagExchange.
//!
//! # The proof
//!
//! [`PartialLinkingTag`] carries the partial together with a Chaum–Pedersen proof of equality of discrete logs
//! across the two bases `G` and `H`:
//!
//! ```text
//!     DLEQ_{G,H}(V_i, T_i):   V_i = s·G   ∧   T_i = s·H   for the same s
//! ```
//!
//! where `V_i` is the contributor's *interpolated MuSig verification share* `λ_i·s_i·G`. The scalar the proof
//! ties the partial to is therefore the very share that party uses to sign with the shared wallet.
//!
//! **The verifier derives `V_i` itself; the prover never supplies it.** `modular_frost`'s
//! `ThresholdView::verification_share` yields the interpolated, offset verification shares, and they sum to the
//! group key `P`, so `V_peer` follows from public key material the verifier already committed to during the
//! commit-then-reveal wallet-key exchange. That is what makes the proof binding: nothing the prover sends can
//! move the statement it must satisfy. If the DLEQ verifies, the partial is `λ_peer·s_peer·H` exactly, so the
//! combined tag is `(d_j + x)·H_p(K_j)` for the honest joint key — the key image the chain will show — and the
//! collision above evaporates. Freshness comes free: every funding transaction carries its own `R_j`, so `K_j`
//! and `H_p(K_j)` differ even between two channels that shared a wallet spend key.
//!
//! # Fiat–Shamir transcript
//!
//! The challenge comes from a `RecommendedTranscript` (Blake2b-based, every message labelled and
//! length-prefixed) with domain [`CONTRIBUTION_TRANSCRIPT_TAG`], absorbing in order: `G`, `H`, `V`, `T`, and the
//! nonce points `R_G = k·G`, `R_H = k·H`; the transcript challenge is then wide-reduced to a scalar. Both bases
//! and both statement points are absorbed, so a proof is bound to one wallet: a different channel has a
//! different `P`, hence a different `H` and `V`, and the proof does not transfer.
//!
//! # Point hygiene
//!
//! `H`, `V` and the received `T` are each rejected if they are the identity or carry a torsion component
//! (shared with [`pvss`](crate::cryptography::pvss)). Torsion rejection is not cosmetic: against a partial with
//! an order-8 component a prover can satisfy the verification equation whenever the challenge happens to vanish
//! mod 8, which is one attempt in eight.
//!
//! In practice a torsioned partial cannot get that far, because `dalek_ff_group`'s decoder rejects torsion, so
//! [`PartialLinkingTag::from_bytes`] refuses it. The runtime check is kept for points that never crossed the
//! wire, and so that the rule does not rest on a dependency's behaviour staying what it is today.
//!
//! Canonicity is a *separate* rule with a separate enforcer: that same decoder reduces `y` mod `p`, so `y + p`
//! decodes to the same point, and only the re-encode comparison in `read_point` refuses it. Nothing here is
//! unsound without it — the challenge absorbs the canonical `to_bytes()` either way — but it keeps one partial
//! from having two wire encodings. A test pins each rule against the vector that actually exercises it.

use crate::cryptography::ciphersuite_ext::{hash_to_F, random_nonzero_F};
use crate::cryptography::pvss::is_torsion_free;
use crate::Ed25519;
use ciphersuite::group::{Group, GroupEncoding};
use ciphersuite::WrappedGroup;
use dalek_ff_group::{EdwardsPoint, Scalar};
use flexible_transcript::{RecommendedTranscript, Transcript};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

/// Transcript domain for the contribution DLEQ. Changing this invalidates every existing proof.
pub const CONTRIBUTION_TRANSCRIPT_TAG: &[u8] = b"Grease funding linking tag contribution DLEQ v1";

/// Domain tag for reducing the transcript challenge to a scalar.
const CONTRIBUTION_CHALLENGE_TAG: &[u8] = b"GREASE-LINKING-TAG-DLEQ-CHALLENGE-v1";

/// Wire size of a [`PartialLinkingTag`]: the partial, then the challenge and response scalars.
pub const PARTIAL_LINKING_TAG_BYTES: usize = 96;

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum LinkingTagError {
    #[error("The {0} is the identity element")]
    IdentityPoint(&'static str),
    #[error("The {0} is not torsion-free")]
    TorsionPoint(&'static str),
    #[error("The contributed share is zero, which contributes nothing to the linking tag")]
    ZeroShare,
    #[error("The proof of correct contribution to the linking tag does not verify")]
    ProofVerificationFailure,
    #[error("Malformed partial linking tag: {0}")]
    MalformedEncoding(String),
}

/// A Chaum–Pedersen proof that a linking-tag partial was computed from the same scalar as the contributor's
/// MuSig verification share. See the module documentation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContributionProof {
    pub challenge: Scalar,
    pub response: Scalar,
}

/// One party's contribution to `L_F`: the partial `T_i = λ_i·s_i·H_p(P)` and the proof that it was derived from
/// the same share as that party's MuSig verification share `V_i = λ_i·s_i·G`.
///
/// This type is the whole of the wire message. It carries no way to reach the partial without stating the base
/// and verification share to check it against, so a caller cannot combine an unproven contribution by accident —
/// [`verified_partial`](Self::verified_partial) is the only accessor, and it verifies first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PartialLinkingTag {
    partial: EdwardsPoint,
    proof: ContributionProof,
}

impl PartialLinkingTag {
    /// Prove correct contribution of `share` — this party's interpolated MuSig secret share `λ_i·s_i` — against
    /// the linking-tag base `base = H_p(P)`, and package the resulting partial `share·base` with its proof.
    ///
    /// Fails if `share` is zero (such a partial contributes nothing) or if `base` fails point hygiene.
    pub fn prove<R: RngCore + CryptoRng>(
        share: &Scalar,
        base: &EdwardsPoint,
        rng: &mut R,
    ) -> Result<Self, LinkingTagError> {
        check_point_hygiene(base, "linking tag base")?;
        if bool::from(<Scalar as ciphersuite::group::ff::Field>::is_zero(share)) {
            return Err(LinkingTagError::ZeroShare);
        }
        let nonce = Zeroizing::new(random_nonzero_F::<Ed25519, _>(rng));
        let verification_share = Ed25519::generator() * *share;
        let partial = *base * *share;
        let challenge = contribution_challenge(
            base,
            &verification_share,
            &partial,
            &(Ed25519::generator() * *nonce),
            &(*base * *nonce),
        );
        let proof = ContributionProof { challenge, response: *nonce + challenge * *share };
        Ok(PartialLinkingTag { partial, proof })
    }

    /// The proof of correct contribution, for callers that want to inspect it. The partial itself is only
    /// reachable through [`verified_partial`](Self::verified_partial).
    pub fn proof(&self) -> &ContributionProof {
        &self.proof
    }

    /// Verify the contribution against the contributor's verification share `V = λ_i·s_i·G` and the linking-tag
    /// base `H`, and return the partial on success.
    ///
    /// `verification_share` must be derived by the verifier from key material it already trusts — the MuSig
    /// interpolation of the two wallet keys — and never taken from the same message as the partial. Supplying a
    /// prover-chosen `V` reduces this to proving `T = s·H` for *some* `s`, which is exactly the property that
    /// does not constrain the tag.
    pub fn verified_partial(
        &self,
        verification_share: &EdwardsPoint,
        base: &EdwardsPoint,
    ) -> Result<EdwardsPoint, LinkingTagError> {
        check_point_hygiene(base, "linking tag base")?;
        check_point_hygiene(verification_share, "verification share")?;
        check_point_hygiene(&self.partial, "linking tag partial")?;
        let r_g = Ed25519::generator() * self.proof.response - *verification_share * self.proof.challenge;
        let r_h = *base * self.proof.response - self.partial * self.proof.challenge;
        let expected = contribution_challenge(base, verification_share, &self.partial, &r_g, &r_h);
        match expected == self.proof.challenge {
            true => Ok(self.partial),
            false => Err(LinkingTagError::ProofVerificationFailure),
        }
    }

    /// Serialize to [`PARTIAL_LINKING_TAG_BYTES`] bytes: partial ‖ challenge ‖ response.
    pub fn to_bytes(&self) -> [u8; PARTIAL_LINKING_TAG_BYTES] {
        let mut out = [0u8; PARTIAL_LINKING_TAG_BYTES];
        out[..32].copy_from_slice(self.partial.to_bytes().as_ref());
        out[32..64].copy_from_slice(&self.proof.challenge.to_bytes());
        out[64..].copy_from_slice(&self.proof.response.to_bytes());
        out
    }

    /// Parse the encoding produced by [`to_bytes`](Self::to_bytes). Decoding checks the point and both scalars
    /// are canonical; it does *not* check the proof — call [`verified_partial`](Self::verified_partial) for that.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, LinkingTagError> {
        if bytes.len() != PARTIAL_LINKING_TAG_BYTES {
            return Err(LinkingTagError::MalformedEncoding(format!(
                "expected {PARTIAL_LINKING_TAG_BYTES} bytes, got {}",
                bytes.len()
            )));
        }
        let partial = read_point(&bytes[..32])?;
        let challenge = read_scalar(&bytes[32..64], "challenge")?;
        let response = read_scalar(&bytes[64..], "response")?;
        Ok(PartialLinkingTag { partial, proof: ContributionProof { challenge, response } })
    }
}

impl Serialize for PartialLinkingTag {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        hex::encode(self.to_bytes()).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for PartialLinkingTag {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let hex_str = String::deserialize(deserializer)?;
        let bytes = hex::decode(&hex_str).map_err(|e| serde::de::Error::custom(format!("invalid hex encoding: {e}")))?;
        PartialLinkingTag::from_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}

/// Reject a point that is the identity or carries a torsion component, naming it in the error.
pub fn check_point_hygiene(point: &EdwardsPoint, name: &'static str) -> Result<(), LinkingTagError> {
    if bool::from(point.is_identity()) {
        return Err(LinkingTagError::IdentityPoint(name));
    }
    if !is_torsion_free(point) {
        return Err(LinkingTagError::TorsionPoint(name));
    }
    Ok(())
}

/// Fiat–Shamir challenge over a labelled, length-prefixed transcript. See the module docs for the exact shape.
fn contribution_challenge(
    base: &EdwardsPoint,
    verification_share: &EdwardsPoint,
    partial: &EdwardsPoint,
    nonce_g: &EdwardsPoint,
    nonce_h: &EdwardsPoint,
) -> Scalar {
    let mut t = RecommendedTranscript::new(CONTRIBUTION_TRANSCRIPT_TAG);
    t.append_message(b"generator_g", Ed25519::generator().to_bytes());
    t.append_message(b"linking_tag_base", base.to_bytes());
    t.append_message(b"verification_share", verification_share.to_bytes());
    t.append_message(b"partial_linking_tag", partial.to_bytes());
    t.append_message(b"nonce_g", nonce_g.to_bytes());
    t.append_message(b"nonce_h", nonce_h.to_bytes());
    hash_to_F::<Ed25519>(CONTRIBUTION_CHALLENGE_TAG, &t.challenge(b"challenge"))
}

/// An Ed25519 point, canonical and torsion-free. `EdwardsPoint::from_bytes` rejects torsion but *not* a
/// non-canonical `y` — it reduces mod `p`, so `y + p` decodes to the same point as `y`. Re-encoding and
/// comparing pins the encoding itself, which is what makes the partial's byte representation unique.
fn read_point(bytes: &[u8]) -> Result<EdwardsPoint, LinkingTagError> {
    let mut repr = [0u8; 32];
    repr.copy_from_slice(bytes);
    let malformed = |what: &str| LinkingTagError::MalformedEncoding(format!("partial is {what}"));
    let point = Option::<EdwardsPoint>::from(EdwardsPoint::from_bytes(&repr))
        .ok_or_else(|| malformed("not a valid, torsion-free Ed25519 point"))?;
    (point.to_bytes() == repr).then_some(point).ok_or_else(|| malformed("not canonically encoded"))
}

fn read_scalar(bytes: &[u8], name: &str) -> Result<Scalar, LinkingTagError> {
    let mut repr = [0u8; 32];
    repr.copy_from_slice(bytes);
    Option::<Scalar>::from(<Scalar as ciphersuite::group::ff::PrimeField>::from_repr(repr))
        .ok_or_else(|| LinkingTagError::MalformedEncoding(format!("{name} is not a canonical scalar")))
}

#[cfg(test)]
mod test {
    use super::*;
    use monero_oxide::ed25519::Point as MoneroPoint;
    use rand_core::OsRng;

    /// A stand-in for `H_p(P)`, derived the same way the wallet derives it.
    fn base() -> EdwardsPoint {
        EdwardsPoint(MoneroPoint::biased_hash(*b"GREASE-LINKING-TAG-TEST-BASE----").into())
    }

    fn share(tag: &[u8]) -> Scalar {
        hash_to_F::<Ed25519>(b"GREASE-LINKING-TAG-TEST", tag)
    }

    #[test]
    fn an_honest_contribution_verifies() {
        let s = share(b"honest");
        let contribution = PartialLinkingTag::prove(&s, &base(), &mut OsRng).unwrap();
        let v = Ed25519::generator() * s;
        let partial = contribution.verified_partial(&v, &base()).expect("an honest contribution verifies");
        assert_eq!(partial, base() * s);
    }

    #[test]
    fn the_base_is_torsion_free_and_the_partial_inherits_it() {
        assert!(is_torsion_free(&base()));
        let contribution = PartialLinkingTag::prove(&share(b"hygiene"), &base(), &mut OsRng).unwrap();
        assert!(check_point_hygiene(&contribution.partial, "partial").is_ok());
    }

    #[test]
    fn a_proof_does_not_transfer_to_another_verification_share() {
        let contribution = PartialLinkingTag::prove(&share(b"mine"), &base(), &mut OsRng).unwrap();
        let other = Ed25519::generator() * share(b"theirs");
        assert_eq!(
            contribution.verified_partial(&other, &base()),
            Err(LinkingTagError::ProofVerificationFailure)
        );
    }

    #[test]
    fn a_proof_does_not_transfer_to_another_base() {
        let s = share(b"mine");
        let contribution = PartialLinkingTag::prove(&s, &base(), &mut OsRng).unwrap();
        let other_base = EdwardsPoint(MoneroPoint::biased_hash(*b"GREASE-LINKING-TAG-OTHER-BASE---").into());
        let v = Ed25519::generator() * s;
        assert_eq!(
            contribution.verified_partial(&v, &other_base),
            Err(LinkingTagError::ProofVerificationFailure)
        );
    }

    #[test]
    fn a_tampered_partial_is_rejected() {
        let s = share(b"mine");
        let mut contribution = PartialLinkingTag::prove(&s, &base(), &mut OsRng).unwrap();
        contribution.partial += Ed25519::generator();
        let v = Ed25519::generator() * s;
        assert_eq!(
            contribution.verified_partial(&v, &base()),
            Err(LinkingTagError::ProofVerificationFailure)
        );
    }

    #[test]
    fn a_tampered_response_is_rejected() {
        let s = share(b"mine");
        let mut contribution = PartialLinkingTag::prove(&s, &base(), &mut OsRng).unwrap();
        contribution.proof.response += Scalar::ONE;
        let v = Ed25519::generator() * s;
        assert_eq!(
            contribution.verified_partial(&v, &base()),
            Err(LinkingTagError::ProofVerificationFailure)
        );
    }

    #[test]
    fn an_identity_partial_is_rejected_before_the_proof_is_checked() {
        let s = share(b"mine");
        let mut contribution = PartialLinkingTag::prove(&s, &base(), &mut OsRng).unwrap();
        contribution.partial = EdwardsPoint::identity();
        let v = Ed25519::generator() * s;
        assert_eq!(
            contribution.verified_partial(&v, &base()),
            Err(LinkingTagError::IdentityPoint("linking tag partial"))
        );
    }

    #[test]
    fn a_zero_share_cannot_be_proven() {
        assert_eq!(
            PartialLinkingTag::prove(&Scalar::ZERO, &base(), &mut OsRng),
            Err(LinkingTagError::ZeroShare)
        );
    }

    #[test]
    fn an_identity_base_is_refused() {
        assert_eq!(
            PartialLinkingTag::prove(&share(b"mine"), &EdwardsPoint::identity(), &mut OsRng),
            Err(LinkingTagError::IdentityPoint("linking tag base"))
        );
    }

    /// The wire boundary is where a torsioned or non-canonically encoded partial would have to enter. The two
    /// rules have *different* enforcers and must be pinned separately: `dalek_ff_group`'s decoder rejects
    /// torsion, but it reduces `y` mod `p`, so a non-canonical `y` decodes happily to the same point and only
    /// [`read_point`]'s re-encode check catches it.
    #[test]
    fn the_decoder_refuses_torsioned_and_non_canonical_points() {
        let decode = |hex_point: &str| {
            let mut bytes = PartialLinkingTag::prove(&share(b"wire"), &base(), &mut OsRng).unwrap().to_bytes();
            hex::decode_to_slice(hex_point, &mut bytes[..32]).unwrap();
            PartialLinkingTag::from_bytes(&bytes)
        };
        let reason = |hex_point: &str| match decode(hex_point) {
            Err(LinkingTagError::MalformedEncoding(why)) => why,
            other => panic!("expected a malformed encoding, got: {other:?}"),
        };
        // Points of order 8 and of order 4 — rejected by the decoder's subgroup check.
        assert!(reason("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa").contains("torsion-free"));
        assert!(reason("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f").contains("torsion-free"));
        // y = 1 + p, a non-canonical encoding of y = 1. The decoder *accepts* this — it reduces mod p — so it
        // is the re-encode check that refuses it. Without that check this would be a second wire encoding of
        // one partial.
        assert!(reason("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f").contains("canonically"));
    }

    #[test]
    fn the_encoding_round_trips() {
        let contribution = PartialLinkingTag::prove(&share(b"wire"), &base(), &mut OsRng).unwrap();
        let bytes = contribution.to_bytes();
        assert_eq!(bytes.len(), PARTIAL_LINKING_TAG_BYTES);
        assert_eq!(PartialLinkingTag::from_bytes(&bytes).unwrap(), contribution);

        let json = serde_json::to_string(&contribution).unwrap();
        assert_eq!(serde_json::from_str::<PartialLinkingTag>(&json).unwrap(), contribution);
    }

    #[test]
    fn malformed_encodings_are_refused() {
        assert!(matches!(
            PartialLinkingTag::from_bytes(&[0u8; 95]),
            Err(LinkingTagError::MalformedEncoding(_))
        ));
        // A scalar above the group order is not a canonical encoding.
        let mut bytes = PartialLinkingTag::prove(&share(b"wire"), &base(), &mut OsRng).unwrap().to_bytes();
        bytes[63] = 0xff;
        assert!(matches!(
            PartialLinkingTag::from_bytes(&bytes),
            Err(LinkingTagError::MalformedEncoding(_))
        ));
        assert!(serde_json::from_str::<PartialLinkingTag>("\"not hex\"").is_err());
    }
}
