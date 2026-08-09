//! Verifiable encryption of Ed25519 offsets to arbiter statements — the KEM/DEM core of the Grease v2 arbiter
//! design.
//!
//! Implements the algorithms `EncryptToStatement` and `DecryptWithAttestation` from `docs/src/40_arbiter.typ`
//! (labels `encStmt` / `decStmt`): identity-based encryption where the "identity" is a dispute statement
//! `m = (channel_id, update_count)` and the decryption key for `m` is the arbiter committee's BLS attestation
//! `σ_m = z·H_P(m)`. A party can seal an offset `ω` to `m` against the committee's *stable* master public key `Z`
//! long before anyone signs `m`; decryption becomes possible exactly when the committee attests `m`, and not
//! before.
//!
//! ```text
//! EncryptToStatement(ω, m, Z):   r ←$ Z_q*,  U = r·G_2,  y = e(H_P(m), Z)^r,  c = (ω + H_F(y)) mod ℓ
//! DecryptWithAttestation(U, c, σ_m):         y = e(σ_m, U),                   ω = (c − H_F(y)) mod ℓ
//! ```
//!
//! # The two moduli
//!
//! Two distinct prime orders are in play and must not be conflated:
//!
//! - `q`, the order of the BLS12-381 pairing groups — the domain of the KEM exponent `r`;
//! - `ℓ`, the order of the Ed25519 group — the domain of the offset `ω` and the mask modulus of the DEM.
//!
//! The spec's prose "random scalar r, 0 < r < N" is a short-exponent sampling bug if read with `N = ℓ`: sampling
//! `r` below `ℓ < q` would leak that the exponent lies in a known subrange. Here `r` is a [`BlsScalar`] — uniform
//! in `Z_q` by type — and only the mask arithmetic `c = ω + s` happens mod `ℓ` (enforced by [`Scalar`]'s field
//! arithmetic). A test pins the sampling domain by showing exponents `x` and `x + ℓ` produce distinct ciphertexts.
//!
//! # Wire hygiene
//!
//! [`EncryptedOffset`] deserialization is validated: `U` must be a canonical compressed encoding of a
//! *non-identity* point in the prime-order G2 subgroup, and `c` must be the canonical least residue mod `ℓ`.
//! Malleable encodings never reach protocol logic.

use dalek_ff_group::Scalar;
use ciphersuite::group::ff::{Field, PrimeField};
use hex::ToHex;
use ic_bls12_381::{pairing, G2Affine, Scalar as BlsScalar};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::attestation::{h_f, h_p, AttestationError, G1Point, G2Point, GtElement, Statement};

/// Errors arising from verifiable encryption.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum VerifiableEncryptionError {
    /// A BLS point failed validation (non-canonical encoding or outside the prime-order subgroup).
    #[error(transparent)]
    Attestation(#[from] AttestationError),
    /// A point that must not be the group identity was the identity.
    #[error("the point is the group identity, which is forbidden here")]
    IdentityPoint,
    /// The ciphertext scalar `c` is not canonical: it must be the least residue mod `ℓ`.
    #[error("ciphertext scalar is not the canonical least residue mod the Ed25519 group order")]
    NonCanonicalScalar,
    /// A hex field could not be decoded to the expected length.
    #[error("invalid hex encoding: {0}")]
    InvalidHex(String),
}

//--------------------------------------------------------------------------------------------------------------------
//                                                  EncryptedOffset
//--------------------------------------------------------------------------------------------------------------------

/// A verifiably encrypted offset: the ciphertext `(U, c)` of `EncryptToStatement`.
///
/// `U = r·G_2` is the KEM component (a BLS12-381 G2 point) and `c = (ω + H_F(y)) mod ℓ` the DEM component (an
/// Ed25519 scalar). Construction and deserialization both enforce wire hygiene: `U` non-identity and in the
/// prime-order subgroup, `c` canonical.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncryptedOffset {
    u: G2Point,
    c: Scalar,
}

impl EncryptedOffset {
    /// Assemble a ciphertext from its components, enforcing that `U` is not the identity.
    ///
    /// (`G2Point` is already subgroup-checked on decode, and a [`Scalar`] in memory is canonical by
    /// construction — the identity check is the one constraint the component types don't carry.)
    pub fn new(u: G2Point, c: Scalar) -> Result<Self, VerifiableEncryptionError> {
        if u.is_identity() {
            return Err(VerifiableEncryptionError::IdentityPoint);
        }
        Ok(EncryptedOffset { u, c })
    }

    /// The KEM component `U = r·G_2`.
    pub fn u(&self) -> &G2Point {
        &self.u
    }

    /// The DEM component `c = (ω + s) mod ℓ`.
    pub fn c(&self) -> &Scalar {
        &self.c
    }
}

/// The wire shape: `U` as the 96-byte compressed G2 encoding in hex, `c` as the 32-byte canonical scalar encoding
/// in hex.
#[derive(Serialize, Deserialize)]
struct EncryptedOffsetWire {
    u: G2Point,
    c: String,
}

impl Serialize for EncryptedOffset {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let wire = EncryptedOffsetWire { u: self.u, c: self.c.to_repr().encode_hex() };
        wire.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for EncryptedOffset {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // `G2Point`'s own deserializer has already rejected non-canonical bytes and non-subgroup points here.
        let wire = EncryptedOffsetWire::deserialize(deserializer)?;
        let c = decode_canonical_scalar(&wire.c).map_err(serde::de::Error::custom)?;
        EncryptedOffset::new(wire.u, c).map_err(serde::de::Error::custom)
    }
}

/// Decode a 32-byte hex string as a canonical Ed25519 scalar, rejecting any encoding that is not the least
/// residue mod `ℓ`.
fn decode_canonical_scalar(hex_str: &str) -> Result<Scalar, VerifiableEncryptionError> {
    let bytes: [u8; 32] =
        hex::FromHex::from_hex(hex_str).map_err(|e: hex::FromHexError| VerifiableEncryptionError::InvalidHex(format!("{e}")))?;
    Option::<Scalar>::from(Scalar::from_repr(bytes)).ok_or(VerifiableEncryptionError::NonCanonicalScalar)
}

//--------------------------------------------------------------------------------------------------------------------
//                                                    Encryption
//--------------------------------------------------------------------------------------------------------------------

/// `EncryptToStatement(ω, m, Z)`: seal the offset `ω` to the statement `m` under the arbiter's master public key
/// `Z`, sampling the KEM exponent from the given RNG.
///
/// The exponent `r` is uniform in `Z_q*` — the full BLS12-381 scalar field, **not** `Z_ℓ` (see the module docs on
/// the two moduli). Zero is excluded (resampled) because `U = 0·G_2` would be the identity and `y` the trivial
/// mask.
pub fn encrypt_to_statement<R: RngCore + CryptoRng>(
    omega: &Scalar,
    statement: &Statement,
    master_pk: &G2Point,
    rng: &mut R,
) -> Result<EncryptedOffset, VerifiableEncryptionError> {
    let r = std::iter::repeat_with(|| BlsScalar::random(&mut *rng))
        .find(|r| !bool::from(r.is_zero()))
        .expect("a uniform Z_q sample is nonzero with overwhelming probability");
    encrypt_to_statement_with_r(omega, statement, master_pk, &r)
}

/// `EncryptToStatement` with an explicit KEM exponent — the derandomized entry point the binding proof uses (its
/// per-share exponents `r_k` are PRF-derived, and its verifier recomputes opened ciphertexts from revealed `r_k`).
///
/// `r` must be nonzero and, for hiding, indistinguishable from uniform on `Z_q` — the [`BlsScalar`] type pins the
/// sampling domain to the pairing order `q`, never the mask modulus `ℓ`.
pub fn encrypt_to_statement_with_r(
    omega: &Scalar,
    statement: &Statement,
    master_pk: &G2Point,
    r: &BlsScalar,
) -> Result<EncryptedOffset, VerifiableEncryptionError> {
    if master_pk.is_identity() {
        return Err(VerifiableEncryptionError::IdentityPoint);
    }
    if bool::from(r.is_zero()) {
        return Err(VerifiableEncryptionError::IdentityPoint);
    }
    let u = G2Point::from(G2Affine::from(G2Affine::generator() * r));
    let y = GtElement::from(pairing(h_p(master_pk, statement).as_affine(), master_pk.as_affine()) * r);
    let s = h_f(statement, &u, &y);
    EncryptedOffset::new(u, *omega + s)
}

//--------------------------------------------------------------------------------------------------------------------
//                                                    Decryption
//--------------------------------------------------------------------------------------------------------------------

/// `DecryptWithAttestation(U, c, σ_m)`: recover the offset `ω = (c − H_F(e(σ_m, U))) mod ℓ` using the arbiter's
/// attestation of `m` as the decryption key.
///
/// This is *decryption*, not verification: a `σ_m` that is not the master key's signature on this statement
/// yields a uniformly wrong scalar, not an error. Callers that need to detect that (the dispute path does) check
/// the recovered offset against its public commitment, e.g. `ω·G = Q` or share consistency against the Feldman
/// commitments.
pub fn decrypt_with_attestation(
    ciphertext: &EncryptedOffset,
    statement: &Statement,
    sigma: &G1Point,
) -> Result<Scalar, VerifiableEncryptionError> {
    if sigma.is_identity() || ciphertext.u.is_identity() {
        return Err(VerifiableEncryptionError::IdentityPoint);
    }
    let y = GtElement::from(pairing(sigma.as_affine(), ciphertext.u.as_affine()));
    let s = h_f(statement, &ciphertext.u, &y);
    Ok(ciphertext.c - s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cryptography::attestation::test_helpers::{attest, generate_master_keypair};
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    fn setup(seed: u64) -> (BlsScalar, G2Point, Statement, Scalar, ChaCha20Rng) {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let (z, big_z) = generate_master_keypair(&mut rng);
        let statement = Statement::new(b"channel-xyz".to_vec(), 7);
        let omega = Scalar::random(&mut rng);
        (z, big_z, statement, omega, rng)
    }

    /// The Ed25519 group order ℓ as a BLS12-381 scalar (ℓ < q, so the embedding is exact).
    fn ell_as_bls_scalar() -> BlsScalar {
        let ell_minus_one = (-Scalar::ONE).to_repr();
        BlsScalar::from_bytes(&ell_minus_one).unwrap() + BlsScalar::from(1u64)
    }

    #[test]
    fn round_trip() {
        let (z, big_z, statement, omega, mut rng) = setup(1);
        let ciphertext = encrypt_to_statement(&omega, &statement, &big_z, &mut rng).unwrap();
        let sigma = attest(&z, &statement);
        let recovered = decrypt_with_attestation(&ciphertext, &statement, &sigma).unwrap();
        assert_eq!(recovered, omega);
    }

    #[test]
    fn round_trip_with_explicit_r() {
        let (z, big_z, statement, omega, _) = setup(2);
        let r = BlsScalar::from(31337u64);
        let ciphertext = encrypt_to_statement_with_r(&omega, &statement, &big_z, &r).unwrap();
        let sigma = attest(&z, &statement);
        assert_eq!(decrypt_with_attestation(&ciphertext, &statement, &sigma).unwrap(), omega);
    }

    #[test]
    fn wrong_statement_attestation_recovers_garbage() {
        let (z, big_z, statement, omega, mut rng) = setup(3);
        let ciphertext = encrypt_to_statement(&omega, &statement, &big_z, &mut rng).unwrap();
        // An attestation of the *previous* state must not unlock the offset sealed to state 7.
        let stale = Statement::new(b"channel-xyz".to_vec(), 6);
        let sigma_stale = attest(&z, &stale);
        // Decrypting with the honest statement but the stale key, and with the stale statement throughout, both fail.
        assert_ne!(decrypt_with_attestation(&ciphertext, &statement, &sigma_stale).unwrap(), omega);
        assert_ne!(decrypt_with_attestation(&ciphertext, &stale, &sigma_stale).unwrap(), omega);
    }

    #[test]
    fn wrong_master_key_attestation_recovers_garbage() {
        let (_, big_z, statement, omega, mut rng) = setup(4);
        let ciphertext = encrypt_to_statement(&omega, &statement, &big_z, &mut rng).unwrap();
        let (other_z, _) = generate_master_keypair(&mut rng);
        let sigma_other = attest(&other_z, &statement);
        assert_ne!(decrypt_with_attestation(&ciphertext, &statement, &sigma_other).unwrap(), omega);
    }

    #[test]
    fn tampered_u_recovers_garbage() {
        let (z, big_z, statement, omega, mut rng) = setup(5);
        let ciphertext = encrypt_to_statement(&omega, &statement, &big_z, &mut rng).unwrap();
        let sigma = attest(&z, &statement);
        let tampered_u = G2Point::from(G2Affine::from(ciphertext.u().as_affine() * BlsScalar::from(2u64)));
        let tampered = EncryptedOffset::new(tampered_u, *ciphertext.c()).unwrap();
        assert_ne!(decrypt_with_attestation(&tampered, &statement, &sigma).unwrap(), omega);
    }

    #[test]
    fn tampered_c_recovers_garbage() {
        let (z, big_z, statement, omega, mut rng) = setup(6);
        let ciphertext = encrypt_to_statement(&omega, &statement, &big_z, &mut rng).unwrap();
        let sigma = attest(&z, &statement);
        let tampered = EncryptedOffset::new(*ciphertext.u(), *ciphertext.c() + Scalar::ONE).unwrap();
        assert_ne!(decrypt_with_attestation(&tampered, &statement, &sigma).unwrap(), omega);
    }

    #[test]
    fn kem_exponent_domain_is_z_q_not_z_ell() {
        // Pins risk-assessment condition #1: the KEM exponent lives in Z_q (the pairing order), not Z_ℓ (the mask
        // modulus). If r were reduced mod ℓ anywhere on the way to U = r·G_2, the exponents x and x + ℓ would
        // collapse to the same ciphertext. In Z_q they are distinct scalars and must produce distinct U.
        let (_, big_z, statement, omega, _) = setup(7);
        let x = BlsScalar::from(0xdead_beef_u64);
        let x_plus_ell = x + ell_as_bls_scalar();
        let ct_x = encrypt_to_statement_with_r(&omega, &statement, &big_z, &x).unwrap();
        let ct_x_ell = encrypt_to_statement_with_r(&omega, &statement, &big_z, &x_plus_ell).unwrap();
        assert_ne!(ct_x.u(), ct_x_ell.u());
        assert_ne!(ct_x.c(), ct_x_ell.c());
    }

    #[test]
    fn kem_exponent_can_exceed_ell() {
        // The top of the sampling domain (q - 1 > ℓ) is a legal exponent and round-trips.
        let (z, big_z, statement, omega, _) = setup(8);
        let r_max = -BlsScalar::from(1u64);
        let ciphertext = encrypt_to_statement_with_r(&omega, &statement, &big_z, &r_max).unwrap();
        let sigma = attest(&z, &statement);
        assert_eq!(decrypt_with_attestation(&ciphertext, &statement, &sigma).unwrap(), omega);
    }

    #[test]
    fn zero_exponent_and_identity_points_are_rejected() {
        let (z, big_z, statement, omega, mut rng) = setup(9);
        assert_eq!(
            encrypt_to_statement_with_r(&omega, &statement, &big_z, &BlsScalar::from(0u64)),
            Err(VerifiableEncryptionError::IdentityPoint)
        );
        let identity_z = G2Point::from(G2Affine::identity());
        assert_eq!(
            encrypt_to_statement(&omega, &statement, &identity_z, &mut rng),
            Err(VerifiableEncryptionError::IdentityPoint)
        );
        let ciphertext = encrypt_to_statement(&omega, &statement, &big_z, &mut rng).unwrap();
        let identity_sigma = G1Point::from(ic_bls12_381::G1Affine::identity());
        assert_eq!(
            decrypt_with_attestation(&ciphertext, &statement, &identity_sigma),
            Err(VerifiableEncryptionError::IdentityPoint)
        );
        assert_eq!(EncryptedOffset::new(identity_z, Scalar::ONE), Err(VerifiableEncryptionError::IdentityPoint));
        let _ = (z, statement);
    }

    #[test]
    fn serde_round_trip() {
        let (z, big_z, statement, omega, mut rng) = setup(10);
        let ciphertext = encrypt_to_statement(&omega, &statement, &big_z, &mut rng).unwrap();
        let json = serde_json::to_string(&ciphertext).unwrap();
        let back: EncryptedOffset = serde_json::from_str(&json).unwrap();
        assert_eq!(ciphertext, back);
        let sigma = attest(&z, &statement);
        assert_eq!(decrypt_with_attestation(&back, &statement, &sigma).unwrap(), omega);
    }

    #[test]
    fn deserialize_rejects_non_canonical_c() {
        let (_, big_z, statement, omega, mut rng) = setup(11);
        let ciphertext = encrypt_to_statement(&omega, &statement, &big_z, &mut rng).unwrap();
        // ℓ itself: congruent to 0 mod ℓ but not the least residue, so the encoding is non-canonical.
        let ell_hex = "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010";
        assert!(matches!(decode_canonical_scalar(ell_hex), Err(VerifiableEncryptionError::NonCanonicalScalar)));
        let json = serde_json::to_string(&ciphertext).unwrap();
        let c_hex: String = ciphertext.c().to_repr().encode_hex();
        let tampered_json = json.replace(&c_hex, ell_hex);
        assert_ne!(json, tampered_json);
        assert!(serde_json::from_str::<EncryptedOffset>(&tampered_json).is_err());
    }

    #[test]
    fn deserialize_rejects_bad_u() {
        let (_, big_z, statement, omega, mut rng) = setup(12);
        let ciphertext = encrypt_to_statement(&omega, &statement, &big_z, &mut rng).unwrap();
        let json = serde_json::to_string(&ciphertext).unwrap();
        let u_hex: String = ciphertext.u().to_compressed().encode_hex();
        // Not a valid G2 encoding at all.
        let garbage = "ff".repeat(96);
        assert!(serde_json::from_str::<EncryptedOffset>(&json.replace(&u_hex, &garbage)).is_err());
        // A canonical encoding of the identity: subgroup-valid, but forbidden here.
        let identity_hex: String = G2Point::from(G2Affine::identity()).to_compressed().encode_hex();
        assert!(serde_json::from_str::<EncryptedOffset>(&json.replace(&u_hex, &identity_hex)).is_err());
    }

    #[test]
    fn fresh_randomness_gives_distinct_ciphertexts() {
        // Encrypting the same offset to the same statement twice must not repeat U (r_k reuse leaks ω across
        // ciphertexts — the binding proof rejects duplicate U for exactly this reason).
        let (_, big_z, statement, omega, mut rng) = setup(13);
        let ct1 = encrypt_to_statement(&omega, &statement, &big_z, &mut rng).unwrap();
        let ct2 = encrypt_to_statement(&omega, &statement, &big_z, &mut rng).unwrap();
        assert_ne!(ct1.u(), ct2.u());
        assert_ne!(ct1.c(), ct2.c());
    }
}
