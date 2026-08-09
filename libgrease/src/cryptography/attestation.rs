//! BLS12-381 attestation primitives for the Grease v2 arbiter.
//!
//! The v2 arbiter (see `docs/src/40_arbiter.typ`, §"Attestation as a decryption key" and §"Instantiation on the
//! Internet Computer") is a threshold-BLS committee whose signature on a statement `m = (channel_id, update_count)`
//! doubles as an identity-based decryption key for offsets encrypted to `m`. This module provides the party-side
//! plumbing for that scheme:
//!
//! - Wrapper types [`G1Point`], [`G2Point`] and [`GtElement`] over `ic_bls12_381` with validated, canonical
//!   serialization. The `ic_bls12_381` crate is DFINITY's maintained fork of zkcrypto's `bls12_381` and is the
//!   arithmetic used by `ic-vetkeys`, so byte-level compatibility with vetKD attestations is by construction.
//! - The deterministic [`Statement`] encoding.
//! - [`h_p`]: hash-to-G1 reproducing vetKD's *augmented* hash-to-curve (the derived public key is folded into the
//!   hash input).
//! - [`h_f`]: the mask hash `H_F: G_T -> Z_ell` mapping a pairing output to an Ed25519 scalar via wide reduction.
//! - [`verify_attestation`]: the BLS pairing check `e(sigma_m, G_2) = e(H_P(m), Z)`.
//!
//! # Frozen encodings
//!
//! Both channel parties must reproduce these byte encodings *exactly* — a divergence stays invisible until
//! dispute-path decryption fails. The following are therefore frozen; compatibility vectors cross-checked against
//! `ic-vetkeys` and `ark-bls12-381` live in `crate::tests::vetkd_compat_vectors`.
//!
//! | Object                | Encoding                                                                    |
//! |-----------------------|-----------------------------------------------------------------------------|
//! | G1 point              | 48-byte ZCash-style compressed encoding (`G1Affine::{to,from}_compressed`)  |
//! | G2 point              | 96-byte ZCash-style compressed encoding (`G2Affine::{to,from}_compressed`)  |
//! | G_T element           | 576-byte `Gt::to_bytes` (Fp12 as `c1 ‖ c0`, each 288 bytes; see below)      |
//! | Statement             | `u32-LE(len(channel_id)) ‖ channel_id ‖ u64-LE(update_count)`               |
//!
//! The G_T encoding is `ic_bls12_381::Gt::to_bytes`, which lays out the Fp12 element as `c1 ‖ c0` where each Fp6
//! is `c2 ‖ c1 ‖ c0`, each Fp2 is `c1 ‖ c0`, and each base-field Fp is a 48-byte big-endian integer. It is pinned
//! by a known-answer test below.

use ciphersuite::group::ff::Field;
use dalek_ff_group::Scalar;
use hex::{FromHex, FromHexError, ToHex};
use ic_bls12_381::hash_to_curve::{ExpandMsgXmd, HashToCurve};
use ic_bls12_381::{multi_miller_loop, G1Affine, G1Projective, G2Affine, G2Prepared, Gt, Scalar as BlsScalar};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use thiserror::Error;

/// Length of a compressed G1 point in bytes.
pub const G1_COMPRESSED_LEN: usize = 48;
/// Length of a compressed G2 point in bytes.
pub const G2_COMPRESSED_LEN: usize = 96;
/// Length of the canonical G_T serialization in bytes (uncompressed Fp12).
pub const GT_SERIALIZED_LEN: usize = 576;

/// Domain-separation tag for [`h_p`], vetKD's *augmented* hash-to-G1.
///
/// This is the RFC 9380 ciphersuite `BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_` with the message-augmentation tag
/// variant (`_AUG_`), exactly as used by `ic-vetkeys`' `augmented_hash_to_g1`. The augmentation itself is the
/// derived public key prepended to the message (see [`h_p`]); the DST does not change per key.
pub const HASH_TO_G1_AUG_DST: &[u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_AUG_";

/// Grease-unique domain-separation tag for [`h_f`].
///
/// Chosen to be disjoint from every DST vetKD itself feeds a pairing output into, so a Grease mask can never
/// collide with a vetKD-internal hash of the same G_T element. Versioned so a future encoding change gets a new
/// tag rather than a silent divergence.
pub const H_F_DST: &[u8] = b"GREASE-V2-HF-GT-TO-ED25519-SHA512-V1";

/// Errors arising from attestation plumbing.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AttestationError {
    /// The byte string is not the canonical compressed encoding of a point in the prime-order subgroup.
    #[error("byte string is not a canonical encoding of a BLS12-381 subgroup point")]
    InvalidPoint,
    /// A point that must not be the group identity was the identity.
    #[error("the point is the group identity, which is forbidden here")]
    IdentityPoint,
    /// A hex string could not be decoded.
    #[error("invalid hex encoding: {0}")]
    InvalidHex(String),
    /// The pairing check failed: sigma is not the master key's signature on this statement.
    #[error("attestation verification failed: the signature does not attest this statement under this key")]
    VerificationFailure,
}

impl From<FromHexError> for AttestationError {
    fn from(e: FromHexError) -> Self {
        AttestationError::InvalidHex(format!("{e}"))
    }
}

//--------------------------------------------------------------------------------------------------------------------
//                                                  Wrapper types
//--------------------------------------------------------------------------------------------------------------------

/// A point in the BLS12-381 G1 group. Attestations `sigma_m = z·H_P(m)` live here.
///
/// Deserialization is validated: only canonical compressed encodings of points in the prime-order subgroup are
/// accepted (`G1Affine::from_compressed` performs the subgroup check).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct G1Point(G1Affine);

/// A point in the BLS12-381 G2 group. The arbiter's master public key `Z = z·G_2` and the ciphertext component
/// `U = r·G_2` live here.
///
/// Deserialization is validated: only canonical compressed encodings of points in the prime-order subgroup are
/// accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct G2Point(G2Affine);

/// An element of the BLS12-381 target group G_T — the output of the pairing `e: G1 × G2 → G_T`.
///
/// Its canonical fixed-length serialization is [`GtElement::to_bytes`] (576 bytes). G_T elements are never
/// transmitted in the Grease protocol — they exist only as local pairing outputs fed to [`h_f`] — so this type is
/// serialize-only: `ic_bls12_381` offers no validated G_T decoding, and none is needed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GtElement(Gt);

macro_rules! impl_compressed_point {
    ($name:ident, $affine:ty, $len:expr) => {
        impl $name {
            /// The canonical compressed encoding of this point.
            pub fn to_compressed(&self) -> [u8; $len] {
                self.0.to_compressed()
            }

            /// Decode a canonical compressed encoding, rejecting non-canonical bytes and points outside the
            /// prime-order subgroup. The identity is a valid encoding; reject it at use sites where it is
            /// meaningless (as [`verify_attestation`] does).
            pub fn from_compressed(bytes: &[u8; $len]) -> Result<Self, AttestationError> {
                Option::<$affine>::from(<$affine>::from_compressed(bytes)).map($name).ok_or(AttestationError::InvalidPoint)
            }

            /// Access the underlying affine point.
            pub fn as_affine(&self) -> &$affine {
                &self.0
            }

            /// Whether this point is the group identity.
            pub fn is_identity(&self) -> bool {
                self.0.is_identity().into()
            }
        }

        impl From<$affine> for $name {
            fn from(p: $affine) -> Self {
                $name(p)
            }
        }

        impl ToHex for $name {
            fn encode_hex<T: FromIterator<char>>(&self) -> T {
                self.to_compressed().encode_hex()
            }

            fn encode_hex_upper<T: FromIterator<char>>(&self) -> T {
                self.to_compressed().encode_hex_upper()
            }
        }

        impl FromHex for $name {
            type Error = AttestationError;

            fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
                let bytes = <[u8; $len]>::from_hex(hex)?;
                Self::from_compressed(&bytes)
            }
        }

        impl Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(&self.encode_hex::<String>())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let hex_str = String::deserialize(deserializer)?;
                Self::from_hex(&hex_str).map_err(serde::de::Error::custom)
            }
        }
    };
}

impl_compressed_point!(G1Point, G1Affine, G1_COMPRESSED_LEN);
impl_compressed_point!(G2Point, G2Affine, G2_COMPRESSED_LEN);

impl GtElement {
    /// The canonical fixed-length serialization of this G_T element (see the module docs for the frozen layout).
    pub fn to_bytes(&self) -> [u8; GT_SERIALIZED_LEN] {
        self.0.to_bytes()
    }

    /// Access the underlying `Gt` element.
    pub fn as_gt(&self) -> &Gt {
        &self.0
    }
}

impl From<Gt> for GtElement {
    fn from(gt: Gt) -> Self {
        GtElement(gt)
    }
}

impl Serialize for GtElement {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_bytes().encode_hex::<String>())
    }
}

//--------------------------------------------------------------------------------------------------------------------
//                                                Statement encoding
//--------------------------------------------------------------------------------------------------------------------

/// The dispute statement `m_i = (channel_id, i)`: "on channel `channel_id`, state `i` is the latest".
///
/// Its byte encoding, [`Statement::to_bytes`], is the identity the arbiter attests and the identity offsets are
/// encrypted to, so it is deterministic and frozen: `u32-LE(len(channel_id)) ‖ channel_id ‖ u64-LE(update_count)`.
/// The length prefix keeps distinct `(channel_id, update_count)` pairs from ever encoding to the same bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Statement {
    channel_id: Vec<u8>,
    update_count: u64,
}

impl Statement {
    /// Create the statement "on this channel, state `update_count` is the latest".
    pub fn new(channel_id: impl Into<Vec<u8>>, update_count: u64) -> Self {
        Statement { channel_id: channel_id.into(), update_count }
    }

    /// The channel identifier this statement speaks about.
    pub fn channel_id(&self) -> &[u8] {
        &self.channel_id
    }

    /// The state index this statement claims is the latest.
    pub fn update_count(&self) -> u64 {
        self.update_count
    }

    /// The frozen byte encoding: `u32-LE(len(channel_id)) ‖ channel_id ‖ u64-LE(update_count)`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(4 + self.channel_id.len() + 8);
        bytes.extend_from_slice(&(self.channel_id.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.channel_id);
        bytes.extend_from_slice(&self.update_count.to_le_bytes());
        bytes
    }
}

//--------------------------------------------------------------------------------------------------------------------
//                                                     Hashing
//--------------------------------------------------------------------------------------------------------------------

/// `H_P(m)`: hash a statement to a G1 point, reproducing vetKD's *augmented* hash-to-curve.
///
/// vetKD folds the derived public key into the hash input: the point is `H2G1(dpk ‖ m)` under
/// [`HASH_TO_G1_AUG_DST`], where `dpk` is the 96-byte compressed G2 derived public key. The `dpk` parameter is
/// explicit so the follow-up vectors ticket can cross-check this function against `ic-vetkeys` byte-for-byte; in
/// the Grease protocol it is the arbiter's published master public key `Z` for the fixed context.
pub fn h_p(dpk: &G2Point, statement: &Statement) -> G1Point {
    let m = statement.to_bytes();
    let mut input = Vec::with_capacity(G2_COMPRESSED_LEN + m.len());
    input.extend_from_slice(&dpk.to_compressed());
    input.extend_from_slice(&m);
    let point = <G1Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(input, HASH_TO_G1_AUG_DST);
    G1Point(G1Affine::from(point))
}

/// `H_F: G_T → Z_ell`: hash a pairing output to an Ed25519 scalar — the mask `s` in `EncryptToStatement` /
/// `DecryptWithAttestation`.
///
/// The hash input is length-prefixed rather than naively concatenated (`dst ‖ data` has transposition
/// collisions) and binds the statement and the ciphertext's ephemeral point alongside the mask source:
///
/// ```text
/// SHA-512( u64-LE(len(DST)) ‖ DST ‖ u64-LE(len(m)) ‖ m ‖ ser_G2(U) ‖ ser_GT(y) )
/// ```
///
/// where `m` is the frozen [`Statement`] encoding, `ser_G2` the 96-byte compressed encoding and `ser_GT` the
/// canonical 576-byte G_T serialization ([`GtElement::to_bytes`]). `U` and `y` are fixed-length, so only the
/// variable-length fields carry prefixes.
///
/// The 64 digest bytes are read as an integer and *wide-reduced* modulo `ell` (the Ed25519 group order), keeping
/// the mask within 2^-128 of uniform on `Z_ell` — a hard requirement for `c = ω + s` to be a sound one-time pad,
/// not an implementation detail. Never replace this with a 32-byte narrow reduction.
pub fn h_f(statement: &Statement, u: &G2Point, y: &GtElement) -> Scalar {
    let m = statement.to_bytes();
    let digest = Sha512::new()
        .chain_update((H_F_DST.len() as u64).to_le_bytes())
        .chain_update(H_F_DST)
        .chain_update((m.len() as u64).to_le_bytes())
        .chain_update(m)
        .chain_update(u.to_compressed())
        .chain_update(y.to_bytes())
        .finalize();
    Scalar::from_bytes_mod_order_wide(&digest.into())
}

//--------------------------------------------------------------------------------------------------------------------
//                                              Attestation verification
//--------------------------------------------------------------------------------------------------------------------

/// Verify that `sigma` is the arbiter's attestation of `statement` under the master public key `master_pk`:
/// the BLS pairing check `e(sigma, G_2) = e(H_P(m), Z)`.
///
/// Identity points are rejected outright: an identity `Z` would verify any identity signature, and an identity
/// `sigma` attests nothing.
pub fn verify_attestation(sigma: &G1Point, statement: &Statement, master_pk: &G2Point) -> Result<(), AttestationError> {
    if sigma.is_identity() || master_pk.is_identity() {
        return Err(AttestationError::IdentityPoint);
    }
    let h = h_p(master_pk, statement);
    // e(sigma, -G_2) · e(H_P(m), Z) = 1  ⇔  e(sigma, G_2) = e(H_P(m), Z), in one multi-Miller loop.
    let neg_g2 = G2Prepared::from(-G2Affine::generator());
    let z = G2Prepared::from(*master_pk.as_affine());
    let check = multi_miller_loop(&[(sigma.as_affine(), &neg_g2), (h.as_affine(), &z)]).final_exponentiation();
    match check == Gt::identity() {
        true => Ok(()),
        false => Err(AttestationError::VerificationFailure),
    }
}

//--------------------------------------------------------------------------------------------------------------------
//                                                 Test-only helpers
//--------------------------------------------------------------------------------------------------------------------

/// Test-only helpers standing in for the arbiter committee: a locally generated master key and single-signer
/// attestations. In production the master secret `z` exists only as shares across the committee; nothing outside
/// tests may ever hold it whole.
#[cfg(any(test, feature = "mocks"))]
pub mod test_helpers {
    use super::*;
    use rand_core::{CryptoRng, RngCore};

    /// Generate a master keypair `(z, Z = z·G_2)` as a stand-in for the arbiter committee's threshold key.
    pub fn generate_master_keypair<R: RngCore + CryptoRng>(rng: &mut R) -> (BlsScalar, G2Point) {
        let z = BlsScalar::random(rng);
        (z, master_public_key(&z))
    }

    /// The master public key `Z = z·G_2` for a master secret `z`.
    pub fn master_public_key(z: &BlsScalar) -> G2Point {
        G2Point::from(G2Affine::from(G2Affine::generator() * z))
    }

    /// Attest a statement: `sigma_m = z·H_P(m)`, the committee's BLS signature on `m` — and the decryption key
    /// for everything encrypted to `m`.
    pub fn attest(z: &BlsScalar, statement: &Statement) -> G1Point {
        let dpk = master_public_key(z);
        let h = h_p(&dpk, statement);
        G1Point::from(G1Affine::from(h.as_affine() * z))
    }
}

#[cfg(test)]
mod tests {
    use super::test_helpers::{attest, generate_master_keypair, master_public_key};
    use super::*;
    use ic_bls12_381::pairing;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    fn fixed_master_secret() -> BlsScalar {
        BlsScalar::from(0x1234_5678_90ab_cdef_u64)
    }

    #[test]
    fn g1_compressed_round_trip() {
        let z = fixed_master_secret();
        let sigma = attest(&z, &Statement::new(b"chan".to_vec(), 3));
        let bytes = sigma.to_compressed();
        let back = G1Point::from_compressed(&bytes).unwrap();
        assert_eq!(sigma, back);
    }

    #[test]
    fn g2_compressed_round_trip() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (_, big_z) = generate_master_keypair(&mut rng);
        let bytes = big_z.to_compressed();
        let back = G2Point::from_compressed(&bytes).unwrap();
        assert_eq!(big_z, back);
    }

    #[test]
    fn serde_round_trips() {
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        let (z, big_z) = generate_master_keypair(&mut rng);
        let sigma = attest(&z, &Statement::new(b"chan".to_vec(), 1));

        let json = serde_json::to_string(&big_z).unwrap();
        let back: G2Point = serde_json::from_str(&json).unwrap();
        assert_eq!(big_z, back);

        let json = serde_json::to_string(&sigma).unwrap();
        let back: G1Point = serde_json::from_str(&json).unwrap();
        assert_eq!(sigma, back);

        let m = Statement::new(b"id".to_vec(), 9);
        let json = serde_json::to_string(&m).unwrap();
        let back: Statement = serde_json::from_str(&json).unwrap();
        assert_eq!(m, back);
    }

    #[test]
    fn invalid_point_encodings_are_rejected() {
        assert_eq!(G1Point::from_compressed(&[0xFF; G1_COMPRESSED_LEN]), Err(AttestationError::InvalidPoint));
        assert_eq!(G2Point::from_compressed(&[0xFF; G2_COMPRESSED_LEN]), Err(AttestationError::InvalidPoint));
        assert!(G1Point::from_hex("beef").is_err());
    }

    #[test]
    fn statement_encoding_is_frozen() {
        let m = Statement::new(b"chan".to_vec(), 7);
        let expected = [4u8, 0, 0, 0, b'c', b'h', b'a', b'n', 7, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(m.to_bytes(), expected);
    }

    #[test]
    fn statement_encoding_separates_boundaries() {
        // Without the length prefix these two would collide at the id/count boundary.
        let a = Statement::new(b"ab".to_vec(), 0x63);
        let b = Statement::new(b"abc".to_vec(), 0);
        assert_ne!(a.to_bytes(), b.to_bytes());
    }

    #[test]
    fn gt_serialization_is_frozen() {
        // Pins the 576-byte G_T encoding to `ic_bls12_381 0.10`'s `Gt::to_bytes` (Fp12 as c1 ‖ c0). If a
        // dependency change alters this, every sealed offset in flight becomes undecryptable — this test failing
        // means the encoding moved, not that it should be re-pinned casually.
        let y = GtElement::from(pairing(&G1Affine::generator(), &G2Affine::generator()));
        let bytes = y.to_bytes();
        assert_eq!(bytes.len(), GT_SERIALIZED_LEN);
        let digest = Sha512::digest(bytes);
        assert_eq!(hex::encode(&digest[..32]), "1851021aa588d875160b2cde03248cef08f39b121fc4d7655fbbec012f944571");
    }

    #[test]
    fn h_p_is_deterministic_and_domain_separated() {
        let z = fixed_master_secret();
        let dpk = master_public_key(&z);
        let m = Statement::new(b"chan".to_vec(), 1);
        assert_eq!(h_p(&dpk, &m), h_p(&dpk, &m));
        // Different statement, different point.
        assert_ne!(h_p(&dpk, &m), h_p(&dpk, &Statement::new(b"chan".to_vec(), 2)));
        // Different dpk, different point — the augmentation is doing its job.
        let other_dpk = master_public_key(&BlsScalar::from(999u64));
        assert_ne!(h_p(&dpk, &m), h_p(&other_dpk, &m));
    }

    #[test]
    fn h_f_is_deterministic_and_input_sensitive() {
        let z = fixed_master_secret();
        let big_z = master_public_key(&z);
        let u = G2Point::from(G2Affine::from(G2Affine::generator() * &BlsScalar::from(5u64)));
        let m = Statement::new(b"chan".to_vec(), 1);
        let y = GtElement::from(pairing(h_p(&big_z, &m).as_affine(), big_z.as_affine()));

        let s = h_f(&m, &u, &y);
        assert_eq!(s, h_f(&m, &u, &y));
        assert_ne!(s, Scalar::ZERO);
        // Any input moving moves the mask.
        assert_ne!(s, h_f(&Statement::new(b"chan".to_vec(), 2), &u, &y));
        let other_u = G2Point::from(G2Affine::from(G2Affine::generator() * &BlsScalar::from(6u64)));
        assert_ne!(s, h_f(&m, &other_u, &y));
        let other_y = GtElement::from(pairing(&G1Affine::generator(), big_z.as_affine()));
        assert_ne!(s, h_f(&m, &u, &other_y));
    }

    #[test]
    fn h_f_known_answer() {
        // Known-answer vector freezing H_F end to end: DST, length prefixes, point/G_T serialization and the
        // wide reduction. Recompute only on a deliberate, versioned change of H_F_DST.
        let m = Statement::new(b"grease-kat".to_vec(), 42);
        let u = G2Point::from(G2Affine::from(G2Affine::generator() * &BlsScalar::from(11u64)));
        let y = GtElement::from(pairing(&G1Affine::generator(), &G2Affine::generator()));
        let s = h_f(&m, &u, &y);
        assert_eq!(hex::encode(s.to_bytes()), "8fda2c2830cb329954df9dc60f26e94e5a36d3ade55e439d17a0c5804f258303");
    }

    #[test]
    fn attestation_verifies_and_decryption_masks_agree() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let (z, big_z) = generate_master_keypair(&mut rng);
        let m = Statement::new(b"channel-xyz".to_vec(), 12);
        let sigma = attest(&z, &m);
        verify_attestation(&sigma, &m, &big_z).unwrap();

        // The IBE correctness identity behind EncryptToStatement/DecryptWithAttestation:
        // e(H_P(m), Z)^r  ==  e(sigma_m, r·G_2).
        let r = BlsScalar::from(31337u64);
        let u = G2Point::from(G2Affine::from(G2Affine::generator() * &r));
        let y_enc = GtElement::from(pairing(h_p(&big_z, &m).as_affine(), big_z.as_affine()) * &r);
        let y_dec = GtElement::from(pairing(sigma.as_affine(), u.as_affine()));
        assert_eq!(y_enc, y_dec);
        assert_eq!(h_f(&m, &u, &y_enc), h_f(&m, &u, &y_dec));
    }

    #[test]
    fn attestation_rejects_wrong_statement_key_and_identity() {
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        let (z, big_z) = generate_master_keypair(&mut rng);
        let m = Statement::new(b"channel-xyz".to_vec(), 12);
        let sigma = attest(&z, &m);

        let stale = Statement::new(b"channel-xyz".to_vec(), 11);
        assert_eq!(verify_attestation(&sigma, &stale, &big_z), Err(AttestationError::VerificationFailure));

        let (_, other_z) = generate_master_keypair(&mut rng);
        assert_eq!(verify_attestation(&sigma, &m, &other_z), Err(AttestationError::VerificationFailure));

        let identity_sigma = G1Point::from(G1Affine::identity());
        assert_eq!(verify_attestation(&identity_sigma, &m, &big_z), Err(AttestationError::IdentityPoint));

        let identity_key = G2Point::from(G2Affine::identity());
        assert_eq!(verify_attestation(&sigma, &m, &identity_key), Err(AttestationError::IdentityPoint));
    }
}
