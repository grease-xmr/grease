//! vetKD compatibility vectors for `H_P` and the G_T encoding (hard gate).
//!
//! Both channel parties run the same `cryptography::attestation` code, so cut-and-choose can never catch a
//! *consistently* wrong `H_P` or G_T serialization — the mistake would surface only when a real vetKD attestation
//! fails to decrypt on the dispute path, i.e. when value is already at stake. These tests are the gate that keeps
//! that from happening (`docs/src/40_arbiter.typ` §icp: "the group placement, point serialization, and especially
//! the hash-to-curve derivation — which augments the hashed statement with the derived public key — must be
//! reproduced exactly by the party-side encryptor").
//!
//! Two independent implementations are checked against **frozen literals** (never recomputed on both sides of an
//! assert, so a silent dependency upgrade that changes hashing or serialization fails loudly):
//!
//! - **`ic-vetkeys`** (DFINITY's client library — the code real vetKD users run) cross-checks `H_P`. Its augmented
//!   hash-to-curve is private, but `verify_bls_signature(dpk, input, sig)` accepts `sig = z·H` for `dpk = z·G_2`
//!   **iff** `H` equals its own `augmented_hash_to_g1(dpk_compressed ‖ input)`, so verification of a signature built
//!   from a frozen `H_P` literal is an equality test on the hash itself. An `IbeCiphertext` round-trip then proves
//!   the dispute-path property end to end: a Grease-computed attestation is a working vetKD IBE decryption key
//!   (ic-vetkeys' IBE also derives its seed mask from `Gt::to_bytes`, exercising the G_T encoding in their DEM).
//! - **`ark-bls12-381`** (arkworks — an independent pairing/field implementation sharing no code with
//!   `ic_bls12_381`; ic-vetkeys itself links the very same `ic_bls12_381 0.10`, so it cannot serve as the second
//!   library for G_T) cross-checks the 576-byte G_T vector value *and* the frozen `c1 ‖ c0` big-endian layout.
//!
//! The vetKD `DerivedPublicKey` two-step derivation (master key → canister key → context sub-key) enters `H_P`
//! only through the derived key's 96-byte compressed encoding, which is exactly the `dpk` parameter of
//! `attestation::h_p`. The vectors below therefore cover derived keys of any provenance: the dpk here is an
//! arbitrary G2 point with a known (nothing-up-my-sleeve) discrete log, which is what makes the signature-based
//! hash equality check possible at all.

use crate::cryptography::attestation::{h_p, G2Point, Statement};
use ark_ec::pairing::Pairing;
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField};
use ic_bls12_381::{pairing, G1Affine, G2Affine, Scalar as BlsScalar};
use ic_vetkeys::{verify_bls_signature, DerivedPublicKey, IbeCiphertext, IbeIdentity, IbeSeed, VetKey};

/// Nothing-up-my-sleeve master secret: the little-endian interpretation of this ASCII string (a canonical BLS12-381
/// scalar — its top byte `0x31` keeps it below the group order).
const MASTER_SECRET_ASCII: &[u8; 32] = b"GREASE-V2-VETKD-COMPAT-VECTOR-01";

/// Frozen: the 96-byte compressed derived public key `Z = z·G_2` for the master secret above.
const DPK_HEX: &str = concat!(
    "800c1289bd389dd4725f55ae5ff9b83bd730937bfcc2ffec275cbd339e2abf9fe9549a197d58b707120e765c0965edee",
    "194f4ab91de586560e24ad128082ce17734dfa89974732f0377c874a2a5bc0f46c0543d32e8a936c09d26a5ba0a1ead1",
);

/// Frozen: the canonical 576-byte serialization of `e(G_1, G_2)` (the pairing of the standard generators),
/// as produced by `ic_bls12_381::Gt::to_bytes` — Fp12 laid out `c1 ‖ c0`, each Fp6 `c2 ‖ c1 ‖ c0`, each Fp2
/// `c1 ‖ c0`, each Fp a 48-byte big-endian integer. If this test fails after a dependency change, every sealed
/// offset in flight has become undecryptable — the encoding moved; do not re-pin casually.
const GT_GENERATOR_HEX: &str = concat!(
    "0f41e58663bf08cf068672cbd01a7ec73baca4d72ca93544deff686bfd6df543d48eaa24afe47e1efde449383b67663104c581234d086a9902249b64728ffd21",
    "a189e87935a954051c7cdba7b3872629a4fafc05066245cb9108f0242d0fe3ef03350f55a7aefcd3c31b4fcb6ce5771cc6a0e9786ab5973320c806ad36082910",
    "7ba810c5a09ffdd9be2291a0c25a99a211b8b424cd48bf38fcef68083b0b0ec5c81a93b330ee1a677d0d15ff7b984e8978ef48881e32fac91b93b47333e2ba57",
    "06fba23eb7c5af0d9f80940ca771b6ffd5857baaf222eb95a7d2809d61bfe02e1bfd1b68ff02f0b8102ae1c2d5d5ab1a19f26337d205fb469cd6bd15c3d5a04d",
    "c88784fbb3d0b2dbdea54d43b2b73f2cbb12d58386a8703e0f948226e47ee89d018107154f25a764bd3c79937a45b84546da634b8f6be14a8061e55cceba478b",
    "23f7dacaa35c8ca78beae9624045b4b601b2f522473d171391125ba84dc4007cfbf2f8da752f7c74185203fcca589ac719c34dffbbaad8431dad1c1fb597aaa5",
    "193502b86edb8857c273fa075a50512937e0794e1e65a7617c90d8bd66065b1fffe51d7a579973b1315021ec3c19934f1368bb445c7c2d209703f239689ce34c",
    "0378a68e72a6b3b216da0e22a5031b54ddff57309396b38c881c4c849ec23e87089a1c5b46e5110b86750ec6a532348868a84045483c92b7af5af689452eafab",
    "f1a8943e50439f1d59882a98eaa0170f1250ebd871fc0a92a7b2d83168d0d727272d441befa15c503dd8e90ce98db3e7b6d194f60839c508a84305aaca1789b6",
);

/// A representative 65-character v2 channel id (`"XGC"` + 62 hex characters).
const CHANNEL_ID_65: &[u8] = b"XGC00112233445566778899aabbccddeeff00112233445566778899aabbccdife";

fn master_secret() -> BlsScalar {
    BlsScalar::from_bytes(MASTER_SECRET_ASCII).unwrap()
}

fn grease_dpk() -> G2Point {
    G2Point::from(G2Affine::from(G2Affine::generator() * master_secret()))
}

fn vetkd_dpk() -> DerivedPublicKey {
    DerivedPublicKey::deserialize(&hex::decode(DPK_HEX).unwrap()).unwrap()
}

/// The frozen `H_P` vectors: edge-shaped statements paired with the 48-byte compressed `H_P(dpk, m)` each must
/// hash to. Shapes: empty id at both count extremes, a 1-byte id, a real 65-character channel id, a 32-byte
/// binary id at a u32 boundary count, and an id that is itself a valid statement encoding (nesting shape).
fn h_p_vectors() -> Vec<(Statement, &'static str)> {
    vec![
        (
            Statement::new(Vec::new(), 0),
            "ae3224a1cab05a81dc09531746e93f607080ccd68fc8704c75be252790c93e968a88340d78ea8b176e1c743c1fbd4e43",
        ),
        (
            Statement::new(Vec::new(), u64::MAX),
            "a96190a39794b996877c78e353a962f69f2c51f0ee82343a884c050d72cb26268de35c3f848d7e21205f53cfbcc3853a",
        ),
        (
            Statement::new(vec![0u8], 1),
            "924335f3d62246d1faa0e3d3c0263ae679d342d83228b5ea3d69f6cced0c2c6bab95d719bd72fc9b05018c9867e36233",
        ),
        (
            Statement::new(CHANNEL_ID_65.to_vec(), 7),
            "b14eb946d6741494ec94f86517d6d12b567ed50ee3b1132fdf87c7f124e4d275475e2dcb0e7c5601beb525731386672d",
        ),
        (
            Statement::new((0u8..32).collect::<Vec<u8>>(), 1u64 << 32),
            "a93ae08ab6b967a1c96c4949fe80825e57a23cec01136d1e08bd0d5c09d3e78177b1508f4cbe5bdbdae3b00d2e931f15",
        ),
        (
            Statement::new(Statement::new(b"x".to_vec(), 1).to_bytes(), 2),
            "852acb26be468f79992b8a53dc30c2eb0a5023a0fdbe6695c6a22d4580585eef3e509e47a42188e3142880e7762c9c40",
        ),
    ]
}

/// Decode a frozen 48-byte compressed G1 hex literal.
fn g1_from_hex(hex_str: &str) -> G1Affine {
    let bytes: [u8; 48] = hex::decode(hex_str).unwrap().try_into().unwrap();
    G1Affine::from_compressed(&bytes).unwrap()
}

#[test]
fn master_dpk_matches_frozen_vector_and_ic_vetkeys_roundtrip() {
    // Grease side: z·G_2 serializes to the frozen literal.
    assert_eq!(hex::encode(grease_dpk().to_compressed()), DPK_HEX);
    // ic-vetkeys side: the same bytes are a valid DerivedPublicKey and survive its serialize round-trip unchanged,
    // pinning the shared 96-byte compressed G2 encoding.
    assert_eq!(hex::encode(vetkd_dpk().serialize()), DPK_HEX);
}

#[test]
fn h_p_matches_frozen_vectors() {
    let dpk = grease_dpk();
    h_p_vectors()
        .iter()
        .for_each(|(m, expected)| assert_eq!(&hex::encode(h_p(&dpk, m).to_compressed()), expected, "H_P drifted for {m:?}"));
}

#[test]
fn frozen_h_p_vectors_verify_as_vetkd_bls_signatures() {
    // For dpk = z·G_2, ic-vetkeys accepts sig = z·H as an augmented BLS signature on `input` iff
    // H == augmented_hash_to_g1(dpk_compressed ‖ input): e(z·H, G_2) = e(H_aug, z·G_2) ⇔ H = H_aug. The signature
    // is built from the *frozen literal*, not from `h_p`, so this asserts ic-vetkeys' own hash-to-curve against
    // the literal — nothing is recomputed on both sides.
    let z = master_secret();
    let dpk = vetkd_dpk();
    h_p_vectors().iter().for_each(|(m, h_hex)| {
        let sigma = G1Affine::from(g1_from_hex(h_hex) * z).to_compressed();
        assert!(verify_bls_signature(&dpk, &m.to_bytes(), &sigma), "ic-vetkeys disagrees with the frozen H_P for {m:?}");
        // Control: the same signature must not verify a different statement, so the check has teeth.
        let other = Statement::new(m.channel_id().to_vec(), m.update_count().wrapping_add(1));
        assert!(!verify_bls_signature(&dpk, &other.to_bytes(), &sigma));
    });
}

#[test]
fn grease_attestation_is_a_working_vetkd_ibe_decryption_key() {
    // The dispute-path property end to end: an attestation sigma_m = z·H_P(m) computed with *Grease's* h_p
    // decrypts a ciphertext produced by *ic-vetkeys'* IBE for identity m — which internally uses its own
    // augmented hash-to-curve, pairing, and Gt::to_bytes-derived seed mask.
    let z = master_secret();
    let m = Statement::new(CHANNEL_ID_65.to_vec(), 42);
    let sigma = G1Affine::from(h_p(&grease_dpk(), &m).as_affine() * z);
    let vetkey = VetKey::deserialize(&sigma.to_compressed()).unwrap();

    let msg = b"grease dispute-path offset recovery";
    let seed = IbeSeed::from_bytes(&[0x5e; 32]).unwrap();
    let ct = IbeCiphertext::encrypt(&vetkd_dpk(), &IbeIdentity::from_bytes(&m.to_bytes()), msg, &seed);
    assert_eq!(ct.decrypt(&vetkey).unwrap(), msg.to_vec());

    // An attestation for any other statement must fail to decrypt.
    let stale = Statement::new(CHANNEL_ID_65.to_vec(), 41);
    let wrong_sigma = G1Affine::from(h_p(&grease_dpk(), &stale).as_affine() * z);
    let wrong_vetkey = VetKey::deserialize(&wrong_sigma.to_compressed()).unwrap();
    assert!(ct.decrypt(&wrong_vetkey).is_err());
}

#[test]
fn gt_generator_encoding_matches_frozen_vector() {
    let gt = pairing(&G1Affine::generator(), &G2Affine::generator());
    let bytes = gt.to_bytes();
    assert_eq!(bytes.len(), 576);
    assert_eq!(hex::encode(bytes), GT_GENERATOR_HEX);
}

#[test]
fn gt_frozen_vector_cross_checked_against_arkworks() {
    // Recompute e(G_1, G_2) with arkworks (independent field towers, independent pairing) and assemble the frozen
    // layout by hand — Fp12 as c1 ‖ c0, Fp6 as c2 ‖ c1 ‖ c0, Fp2 as c1 ‖ c0, Fp as 48-byte big-endian — then
    // compare against the same frozen literal `ic_bls12_381` is held to. Agreement pins both the value and the
    // byte layout of the G_T encoding across two implementations that share no code.
    let gt = ark_bls12_381::Bls12_381::pairing(ark_bls12_381::G1Affine::generator(), ark_bls12_381::G2Affine::generator()).0;
    let bytes = [gt.c1, gt.c0]
        .iter()
        .flat_map(|fp6| [fp6.c2, fp6.c1, fp6.c0])
        .flat_map(|fp2| [fp2.c1, fp2.c0])
        .flat_map(|fp| fp.into_bigint().to_bytes_be())
        .collect::<Vec<u8>>();
    assert_eq!(bytes.len(), 576);
    assert_eq!(hex::encode(bytes), GT_GENERATOR_HEX);
}
