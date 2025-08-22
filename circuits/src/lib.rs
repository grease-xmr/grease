use babyjubjub_rs::*;
use blake2::{Blake2s256, Digest};
use curve25519_dalek::constants::X25519_BASEPOINT;
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::Scalar;
use ff_ce::Field;
use ff_ce::PrimeField;
use hex;
use log::error;
use log::info;
use num_bigint::{BigInt, BigUint};
use num_traits::ops::euclid::Euclid;
use num_traits::Zero;
use poseidon_rs::Fr;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::env;
use std::io::Write;
use std::io::{self, Read};
use std::path::Path;
use std::process::{Command, Stdio};
use tempfile::NamedTempFile;
use thiserror::Error;
use toml;

pub mod helpers;

use lazy_static::lazy_static;
lazy_static! {
    static ref B8: Point = Point {
        x: Fr::from_str("5299619240641551281634865583518297030282874472190772894086521144482721001553",).unwrap(),
        y: Fr::from_str("16950150798460657717958625567821834550301663161624707787222815936182638968203",).unwrap(),
    };
    pub static ref BABY_JUBJUB_ORDER: BigUint = BigUint::parse_bytes(
        b"2736030358979909402780800718157159386076813972158567259200215660948447373041",
        10
    )
    .unwrap();
    static ref BABY_JUBJUB_PRIME: Fr =
        Fr::from_str("21888242871839275222246405745257275088548364400416034343698204186575808495617",).unwrap();
    static ref ED25519_ORDER: BigUint = BigUint::parse_bytes(
        b"7237005577332262213973186563042994240857116359379907606001950938285454250989",
        10
    )
    .unwrap();
}

#[derive(Error, Debug)]
pub enum BBError {
    #[error("An error occurred while io processing. {0}")]
    IoError(#[from] io::Error),
    #[error("An error occurred.")]
    Err(),
    #[error("An error occurred. {0}")]
    String(String),
    #[error("NIZK DLEQ failed to verify")]
    DLEQVerify,
    #[error("Prover failed to verify its own proof")]
    SelfVerify,
}

impl Into<BBError> for &str {
    fn into(self) -> BBError {
        BBError::String(self.to_string())
    }
}

impl From<std::string::String> for BBError {
    fn from(value: std::string::String) -> Self {
        BBError::String(value)
    }
}

fn left_pad_bytes_32(input: &[u8]) -> Result<[u8; 32], String> {
    if input.len() > 32 {
        return Err("Input length exceeds target length".to_string());
    }

    let mut result = [0u8; 32];
    let offset = 32 - input.len();
    result[offset..].copy_from_slice(input);
    Ok(result)
}
pub(crate) fn left_pad_bytes_32_vec(input: &Vec<u8>) -> [u8; 32] {
    assert!(input.len() <= 32, "Input length exceeds target length");

    let mut result = [0u8; 32];
    let offset = 32 - input.len();
    result[offset..].copy_from_slice(input);
    result
}
pub fn right_pad_bytes_32(input: &[u8]) -> [u8; 32] {
    assert!(input.len() <= 32, "Input length exceeds target length");

    let mut result = [0u8; 32];
    result[..input.len()].copy_from_slice(input);
    result
}
fn point_negate(point: Point) -> Point {
    // The negative of a point (x, y) on Baby Jubjub is (-x, y)
    let mut negative_x: Fr = BABY_JUBJUB_PRIME.clone();
    negative_x.sub_assign(&point.x);

    return Point { x: negative_x, y: point.y };
}
fn get_field_bytes(field: &Fr) -> [u8; 32] {
    //Fr(0x1975e7e9cbe0f2ed7a06a09e320036ea1a73862ee2614d2a9a6452d8f7c9aff0)
    let field_object: String = field.to_string();
    assert!(
        field_object.len() == 70,
        "get_field_bytes: field is not correctly self-describing"
    );

    // Decode hex string to bytes
    let substring = &field_object[5..69];
    let bytes = hex::decode(substring).map_err(|_| "Invalid hex string").unwrap();

    bytes.try_into().unwrap()
}
pub fn get_scalar_to_point_bjj(scalar: &BigUint) -> Point {
    assert!(*scalar < *BABY_JUBJUB_ORDER);

    let scalar_i: BigInt = scalar.clone().into();

    let p = B8.mul_scalar(&scalar_i);
    p
}
pub(crate) fn get_scalar_to_point_ed25519(scalar_big_uint: &BigUint) -> MontgomeryPoint {
    // Convert the 32-byte array to an Ed25519 Scalar
    let scalar_bytes_be = scalar_big_uint.to_bytes_be();
    let mut scalar_bytes_le = scalar_bytes_be.clone();
    scalar_bytes_le.reverse();
    let scalar_byte_array_le = right_pad_bytes_32(&scalar_bytes_le);
    let scalar: Scalar = Scalar::from_bytes_mod_order(scalar_byte_array_le);
    // Multiply the scalar by the Curve25519 base point to get a curve point
    let point: MontgomeryPoint = scalar * X25519_BASEPOINT;
    point
}
fn multiply_point_by_scalar_ed25519(point: &MontgomeryPoint, scalar_big_uint: &BigUint) -> MontgomeryPoint {
    // Convert the 32-byte array to an Ed25519 Scalar
    let scalar_bytes_be = scalar_big_uint.to_bytes_be();
    let mut scalar_bytes_le = scalar_bytes_be.clone();
    scalar_bytes_le.reverse();
    let scalar_byte_array_le = right_pad_bytes_32(&scalar_bytes_le);
    let scalar: Scalar = Scalar::from_bytes_mod_order(scalar_byte_array_le);
    // Multiply the scalar by the Curve25519 base point to get a curve point
    let point2: MontgomeryPoint = scalar * point;
    point2
}
enum MontgomeryPointSigns {
    PP,
    PN,
    NP,
    NN,
}
fn subtract_montgomery_points(
    point1: MontgomeryPoint,
    point2: MontgomeryPoint,
    sign: MontgomeryPointSigns,
) -> Option<MontgomeryPoint> {
    // Convert both MontgomeryPoints to EdwardsPoints
    let edwards1 = match sign {
        MontgomeryPointSigns::PP | MontgomeryPointSigns::PN => point1.to_edwards(0u8)?,
        MontgomeryPointSigns::NP | MontgomeryPointSigns::NN => point1.to_edwards(1u8)?,
    };
    let edwards2 = match sign {
        MontgomeryPointSigns::PP | MontgomeryPointSigns::NP => point2.to_edwards(0u8)?,
        MontgomeryPointSigns::PN | MontgomeryPointSigns::NN => point2.to_edwards(1u8)?,
    };

    // Subtract EdwardsPoints
    let result_edwards = edwards1 - edwards2;

    // Convert result back to MontgomeryPoint
    Some(result_edwards.to_montgomery())
}
fn byte_array_to_string_array(bytes: &[u8; 32]) -> [String; 32] {
    let mut array: [String; 32] = Default::default();
    for i in 0..32 {
        array[i] = bytes[i].to_string();
    }
    array
}

pub fn make_scalar_bjj<R: CryptoRng + RngCore>(rng: &mut R) -> BigUint {
    let mut secret_bytes = [0u8; 32];
    rng.fill_bytes(&mut secret_bytes);
    let scalar: BigUint = BigUint::from_bytes_be(&secret_bytes);
    let scalar: BigUint = scalar.rem_euclid(&BABY_JUBJUB_ORDER);
    scalar
}

pub fn make_keypair_bjj<R: CryptoRng + RngCore>(rng: &mut R) -> (BigUint, babyjubjub_rs::Point) {
    let mut secret_bytes = [0u8; 32];
    rng.fill_bytes(&mut secret_bytes);
    let secret_key: BigUint = BigUint::from_bytes_be(&secret_bytes);
    let secret_key: BigUint = secret_key.rem_euclid(&BABY_JUBJUB_ORDER);
    let public_key: Point = get_scalar_to_point_bjj(&secret_key);
    (secret_key, public_key)
}

pub fn make_scalar_ed25519<R: CryptoRng + RngCore>(rng: &mut R) -> BigUint {
    let mut secret_bytes = [0u8; 32];
    rng.fill_bytes(&mut secret_bytes);
    let scalar: BigUint = BigUint::from_bytes_be(&secret_bytes);
    let scalar: BigUint = scalar.rem_euclid(&ED25519_ORDER);
    scalar
}

pub fn make_keypair_ed25519<R: CryptoRng + RngCore>(rng: &mut R) -> (BigUint, MontgomeryPoint) {
    let mut secret_bytes = [0u8; 32];
    rng.fill_bytes(&mut secret_bytes);
    let secret_key: BigUint = BigUint::from_bytes_be(&secret_bytes);
    let secret_key: BigUint = secret_key.rem_euclid(&ED25519_ORDER);
    let public_key = get_scalar_to_point_ed25519(&secret_key);
    (secret_key, public_key)
}

pub fn make_keypair_ed25519_bjj_order<R: CryptoRng + RngCore>(rng: &mut R) -> (BigUint, MontgomeryPoint) {
    let mut secret_bytes = [0u8; 32];
    rng.fill_bytes(&mut secret_bytes);
    let secret_key: BigUint = BigUint::from_bytes_be(&secret_bytes);
    let secret_key: BigUint = secret_key.rem_euclid(&BABY_JUBJUB_ORDER);
    let public_key = get_scalar_to_point_ed25519(&secret_key);
    (secret_key, public_key)
}

pub(crate) fn make_witness0(
    nonce_peer: &BigUint,
    blinding: &BigUint,
) -> Result<(BigUint, babyjubjub_rs::Point, MontgomeryPoint), BBError> {
    assert!(*nonce_peer <= *BABY_JUBJUB_ORDER);
    assert!(*blinding <= *BABY_JUBJUB_ORDER);

    // Input byte array
    let header: [u8; 32] = [0; 32]; // VerifyWitness0 HASH_HEADER_CONSTANT
    let nonce_peer_bytes = nonce_peer.to_bytes_be();
    let blinding_bytes = blinding.to_bytes_be();
    let mut result = Vec::with_capacity(96);
    result.extend_from_slice(&header);
    result.extend_from_slice(&left_pad_bytes_32(&nonce_peer_bytes)?);
    result.extend_from_slice(&left_pad_bytes_32(&blinding_bytes)?);

    // Create a BLAKE2s hasher instance
    let mut hasher = Blake2s256::new();

    // Feed the input bytes to the hasher
    hasher.update(result);

    // Compute the hash
    let hash_verify_witness0_bytes = hasher.finalize();
    // Convert hash bytes to BigUint (big-endian)
    let hash_verify_witness0 = BigUint::from_bytes_be(&hash_verify_witness0_bytes);

    // Modulo BABY_JUBJUB_ORDER
    let witness_0: BigUint = hash_verify_witness0.rem_euclid(&BABY_JUBJUB_ORDER);

    // BJJ key point
    let t_0: Point = B8.mul_scalar(&witness_0.clone().into());

    let s_0: MontgomeryPoint = get_scalar_to_point_ed25519(&witness_0);

    Ok((witness_0, t_0, s_0))
}

//FeldmanSecretShare_2_of_2
pub(crate) fn feldman_secret_share_2_of_2(
    witness_0: &BigUint,
    a_1: &BigUint,
) -> Result<(babyjubjub_rs::Point, BigUint, BigUint), BBError> {
    let c_1 = B8.mul_scalar(&a_1.clone().into());

    let share_1: BigUint = BABY_JUBJUB_ORDER.clone() - witness_0 + BABY_JUBJUB_ORDER.clone() - a_1;
    let share_1: BigUint = share_1.rem_euclid(&BABY_JUBJUB_ORDER);

    let share_2: BigUint = witness_0 + witness_0 + a_1;
    let share_2: BigUint = share_2.rem_euclid(&BABY_JUBJUB_ORDER);

    {
        //Verify reconstruction
        let witness_0_calc: BigUint = &share_1 + &share_2;
        let witness_0_calc: BigUint = witness_0_calc.rem_euclid(&BABY_JUBJUB_ORDER);
        assert_eq!(witness_0, &witness_0_calc);

        //Verify peer verification
        let witness_0_t = B8.mul_scalar(&witness_0.clone().into());
        let t_plus_c_1: PointProjective = witness_0_t.projective().add(&c_1.projective());
        let peer_v_rhs = point_negate(t_plus_c_1.affine());
        let peer_v_lhs = B8.mul_scalar(&share_1.clone().into());
        assert_eq!(peer_v_rhs.x, peer_v_lhs.x);
        assert_eq!(peer_v_rhs.y, peer_v_lhs.y);

        //Verify KES verification
        let t_double_alpha: Point = witness_0_t.mul_scalar(&BigInt::from(2));
        let t_double_beta: PointProjective = witness_0_t.projective().add(&witness_0_t.projective());
        assert_eq!(t_double_alpha.x, t_double_beta.affine().x);
        assert_eq!(t_double_alpha.y, t_double_beta.affine().y);

        let kes_v_rhs = t_double_beta.add(&c_1.projective());
        let kes_v_lhs = B8.mul_scalar(&share_2.clone().into());
        assert_eq!(kes_v_rhs.affine().x, kes_v_lhs.x);
        assert_eq!(kes_v_rhs.affine().y, kes_v_lhs.y);
    }

    Ok((c_1, share_1, share_2))
}

//Encrypt to peer/KES
pub(crate) fn encrypt_message_ecdh(
    message: &BigUint,
    r: &BigUint,
    public_key: &babyjubjub_rs::Point,
    private_key: Option<&BigUint>,
) -> Result<(babyjubjub_rs::Point, BigUint), BBError> {
    let r_g = B8.mul_scalar(&r.clone().into());
    let r_p = public_key.mul_scalar(&r.clone().into());

    // Input byte array
    let r_p_x_bytes = get_field_bytes(&r_p.x);
    let r_p_y_bytes = get_field_bytes(&r_p.y);
    let mut result = Vec::with_capacity(64);
    result.extend_from_slice(&left_pad_bytes_32(&r_p_x_bytes)?);
    result.extend_from_slice(&left_pad_bytes_32(&r_p_y_bytes)?);

    // Create a BLAKE2s hasher instance
    let mut hasher = Blake2s256::new();

    // Feed the input bytes to the hasher
    hasher.update(result);

    // Compute the hash
    let hash_shared_secret_bytes = hasher.finalize();
    // Convert hash bytes to BigUint (big-endian)
    let hash_shared_secret = BigUint::from_bytes_be(&hash_shared_secret_bytes);

    // Modulo BABY_JUBJUB_ORDER
    let shared_secret: BigUint = hash_shared_secret.rem_euclid(&BABY_JUBJUB_ORDER);

    let cipher: BigUint = message + &shared_secret;
    let cipher: BigUint = cipher.rem_euclid(&BABY_JUBJUB_ORDER);

    let fi = r_g;
    let enc = cipher;

    if let Some(private_key) = private_key {
        verify_encrypt_message_ecdh(message, r, public_key, &fi, &enc, &shared_secret, private_key)?;
    }
    Ok((fi, enc))
}

//Encrypt to peer/KES
pub(crate) fn verify_encrypt_message_ecdh(
    message: &BigUint,
    r: &BigUint,
    public_key: &babyjubjub_rs::Point,
    fi: &babyjubjub_rs::Point,
    enc: &BigUint,
    shared_secret: &BigUint,
    private_key: &BigUint,
) -> Result<(), BBError> {
    let r_p = public_key.mul_scalar(&r.clone().into());

    //Verify
    let private_key_i: BigInt = private_key.clone().into();

    let fi_s: Point = fi.mul_scalar(&private_key_i);
    assert_eq!(fi_s.x, r_p.x);
    assert_eq!(fi_s.y, r_p.y);

    // Input byte array
    let fi_s_x_bytes = get_field_bytes(&fi_s.x);
    let fi_s_y_bytes = get_field_bytes(&fi_s.y);
    let mut result = Vec::with_capacity(64);
    result.extend_from_slice(&left_pad_bytes_32(&fi_s_x_bytes)?);
    result.extend_from_slice(&left_pad_bytes_32(&fi_s_y_bytes)?);

    // Create a BLAKE2s hasher instance
    let mut hasher = Blake2s256::new();

    // Feed the input bytes to the hasher
    hasher.update(result);

    // Compute the hash
    let hash_shared_secret_calc_bytes = hasher.finalize();
    // Convert hash bytes to BigUint (big-endian)
    let hash_shared_secret_calc = BigUint::from_bytes_be(&hash_shared_secret_calc_bytes);

    // Modulo BABY_JUBJUB_ORDER
    let shared_secret_calc: BigUint = hash_shared_secret_calc.rem_euclid(&BABY_JUBJUB_ORDER);
    assert_eq!(shared_secret_calc, *shared_secret);

    let share_calc = enc + BABY_JUBJUB_ORDER.clone() - &shared_secret_calc;
    let share_calc: BigUint = share_calc.rem_euclid(&BABY_JUBJUB_ORDER);
    assert_eq!(share_calc, *message);

    Ok(())
}

//Update/VerifyCOF
pub(crate) fn make_vcof(witness_im1: &BigUint) -> Result<(BigUint, babyjubjub_rs::Point, MontgomeryPoint), BBError> {
    assert!(*witness_im1 < *BABY_JUBJUB_ORDER);

    // Input byte array
    let header: [u8; 32] = [0; 32]; // VerifyWitness0 HASH_HEADER_CONSTANT
    let witness_im1_bytes = witness_im1.to_bytes_be();
    let mut result = Vec::with_capacity(64);
    result.extend_from_slice(&header);
    result.extend_from_slice(&left_pad_bytes_32(&witness_im1_bytes)?);

    // Create a BLAKE2s hasher instance
    let mut hasher = Blake2s256::new();

    // Feed the input bytes to the hasher
    hasher.update(result);

    // Compute the hash
    let hash_verify_witnessi_bytes = hasher.finalize();
    // Convert hash bytes to BigUint (big-endian)
    let hash_verify_witnessi = BigUint::from_bytes_be(&hash_verify_witnessi_bytes);

    // Modulo BABY_JUBJUB_ORDER
    let witness_i: BigUint = hash_verify_witnessi.rem_euclid(&BABY_JUBJUB_ORDER);

    // BJJ key point
    let t_i = B8.mul_scalar(&witness_i.clone().into());

    let s_i: MontgomeryPoint = get_scalar_to_point_ed25519(&witness_i);

    Ok((witness_i, t_i, s_i))
}

pub(crate) fn generate_dleqproof_simple(
    secret: &BigUint,
    blinding_dleq: &BigUint,
) -> Result<
    (
        [u8; 32],
        BigUint,
        BigUint,
        babyjubjub_rs::Point,
        MontgomeryPoint,
        BigUint,
        BigUint,
    ),
    BBError,
> {
    assert!(secret > &BigUint::from(0u8));
    assert!(*secret <= *BABY_JUBJUB_ORDER);
    assert!(blinding_dleq > &BigUint::from(0u8));
    assert!(*blinding_dleq <= *BABY_JUBJUB_ORDER);

    // Compute T = secret * G1 (Baby Jubjub)
    let t: Point = B8.mul_scalar(&secret.clone().into());

    let s: MontgomeryPoint = get_scalar_to_point_ed25519(&secret);

    // Compute commitments: R1 = blinding_DLEQ * G1 (Baby Jubjub)
    let r1: Point = B8.mul_scalar(&blinding_dleq.clone().into());

    // Compute commitments: R2 = blinding_DLEQ * G2 (Ed25519)
    let r2: MontgomeryPoint = get_scalar_to_point_ed25519(&blinding_dleq);

    // Input byte array
    let header: [u8; 32] = [0; 32]; // NIZK_DLEQ HASH_HEADER_CONSTANT
    let t_bytes = t.compress();
    let s_bytes = s.to_bytes();
    let r1_bytes: [u8; 32] = r1.compress();
    let r2_bytes = r2.to_bytes();
    let mut result = Vec::with_capacity(160);
    result.extend_from_slice(&header);
    result.extend_from_slice(&t_bytes);
    result.extend_from_slice(&s_bytes);
    result.extend_from_slice(&r1_bytes);
    result.extend_from_slice(&r2_bytes);

    // Create a BLAKE2s hasher instance
    let mut hasher = Blake2s256::new();

    // Feed the input bytes to the hasher
    hasher.update(result);

    // Compute the hash
    let challenge_hash = hasher.finalize();
    // Convert hash bytes to BigUint (big-endian)
    let challenge_bigint = BigUint::from_bytes_be(&challenge_hash);
    let mut challenge_bytes = [0u8; 32];
    challenge_bytes.copy_from_slice(&challenge_hash);

    // Compute response s = c * secret - blinding_DLEQ
    let response = challenge_bigint.clone() * secret;
    if &response <= blinding_dleq {
        // throw new Error('s must be positive');
        return Err(format!("s must be positive: {},{}", response, blinding_dleq).into());
    }
    let response: BigUint = response - blinding_dleq;

    // Compute response s = (c * secret - blinding_DLEQ) mod BABY_JUBJUB_ORDER
    let (response_div_baby_jub_jub, response_baby_jub_jub) = response.div_rem_euclid(&BABY_JUBJUB_ORDER);
    if response_div_baby_jub_jub.bits() > 256u64 {
        // throw new Error('response div BABY_JUBJUB_ORDER too large');
        return Err(format!("response div BABY_JUBJUB_ORDER too large: {}", response_div_baby_jub_jub).into());
    }

    let (response_div_ed25519, response_ed25519) = response.div_rem_euclid(&ED25519_ORDER);
    if response_div_ed25519.bits() > 256u64 {
        //throw new Error('response div ED25519_ORDER too large');
        return Err(format!("response div ED25519_ORDER too large: {}", response_div_ed25519).into());
    }

    {
        //Verify
        let response_baby_jub_jub_g1: Point = B8.mul_scalar(&response_baby_jub_jub.clone().into());

        let challenge_baby_jub_jub = challenge_bigint.rem_euclid(&BABY_JUBJUB_ORDER);
        let response_baby_jub_jub_g1_calc = B8.mul_scalar(
            &((challenge_baby_jub_jub.clone() * secret) - blinding_dleq).rem_euclid(&BABY_JUBJUB_ORDER).into(),
        );
        assert_eq!(response_baby_jub_jub_g1_calc.x, response_baby_jub_jub_g1.x);
        assert_eq!(response_baby_jub_jub_g1_calc.y, response_baby_jub_jub_g1.y);

        let c_t: Point = t.mul_scalar(&challenge_baby_jub_jub.clone().into());

        let c_t_calc = B8.mul_scalar(&(challenge_baby_jub_jub * secret).rem_euclid(&BABY_JUBJUB_ORDER).into());
        assert_eq!(c_t_calc.x, c_t.x);
        assert_eq!(c_t_calc.y, c_t.y);

        let r1_calc = c_t.projective().add(&point_negate(response_baby_jub_jub_g1).projective()).affine();
        assert_eq!(r1_calc.x, r1.x);
        assert_eq!(r1_calc.y, r1.y);

        let response_ed25519_g2: MontgomeryPoint = get_scalar_to_point_ed25519(&response_ed25519);

        let challenge_ed25519 = challenge_bigint.rem_euclid(&ED25519_ORDER);
        let c_s = multiply_point_by_scalar_ed25519(&s, &challenge_ed25519);

        let mut count_match = 0u8;
        let r2_calc_pp = subtract_montgomery_points(c_s, response_ed25519_g2, MontgomeryPointSigns::PP).unwrap();
        if r2_calc_pp == r2 {
            count_match += 1;
        }
        let r2_calc_pn = subtract_montgomery_points(c_s, response_ed25519_g2, MontgomeryPointSigns::PN).unwrap();
        if r2_calc_pn == r2 {
            count_match += 1;
        }
        let r2_calc_np = subtract_montgomery_points(c_s, response_ed25519_g2, MontgomeryPointSigns::NP).unwrap();
        if r2_calc_np == r2 {
            count_match += 1;
        }
        let r2_calc_nn = subtract_montgomery_points(c_s, response_ed25519_g2, MontgomeryPointSigns::NN).unwrap();
        if r2_calc_nn == r2 {
            count_match += 1;
        }
        assert!(count_match > 0u8);
    }

    Ok((
        challenge_bytes,
        response_baby_jub_jub,
        response_ed25519,
        r1,
        r2,
        response_div_baby_jub_jub,
        response_div_ed25519,
    ))
}

pub fn verify_dleq_simple(
    t: &babyjubjub_rs::Point,
    s: &MontgomeryPoint,
    challenge_bytes: &[u8; 32],
    response_baby_jub_jub: &BigUint,
    response_ed25519: &BigUint,
    r1: &babyjubjub_rs::Point,
    r2: &MontgomeryPoint,
) -> Result<bool, BBError> {
    // Input byte array
    let header: [u8; 32] = [0; 32]; // NIZK_DLEQ HASH_HEADER_CONSTANT
    let t_bytes = t.compress();
    let s_bytes = s.to_bytes();
    let r1_bytes: [u8; 32] = r1.compress();
    let r2_bytes = r2.to_bytes();
    let mut result = Vec::with_capacity(160);
    result.extend_from_slice(&header);
    result.extend_from_slice(&t_bytes);
    result.extend_from_slice(&s_bytes);
    result.extend_from_slice(&r1_bytes);
    result.extend_from_slice(&r2_bytes);

    // Create a BLAKE2s hasher instance
    let mut hasher = Blake2s256::new();

    // Feed the input bytes to the hasher
    hasher.update(result);

    // Compute the hash
    let challenge_hash = hasher.finalize();
    // Convert hash bytes to BigUint (big-endian)
    let challenge_bigint = BigUint::from_bytes_be(&challenge_hash);
    let mut challenge_bytes_calc = [0u8; 32];
    challenge_bytes_calc.copy_from_slice(&challenge_hash);

    if challenge_bytes_calc != *challenge_bytes {
        return Ok(false);
    }

    //Verify: r.G == c.x.G - (c*x-r).G => R == c.T - z.G
    //        R1 == challenge_BabyJubJub.T - response_BabyJubJub_g1.G
    let response_baby_jub_jub_g1: Point = B8.mul_scalar(&response_baby_jub_jub.clone().into());
    let challenge_baby_jub_jub: BigUint = challenge_bigint.rem_euclid(&BABY_JUBJUB_ORDER);
    let challenge_baby_jub_jub_t: Point = t.mul_scalar(&challenge_baby_jub_jub.clone().into());

    let r1_calc =
        challenge_baby_jub_jub_t.projective().add(&point_negate(response_baby_jub_jub_g1).projective()).affine();
    if r1.x != r1_calc.x {
        return Ok(false);
    }
    if r1.y != r1_calc.y {
        return Ok(false);
    }

    //Verify: r.G == c.x.G - (c*x-r).G => R == c.T - z.G
    //        R2 == challenge_ed25519.S - response_ed25519.G
    let response_ed25519_g2: MontgomeryPoint = get_scalar_to_point_ed25519(&response_ed25519);
    let challenge_ed25519: BigUint = challenge_bigint.rem_euclid(&ED25519_ORDER);
    let challenge_ed25519_s: MontgomeryPoint = multiply_point_by_scalar_ed25519(&s, &challenge_ed25519);

    let mut count_match = 0u8;
    let r2_calc_pp =
        subtract_montgomery_points(challenge_ed25519_s, response_ed25519_g2, MontgomeryPointSigns::PP).unwrap();
    if r2_calc_pp == *r2 {
        count_match += 1;
    }
    let r2_calc_pn =
        subtract_montgomery_points(challenge_ed25519_s, response_ed25519_g2, MontgomeryPointSigns::PN).unwrap();
    if r2_calc_pn == *r2 {
        count_match += 1;
    }
    let r2_calc_np =
        subtract_montgomery_points(challenge_ed25519_s, response_ed25519_g2, MontgomeryPointSigns::NP).unwrap();
    if r2_calc_np == *r2 {
        count_match += 1;
    }
    let r2_calc_nn =
        subtract_montgomery_points(challenge_ed25519_s, response_ed25519_g2, MontgomeryPointSigns::NN).unwrap();
    if r2_calc_nn == *r2 {
        count_match += 1;
    }

    return Ok(count_match > 0u8);
}

enum Shell {
    Bb,
    Nargo,
}

fn call_shell(shell: Shell, args: &[&str], working_dir: Option<&Path>) -> io::Result<(Vec<u8>, String)> {
    let program = match shell {
        Shell::Bb => "bb",
        Shell::Nargo => "nargo",
    };

    #[cfg(debug_assertions)]
    {
        // Validate command exists
        info!("Validating command '{}'", program);
        if !std::process::Command::new("which").arg(program).status()?.success() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("{} command not found", program),
            ));
        }
    }

    // Spawn the bash command with the provided arguments
    info!(
        "Calling command '{}' in '{}' with args '{:?}'",
        program,
        env::current_dir()?.display(),
        args
    );
    let mut command = Command::new(program);
    let mut command = command.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());

    if let Some(working_dir) = working_dir {
        command = command.current_dir(working_dir);
    }

    let mut command = command.spawn()?;

    // Get stdout and stderr handles
    let stdout =
        command.stdout.take().ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Failed to capture stdout"))?;
    let stderr =
        command.stderr.take().ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Failed to capture stderr"))?;

    // Read stdout into a string
    let mut stdout_output: Vec<u8> = Vec::new();
    io::BufReader::new(stdout).read_to_end(&mut stdout_output)?;

    // Read stderr into a string
    let mut stderr_output = String::new();
    io::BufReader::new(stderr).read_to_string(&mut stderr_output)?;

    // Wait for the command to finish and check for errors
    let status = command.wait()?;
    if !status.success() {
        error!(
            "Failed command '{}' in '{}' with args '{:?}' with status '{}' and error: '{}'",
            program,
            env::current_dir()?.display(),
            args,
            status,
            stderr_output.trim().to_string()
        );
        // panic!("args: {:?}\terror: {}", args, stderr_output.trim().to_string());
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("Script failed with status: {}", status,),
        ));
    }

    Ok((stdout_output, stderr_output.trim().to_string()))
}

pub(crate) fn get_bb_version() -> Result<(u8, u8, u8), BBError> {
    //bb --version
    let args: Vec<&'static str> = vec!["--version"];
    match call_shell(Shell::Bb, &args, None) {
        Ok((stdout, _stderr)) => {
            let stdout = match str::from_utf8(&stdout) {
                Ok(v) => v,
                Err(e) => return Err(format!("Invalid UTF-8 sequence: {}", e).into()),
            };
            let stdout: String = stdout.chars().filter(|&c| !c.is_whitespace()).collect();
            // Split the string by periods
            let parts: Vec<&str> = stdout.split('.').collect();

            // Check if exactly 3 parts
            if parts.len() != 3 {
                return Err("Version string must have exactly three parts separated by periods".into());
            }

            // Parse each part into u8
            let mut result = [0u8; 3];
            for (i, part) in parts.iter().enumerate() {
                match part.parse::<u8>() {
                    Ok(num) => result[i] = num,
                    Err(_) => return Err(format!("Each part must be a valid u8 (0-255): {}", stdout).into()),
                }
            }

            Ok((result[0], result[1], result[2]))
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            Err(BBError::IoError(e))
        }
    }
}

pub(crate) fn get_nargo_version() -> Result<String, BBError> {
    //nargo --version
    let args: Vec<&'static str> = vec!["--version"];
    match call_shell(Shell::Nargo, &args, None) {
        Ok((stdout, _stderr)) => {
            let stdout = match str::from_utf8(&stdout) {
                Ok(v) => v,
                Err(e) => return Err(format!("Invalid UTF-8 sequence: {}", e).into()),
            };

            Ok(stdout.to_string())
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            Err(BBError::IoError(e))
        }
    }
}

#[derive(Serialize)]
struct PointConfig {
    x: String,
    y: String,
}

fn get_point_config_baby_jubjub(point: &Point) -> PointConfig {
    //Fr(0x1975e7e9cbe0f2ed7a06a09e320036ea1a73862ee2614d2a9a6452d8f7c9aff0)
    let x: String = point.x.to_string();
    assert!(x.len() == 70, "get_field_bytes: field is not correctly self-describing");
    let x_str = &x[3..69];

    let y: String = point.y.to_string();
    assert!(y.len() == 70, "get_field_bytes: field is not correctly self-describing");
    let y_str = &y[3..69];

    PointConfig { x: x_str.to_string(), y: y_str.to_string() }
}

#[allow(non_snake_case)]
#[derive(Serialize)]
struct InitConfig {
    a_1: String,
    blinding: String,
    blinding_DLEQ: String,
    challenge_bytes: [String; 32],
    enc_1: String,
    enc_2: String,
    nonce_peer: String,
    r_1: String,
    r_2: String,
    response_div_BabyJubJub: [String; 32],
    response_div_ed25519: [String; 32],
    response_BabyJubJub: String,
    response_ed25519: [String; 32],
    share_1: String,
    share_2: String,
    witness_0: String,

    T_0: PointConfig,
    c_1: PointConfig,
    fi_1: PointConfig,
    fi_2: PointConfig,
    pubkey_KES: PointConfig,
    pubkey_peer: PointConfig,
}

#[allow(non_snake_case)]
#[derive(Serialize)]
struct UpdateConfig {
    blinding_DLEQ: String,
    challenge_bytes: [String; 32],
    response_div_BabyJubJub: [String; 32],
    response_div_ed25519: [String; 32],
    response_BabyJubJub: String,
    response_ed25519: [String; 32],
    witness_i: String,
    witness_im1: String,

    T_i: PointConfig,
    T_im1: PointConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ZeroKnowledgeProofInitPublic {
    #[serde(
        serialize_with = "crate::helpers::init_public_to_hex",
        deserialize_with = "crate::helpers::init_public_from_hex"
    )]
    pub public_input: [u8; 1312],
}

impl ZeroKnowledgeProofInitPublic {
    pub fn from_vec(public: Vec<u8>) -> Result<Self, BBError> {
        if public.len() != 1312 {
            return Err(BBError::String("Invalid public input length".to_string()));
        }
        let public_input: [u8; 1312] =
            public.try_into().map_err(|_| BBError::String("Invalid public input length".to_string()))?;
        Ok(Self { public_input })
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.public_input.to_vec()
    }

    pub fn new(
        nonce_peer: &BigUint,
        t_0: &Point,
        c_1: &Point,
        public_key_bjj_peer: &babyjubjub_rs::Point,
        kes_public_key: &babyjubjub_rs::Point,
        c: &BigUint,
    ) -> Result<Self, BBError> {
        let mut public_input = Vec::with_capacity(288 + (32 * 32));
        public_input.extend_from_slice(&left_pad_bytes_32(&nonce_peer.to_bytes_be())?);
        public_input.extend_from_slice(&get_field_bytes(&t_0.x));
        public_input.extend_from_slice(&get_field_bytes(&t_0.y));
        public_input.extend_from_slice(&get_field_bytes(&c_1.x));
        public_input.extend_from_slice(&get_field_bytes(&c_1.y));
        public_input.extend_from_slice(&get_field_bytes(&public_key_bjj_peer.x));
        public_input.extend_from_slice(&get_field_bytes(&public_key_bjj_peer.y));
        public_input.extend_from_slice(&get_field_bytes(&kes_public_key.x));
        public_input.extend_from_slice(&get_field_bytes(&kes_public_key.y));

        // challenge bytes
        let challenge_bytes = c.to_bytes_be();
        if challenge_bytes.len() > 32 {
            return Err(BBError::String(
                "challenge_bytes must less than or equal to 32 bytes".to_string(),
            ));
        }
        let leading_zeroes = 32 - challenge_bytes.len();
        for _ in 0..leading_zeroes {
            public_input.extend_from_slice(&BigUint::zero().to_bytes_be());
        }
        for i in leading_zeroes..32 {
            let byte = BigUint::from(challenge_bytes[i - leading_zeroes]);
            public_input.extend_from_slice(&byte.to_bytes_be());
        }

        Ok(Self {
            public_input: public_input
                .try_into()
                .map_err(|_| BBError::String("Invalid public input length".to_string()))?,
        })
    }

    pub fn check(
        p: &ZeroKnowledgeProofInitPublic,
        nonce_peer: &BigUint,
        t_0: &Point,
        c_1: &Point,
        public_key_bjj_peer: &babyjubjub_rs::Point,
        kes_public_key: &babyjubjub_rs::Point,
        c: &BigUint,
    ) -> Result<(), BBError> {
        if *nonce_peer != BigUint::from_bytes_be(&p.public_input[0..32]) {
            return Err(BBError::String("Nonce peer does not match".to_string()));
        }
        let t_0_x_bytes = get_field_bytes(&t_0.x);
        if t_0_x_bytes != p.public_input[32..64] {
            return Err(BBError::String("t_0.x does not match".to_string()));
        }
        let t_0_y = get_field_bytes(&t_0.y);
        if t_0_y != p.public_input[64..96] {
            return Err(BBError::String("t_0.y does not match".to_string()));
        }
        let c_1_x_bytes = get_field_bytes(&c_1.x);
        if c_1_x_bytes != p.public_input[96..128] {
            return Err(BBError::String("c_1.x does not match".to_string()));
        }
        let c_1_y_bytes = get_field_bytes(&c_1.y);
        if c_1_y_bytes != p.public_input[128..160] {
            return Err(BBError::String("c_1.y does not match".to_string()));
        }
        let public_key_peer_x_bytes = get_field_bytes(&public_key_bjj_peer.x);
        if public_key_peer_x_bytes != p.public_input[160..192] {
            return Err(BBError::String("public_key_peer.x does not match".to_string()));
        }
        let public_key_peer_y_bytes = get_field_bytes(&public_key_bjj_peer.y);
        if public_key_peer_y_bytes != p.public_input[192..224] {
            return Err(BBError::String("public_key_peer.y does not match".to_string()));
        }
        let kes_public_key_x_bytes = get_field_bytes(&kes_public_key.x);
        if kes_public_key_x_bytes != p.public_input[224..256] {
            return Err(BBError::String("kes_public_key.x does not match".to_string()));
        }
        let kes_public_key_y_bytes = get_field_bytes(&kes_public_key.y);
        if kes_public_key_y_bytes != p.public_input[256..288] {
            return Err(BBError::String("kes_public_key.y does not match".to_string()));
        }
        let challenge_bytes = c.to_bytes_be();
        if challenge_bytes.len() > 32 {
            return Err(BBError::String(
                "challenge_bytes must less than or equal to 32 bytes".to_string(),
            ));
        }
        let leading_zeroes = 32 - challenge_bytes.len();
        if leading_zeroes > 0 {
            for i in 0..leading_zeroes {
                let public_input_index = 288 + (i * 32);
                let public_input_index_until = public_input_index + 32;

                if BigUint::zero()
                    != BigUint::from_bytes_be(&p.public_input[public_input_index..public_input_index_until])
                {
                    return Err(BBError::String("challenge_bytes does not match".to_string()));
                }
            }
        }
        for i in leading_zeroes..32 {
            let public_input_index = 288 + (i * 32);
            let public_input_index_until = public_input_index + 32;
            let challenge_byte = BigUint::from(challenge_bytes[leading_zeroes + i]);

            if challenge_byte != BigUint::from_bytes_be(&p.public_input[public_input_index..public_input_index_until]) {
                return Err(BBError::String("challenge_bytes does not match".to_string()));
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ZeroKnowledgeProofInit {
    pub public_input: Option<ZeroKnowledgeProofInitPublic>,
    #[serde(serialize_with = "crate::helpers::proof_to_hex", deserialize_with = "crate::helpers::proof_from_hex")]
    pub proof: Option<Box<[u8; 14080]>>,
}

impl Default for ZeroKnowledgeProofInit {
    fn default() -> Self {
        Self { public_input: None, proof: None }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct ZeroKnowledgeProofUpdatePublic {
    #[serde(
        serialize_with = "crate::helpers::update_public_to_hex",
        deserialize_with = "crate::helpers::update_public_from_hex"
    )]
    pub public_input: [u8; 1152],
}

impl ZeroKnowledgeProofUpdatePublic {
    pub fn from_vec(public: Vec<u8>) -> Result<Self, BBError> {
        if public.len() != 1152 {
            return Err(BBError::String("Invalid public input length".to_string()));
        }
        let public_input: [u8; 1152] =
            public.try_into().map_err(|_| BBError::String("Invalid public input length".to_string()))?;
        Ok(Self { public_input })
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.public_input.to_vec()
    }

    pub fn new(t_prev: &Point, t_current: &Point, challenge: &BigUint) -> Result<Self, BBError> {
        let mut public_input = Vec::with_capacity(128 + (32 * 32));
        public_input.extend_from_slice(&get_field_bytes(&t_prev.x));
        public_input.extend_from_slice(&get_field_bytes(&t_prev.y));
        public_input.extend_from_slice(&get_field_bytes(&t_current.x));
        public_input.extend_from_slice(&get_field_bytes(&t_current.y));

        // challenge bytes
        let challenge_bytes = challenge.to_bytes_be();
        if challenge_bytes.len() > 32 {
            return Err(BBError::String(
                "challenge_bytes must less than or equal to 32 bytes".to_string(),
            ));
        }
        let leading_zeroes = 32 - challenge_bytes.len();
        for _ in 0..leading_zeroes {
            public_input.extend_from_slice(&BigUint::zero().to_bytes_be());
        }
        for i in leading_zeroes..32 {
            let byte = BigUint::from(challenge_bytes[i - leading_zeroes]);
            public_input.extend_from_slice(&byte.to_bytes_be());
        }

        Ok(Self {
            public_input: public_input
                .try_into()
                .map_err(|_| BBError::String("Invalid public input length".to_string()))?,
        })
    }

    pub fn check(
        p: &ZeroKnowledgeProofUpdatePublic,
        t_prev: &Point,
        t_current: &Point,
        challenge: &BigUint,
    ) -> Result<(), BBError> {
        let t_prev_x_bytes = get_field_bytes(&t_prev.x);
        if t_prev_x_bytes != p.public_input[0..32] {
            return Err(BBError::String("t_prev.x does not match".to_string()));
        }
        let t_prev_y = get_field_bytes(&t_prev.y);
        if t_prev_y != p.public_input[32..64] {
            return Err(BBError::String("t_prev.y does not match".to_string()));
        }
        let t_current_x_bytes = get_field_bytes(&t_current.x);
        if t_current_x_bytes != p.public_input[64..96] {
            return Err(BBError::String("t_current.x does not match".to_string()));
        }
        let t_current_y_bytes = get_field_bytes(&t_current.y);
        if t_current_y_bytes != p.public_input[96..128] {
            return Err(BBError::String("t_current.y does not match".to_string()));
        }
        let challenge_bytes = challenge.to_bytes_be();
        if challenge_bytes.len() > 32 {
            return Err(BBError::String(
                "challenge_bytes must less than or equal to 32 bytes".to_string(),
            ));
        }
        let leading_zeroes = 32 - challenge_bytes.len();
        if leading_zeroes > 0 {
            for i in 0..leading_zeroes {
                let public_input_index = 128 + (i * 32);
                let public_input_index_until = public_input_index + 32;

                if BigUint::zero()
                    != BigUint::from_bytes_be(&p.public_input[public_input_index..public_input_index_until])
                {
                    return Err(BBError::String("challenge_bytes does not match zeroes".to_string()));
                }
            }
        }
        for i in leading_zeroes..32 {
            let public_input_index = 128 + (i * 32);
            let public_input_index_until = public_input_index + 32;
            let challenge_byte = BigUint::from(challenge_bytes[leading_zeroes + i]);

            if challenge_byte != BigUint::from_bytes_be(&p.public_input[public_input_index..public_input_index_until]) {
                return Err(BBError::String(format!(
                    "challenge_bytes does not match: {}, {:?}, {:?}",
                    i,
                    challenge_bytes,
                    &p.public_input[0..1152]
                )));
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct ZeroKnowledgeProofUpdate {
    pub public_input: Option<ZeroKnowledgeProofUpdatePublic>,
    #[serde(serialize_with = "crate::helpers::proof_to_hex", deserialize_with = "crate::helpers::proof_from_hex")]
    pub proof: Option<Box<[u8; 14080]>>,
}

impl Default for ZeroKnowledgeProofUpdate {
    fn default() -> Self {
        Self { public_input: Default::default(), proof: None }
    }
}

pub(crate) fn bb_prove_init(
    a_1: &BigUint,
    blinding: &BigUint,
    blinding_dleq: &BigUint,
    challenge_bytes: &[u8; 32],
    enc_1: &BigUint,
    enc_2: &BigUint,
    nonce_peer: &BigUint,
    r_1: &BigUint,
    r_2: &BigUint,
    response_div_baby_jub_jub: &[u8; 32],
    response_div_ed25519: &[u8; 32],
    response_baby_jub_jub: &BigUint,
    response_ed25519: &[u8; 32],
    share_1: &BigUint,
    share_2: &BigUint,
    witness_0: &BigUint,

    t_0: &Point,
    c_1: &Point,
    fi_1: &Point,
    fi_2: &Point,
    kes_public_key: &Point,
    public_key_peer: &Point,

    nargo_path: &Path,
) -> Result<ZeroKnowledgeProofInit, BBError> {
    let config = InitConfig {
        a_1: a_1.to_string(),
        blinding: blinding.to_string(),
        blinding_DLEQ: blinding_dleq.to_string(),
        challenge_bytes: byte_array_to_string_array(&challenge_bytes),
        enc_1: enc_1.to_string(),
        enc_2: enc_2.to_string(),
        nonce_peer: nonce_peer.to_string(),
        r_1: r_1.to_string(),
        r_2: r_2.to_string(),
        response_div_BabyJubJub: byte_array_to_string_array(&response_div_baby_jub_jub),
        response_div_ed25519: byte_array_to_string_array(&response_div_ed25519),
        response_BabyJubJub: response_baby_jub_jub.to_string(),
        response_ed25519: byte_array_to_string_array(&response_ed25519),
        share_1: share_1.to_string(),
        share_2: share_2.to_string(),
        witness_0: witness_0.to_string(),

        T_0: get_point_config_baby_jubjub(t_0),
        c_1: get_point_config_baby_jubjub(c_1),
        fi_1: get_point_config_baby_jubjub(fi_1),
        fi_2: get_point_config_baby_jubjub(fi_2),
        pubkey_KES: get_point_config_baby_jubjub(kes_public_key),
        pubkey_peer: get_point_config_baby_jubjub(public_key_peer),
    };

    // Serialize to TOML string
    let toml_string = toml::to_string_pretty(&config).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

    let mut witness_config_file = NamedTempFile::with_suffix(".toml")?;
    write!(witness_config_file, "{}", toml_string)?;

    let witness_config_file_path = witness_config_file.path().to_string_lossy().to_string();

    let witness_binary_file = NamedTempFile::with_suffix(".gz")?;
    let witness_binary_file_path = witness_binary_file.path().to_string_lossy().to_string();

    //nargo execute
    let args: Vec<&str> = vec![
        "execute",
        "--silence-warnings",
        "-p",
        &witness_config_file_path,
        "--package",
        "Grease",
        &witness_binary_file_path,
    ];
    let _ = match call_shell(Shell::Nargo, &args, Some(nargo_path)) {
        Ok((stdout, _stderr)) => match str::from_utf8(&stdout) {
            Ok(v) => v.to_string(),
            Err(e) => return Err(format!("Invalid UTF-8 sequence: {}", e).into()),
        },
        Err(e) => {
            eprintln!("Error: {}", e);
            return Err(BBError::IoError(e));
        }
    };

    //Delete temp file
    witness_config_file.close()?;

    //bb prove
    let grease_init_json_bytes = include_bytes!("../target/Grease.json");
    let mut grease_init_json_file = NamedTempFile::with_suffix(".json")?;
    grease_init_json_file.write_all(grease_init_json_bytes)?;

    let grease_init_json_file_path = grease_init_json_file.path().to_string_lossy().to_string();

    let args: Vec<&str> =
        vec!["prove", "-b", &grease_init_json_file_path, "-w", &witness_binary_file_path, "-v", "-o", "-"];
    let mut public_input_and_proof: Vec<u8> = match call_shell(Shell::Bb, &args, None) {
        Ok((stdout, _stderr)) => stdout,
        Err(e) => {
            eprintln!("Error: {}", e);
            return Err(BBError::IoError(e));
        }
    };

    //Delete temp file
    witness_binary_file.close()?;
    grease_init_json_file.close()?;

    if public_input_and_proof.len() != 1312 + 14080 {
        return Err(BBError::String("Invalid public input and proof length".to_string()));
    }

    //41 public fields ==> 1,312 bytes @ 32 bytes each
    let proof: Vec<u8> = public_input_and_proof.split_off(1312);

    if public_input_and_proof.len() != 1312 {
        return Err(BBError::String("Invalid public input length".to_string()));
    }
    if proof.len() != 14080 {
        return Err(BBError::String("Invalid proof length".to_string()));
    }

    Ok(ZeroKnowledgeProofInit {
        public_input: Some(ZeroKnowledgeProofInitPublic::from_vec(public_input_and_proof)?),
        proof: Some(proof.try_into().map_err(|_| BBError::String("proof must be exactly 14080 bytes".to_string()))?),
    })
}

pub(crate) fn bb_verify(
    proof: &Box<[u8; 14080]>,
    public_inputs: &Vec<u8>,
    view_key_file: &str,
) -> Result<bool, BBError> {
    // Create named temporary files
    let mut proof_file = NamedTempFile::new()?;
    let mut public_inputs_file = NamedTempFile::new()?;

    // Write content to the temporary files
    proof_file.write_all(&proof.to_vec())?;
    public_inputs_file.write_all(public_inputs)?;

    let proof_file_path = proof_file.path().to_string_lossy().to_string();
    let public_inputs_file_path = public_inputs_file.path().to_string_lossy().to_string();

    //nargo verify
    let args: Vec<&str> =
        vec!["verify", "-v", "-k", view_key_file, "-p", &proof_file_path, "-i", &public_inputs_file_path];
    let ret: Result<bool, BBError> = match call_shell(Shell::Bb, &args, None) {
        Ok((_stdout, _stderr)) => Ok(true),
        Err(e) => {
            eprintln!("Error: {}", e);
            Err(e.into())
        }
    };

    //Delete temp files
    proof_file.close()?;
    public_inputs_file.close()?;

    ret
}

pub fn bb_verify_init(
    nonce_peer: &BigUint,
    public_key_bjj_peer: &babyjubjub_rs::Point,
    kes_public_key: &babyjubjub_rs::Point,
    public_init: &PublicInit,
    zero_knowledge_proof_init: &ZeroKnowledgeProofInit,
) -> Result<bool, BBError> {
    let proof = match zero_knowledge_proof_init.proof {
        Some(ref p) => p,
        None => return Err(BBError::String("Proof is missing".to_string())),
    };

    let public = match zero_knowledge_proof_init.public_input {
        Some(ref p) => {
            ZeroKnowledgeProofInitPublic::check(
                p,
                nonce_peer,
                &public_init.T_0,
                &public_init.c_1,
                public_key_bjj_peer,
                kes_public_key,
                &public_init.c,
            )?;

            p.to_vec()
        }
        None => {
            let p = ZeroKnowledgeProofInitPublic::new(
                nonce_peer,
                &public_init.T_0,
                &public_init.c_1,
                public_key_bjj_peer,
                kes_public_key,
                &public_init.c,
            )?;

            p.to_vec()
        }
    };

    let vk_key_bytes = include_bytes!("../target/vk/vk.key");
    let mut vk_key_file = NamedTempFile::with_suffix(".json")?;
    vk_key_file.write_all(vk_key_bytes)?;

    let vk_key_file_path = vk_key_file.path().to_string_lossy().to_string();

    let res = bb_verify(proof, &public, &vk_key_file_path)?;

    vk_key_file.close()?;

    Ok(res)
}

pub(crate) fn bb_prove_update(
    blinding_dleq: &BigUint,
    challenge_bytes: &[u8; 32],
    response_div_baby_jub_jub: &[u8; 32],
    response_div_ed25519: &[u8; 32],
    response_baby_jub_jub: &BigUint,
    response_ed25519: &[u8; 32],
    witness_i: &BigUint,
    witness_im1: &BigUint,

    t_i: &Point,
    t_im1: &Point,

    nargo_path: &Path,
) -> Result<ZeroKnowledgeProofUpdate, BBError> {
    let config = UpdateConfig {
        blinding_DLEQ: blinding_dleq.to_string(),
        challenge_bytes: byte_array_to_string_array(&challenge_bytes),
        response_div_BabyJubJub: byte_array_to_string_array(&response_div_baby_jub_jub),
        response_div_ed25519: byte_array_to_string_array(&response_div_ed25519),
        response_BabyJubJub: response_baby_jub_jub.to_string(),
        response_ed25519: byte_array_to_string_array(&response_ed25519),
        witness_i: witness_i.to_string(),
        witness_im1: witness_im1.to_string(),

        T_i: get_point_config_baby_jubjub(t_i),
        T_im1: get_point_config_baby_jubjub(t_im1),
    };

    // Serialize to TOML string
    let toml_string = toml::to_string_pretty(&config).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

    let mut witness_config_file = NamedTempFile::with_suffix(".toml")?;
    write!(witness_config_file, "{}", toml_string)?;

    let witness_config_file_path = witness_config_file.path().to_string_lossy().to_string();

    let witness_binary_file = NamedTempFile::with_suffix(".gz")?;
    let witness_binary_file_path = witness_binary_file.path().to_string_lossy().to_string();

    //nargo execute
    let args: Vec<&str> = vec![
        "execute",
        "--silence-warnings",
        "-p",
        &witness_config_file_path,
        "--package",
        "GreaseUpdate",
        &witness_binary_file_path,
    ];
    let _ = match call_shell(Shell::Nargo, &args, Some(nargo_path)) {
        Ok((stdout, _stderr)) => match str::from_utf8(&stdout) {
            Ok(v) => v.to_string(),
            Err(e) => return Err(format!("Invalid UTF-8 sequence: {}", e).into()),
        },
        Err(e) => {
            eprintln!("Error: {}", e);
            return Err(BBError::IoError(e));
        }
    };

    //Delete temp file
    witness_config_file.close()?;

    //bb prove
    let grease_update_json_bytes = include_bytes!("../target/GreaseUpdate.json");
    let mut grease_update_json_file = NamedTempFile::with_suffix(".json")?;
    grease_update_json_file.write_all(grease_update_json_bytes)?;

    let grease_update_json_file_path = grease_update_json_file.path().to_string_lossy().to_string();

    let args: Vec<&str> =
        vec!["prove", "-b", &grease_update_json_file_path, "-w", &witness_binary_file_path, "-v", "-o", "-"];
    let mut public_input_and_proof = match call_shell(Shell::Bb, &args, None) {
        Ok((stdout, _stderr)) => stdout,
        Err(e) => {
            eprintln!("Error: {}", e);
            return Err(BBError::IoError(e));
        }
    };

    //Delete temp file
    witness_binary_file.close()?;
    grease_update_json_file.close()?;

    //36 public fields ==> 1,152 bytes @ 32 bytes each
    let proof: Vec<u8> = public_input_and_proof.split_off(1152);

    Ok(ZeroKnowledgeProofUpdate {
        public_input: Some(ZeroKnowledgeProofUpdatePublic::from_vec(public_input_and_proof)?),
        proof: Some(proof.try_into().map_err(|_| BBError::String("proof must be exactly 14080 bytes".to_string()))?),
    })
}

/// The outputs of the Commitment0 proofs that must be shared with the peer.
#[allow(non_snake_case)]
#[derive(Debug, Clone)]
pub struct PublicInit {
    /// **Τ₀** - The public key/curve point on Baby Jubjub for ω₀.
    pub T_0: Point,
    /// **c₁** - Feldman commitment 1 (used in tandem with Feldman commitment 0 = Τ₀), which is a public key/curve point on Baby Jubjub.
    pub c_1: Point,
    /// **Φ₁** - The ephemeral public key/curve point on Baby Jubjub for message transportation to the peer.
    pub phi_1: Point,
    /// **χ₁** - The encrypted value of σ₁.
    pub enc_1: BigUint,
    /// **Φ₂** - The ephemeral public key/curve point on Baby Jubjub for message transportation to the KES.
    pub phi_2: Point,
    /// **χ₂** - The encrypted value of σ₂ (enc₂).
    pub enc_2: BigUint,
    /// **S₀** - The public key/curve point on Ed25519 for ω₀.
    pub S_0: MontgomeryPoint,
    /// **c** - The Fiat–Shamir heuristic challenge (challenge_bytes).
    pub c: BigUint,
    /// **ρ_BabyJubjub** - The Fiat–Shamir heuristic challenge response on the Baby Jubjub curve (response_BabyJubJub).
    pub rho_bjj: BigUint,
    /// **ρ_Ed25519** - The Fiat–Shamir heuristic challenge response on the Ed25519 curve (response_div_ed25519).
    pub rho_ed: BigUint,
    /// **R_BabyJubjub** - The ... on the Baby Jubjub curve (R1).
    pub R1: Point,
    /// **R_Ed25519** - The ... on the Ed25519 curve (R2).
    pub R2: MontgomeryPoint,
}

#[allow(non_snake_case)]
impl PublicInit {
    pub fn new(
        T_0: &Point,
        c_1: &Point,
        phi_1: &Point,
        enc_1: &BigUint,
        phi_2: &Point,
        enc_2: &BigUint,
        S_0: &MontgomeryPoint,
        challenge_bytes: &[u8; 32],
        rho_bjj: &BigUint,
        rho_ed: &BigUint,
        R1: &Point,
        R2: &MontgomeryPoint,
    ) -> Self {
        let challenge: BigUint = BigUint::from_bytes_be(challenge_bytes);

        PublicInit {
            T_0: T_0.clone(),
            c_1: c_1.clone(),
            phi_1: phi_1.clone(),
            enc_1: enc_1.clone(),
            phi_2: phi_2.clone(),
            enc_2: enc_2.clone(),
            S_0: S_0.clone(),
            c: challenge,
            rho_bjj: rho_bjj.clone(),
            rho_ed: rho_ed.clone(),
            R1: R1.clone(),
            R2: R2.clone(),
        }
    }
}

/// Struct holding the public outputs from a ZK update proof.
#[allow(non_snake_case)]
#[derive(Debug, Clone)]
pub struct PublicUpdate {
    /// **Τ_(i-1)** - The public key/curve point on Baby Jubjub for ω_(i-1).
    pub T_prev: Point,
    /// **Τ_i** - The public key/curve point on Baby Jubjub for ω_i.
    pub T_current: Point,
    /// **S_i** - The public key/curve point on Ed25519 for ω_i.
    pub S_current: MontgomeryPoint,
    /// **C** - The Fiat–Shamir heuristic challenge (`challenge_bytes`).
    pub challenge: BigUint,
    /// **ρ_BabyJubjub** - The Fiat–Shamir heuristic challenge response on the Baby Jubjub curve (`response_BabyJubJub`).
    pub rho_bjj: BigUint,
    /// **ρ_Ed25519** - The Fiat–Shamir heuristic challenge response on the Ed25519 curve (`response_div_ed25519`).
    pub rho_ed: BigUint,
    /// **R_BabyJubjub** - DLEQ commitment 1, which is a public key/curve point on Baby Jubjub (`R_1`).
    pub R_bjj: Point,
    /// **R_Ed25519** - DLEQ commitment 2, which is a public key/curve point on Ed25519 (`R_2`).
    pub R_ed: MontgomeryPoint,
}

#[allow(non_snake_case)]
impl PublicUpdate {
    pub fn new(
        T_prev: &Point,
        T_current: &Point,
        S_current: &MontgomeryPoint,
        challenge_bytes: &[u8; 32],
        rho_bjj: &BigUint,
        rho_ed: &BigUint,
        R_bjj: &Point,
        R_ed: &MontgomeryPoint,
    ) -> Self {
        let challenge: BigUint = BigUint::from_bytes_be(challenge_bytes);

        PublicUpdate {
            T_prev: T_prev.clone(),
            T_current: T_current.clone(),
            S_current: S_current.clone(),
            challenge: challenge,
            rho_bjj: rho_bjj.clone(),
            rho_ed: rho_ed.clone(),
            R_bjj: R_bjj.clone(),
            R_ed: R_ed.clone(),
        }
    }
}

pub fn bb_verify_update(
    public_update: &PublicUpdate,
    zero_knowledge_proof_update: &ZeroKnowledgeProofUpdate,
) -> Result<bool, BBError> {
    let proof = match zero_knowledge_proof_update.proof {
        Some(ref p) => p,
        None => return Err(BBError::String("Proof is missing".to_string())),
    };

    let public = match zero_knowledge_proof_update.public_input {
        Some(ref p) => {
            ZeroKnowledgeProofUpdatePublic::check(
                p,
                &public_update.T_prev,
                &public_update.T_current,
                &public_update.challenge,
            )?;

            p.to_vec()
        }
        None => {
            let p = ZeroKnowledgeProofUpdatePublic::new(
                &public_update.T_prev,
                &public_update.T_current,
                &public_update.challenge,
            )?;

            p.to_vec()
        }
    };

    let vk_update_key_bytes = include_bytes!("../target/vk/vkUpdate.key");
    let mut vk_update_key_file = NamedTempFile::with_suffix(".json")?;
    vk_update_key_file.write_all(vk_update_key_bytes)?;

    let vk_update_key_file_path = vk_update_key_file.path().to_string_lossy().to_string();

    let res = bb_verify(proof, &public, &vk_update_key_file_path)?;

    vk_update_key_file.close()?;

    Ok(res)
}

pub struct InitialProof {
    /// **Τ₀** - The public key/curve point on Baby Jubjub for ω₀.
    pub t_0: babyjubjub_rs::Point,
    /// **c₁** - Feldman commitment 1 (used in tandem with Feldman commitment 0 = Τ₀), which is a public key/curve point on Baby Jubjub.
    pub c_1: babyjubjub_rs::Point,
    /// **Φ₁** - The ephemeral public key/curve point on Baby Jubjub for message transportation to the peer.
    pub phi_1: babyjubjub_rs::Point,
    /// **χ₁** - The encrypted value of σ₁.
    pub enc_1: BigUint,
    /// **Φ₂** - The ephemeral public key/curve point on Baby Jubjub for message transportation to the KES.
    pub phi_2: babyjubjub_rs::Point,
    /// **χ₂** - The encrypted value of σ₂ (enc₂).
    pub enc_2: BigUint,
    /// **S₀** - The public key/curve point on Ed25519 for ω₀.
    pub s_0: MontgomeryPoint,
    /// **ρ_BabyJubjub** - The Fiat–Shamir heuristic challenge response on the Baby Jubjub curve (response_BabyJubJub).
    pub rho_bjj: BigUint,
    /// **ρ_Ed25519** - The Fiat–Shamir heuristic challenge response on the Ed25519 curve (response_div_ed25519).
    pub rho_ed: BigUint,
    /// **R_BabyJubjub** - The ... on the Baby Jubjub curve (R1).
    pub r1: babyjubjub_rs::Point,
    /// **R_Ed25519** - The ... on the Ed25519 curve (R2).
    pub r2: MontgomeryPoint,

    pub challenge_bytes: [u8; 32],
    pub witness_0: BigUint,
    pub share_1: BigUint,
    pub share_2: BigUint,
    pub response_div_baby_jub_jub: [u8; 32],
    pub response_div_ed25519: [u8; 32],
    pub zero_knowledge_proof_init: ZeroKnowledgeProofInit,
}

/// Generates initial proofs for the circuit.
pub fn generate_initial_proofs(
    nonce_peer: &BigUint,
    blinding: &BigUint,
    a_1: &BigUint,
    r_1: &BigUint,
    public_key_bjj_peer: &babyjubjub_rs::Point,
    r_2: &BigUint,
    kes_public_key: &babyjubjub_rs::Point,
    blinding_dleq: &BigUint,
    nargo_path: &Path,
) -> Result<InitialProof, BBError> {
    let (major, minor, build) = get_bb_version().unwrap();
    info!("`bb` version: {}.{}.{}", major, minor, build);

    let nargo_version = get_nargo_version().unwrap();
    info!("`nargo` version: {}", nargo_version);

    let (witness_0, t_0, s_0) = make_witness0(&nonce_peer, &blinding)?;

    let (c_1, share_1, share_2) = feldman_secret_share_2_of_2(&witness_0, &a_1)?;

    let (fi_1, enc_1) = encrypt_message_ecdh(&share_1, &r_1, &public_key_bjj_peer, None)?;

    let (fi_2, enc_2) = encrypt_message_ecdh(&share_2, &r_2, &kes_public_key, None)?;

    //NIZK DLEQ
    let (
        challenge_bytes,
        response_baby_jub_jub,
        response_ed25519,
        r1,
        r2,
        response_div_baby_jub_jub,
        response_div_ed25519,
    ) = generate_dleqproof_simple(&witness_0, &blinding_dleq)?;

    //Verify
    {
        let res = verify_dleq_simple(
            &t_0,
            &s_0,
            &challenge_bytes,
            &response_baby_jub_jub,
            &response_ed25519,
            &r1,
            &r2,
        );
        match res {
            Ok(verified) => {
                if verified {
                    info!("DLEQ verified");
                } else {
                    info!("DLEQ failed to verify!");
                    return Err(BBError::DLEQVerify);
                }
            }
            Err(e) => {
                info!("DLEQ failed to verify with error: {e}");
                return Err(e);
            }
        };
    }

    //Prove
    let zero_knowledge_proof_init = bb_prove_init(
        &a_1,
        &blinding,
        &blinding_dleq,
        &challenge_bytes,
        &enc_1,
        &enc_2,
        &nonce_peer,
        &r_1,
        &r_2,
        &left_pad_bytes_32_vec(&response_div_baby_jub_jub.to_bytes_be()),
        &left_pad_bytes_32_vec(&response_div_ed25519.to_bytes_be()),
        &response_baby_jub_jub,
        &left_pad_bytes_32_vec(&response_ed25519.to_bytes_be()),
        &share_1,
        &share_2,
        &witness_0,
        &t_0,
        &c_1,
        &fi_1,
        &fi_2,
        &kes_public_key,
        &public_key_bjj_peer,
        nargo_path,
    )?;

    //Verify
    let public_init = PublicInit::new(
        &t_0,
        &c_1,
        &fi_1,
        &enc_1,
        &fi_2,
        &enc_2,
        &s_0,
        &challenge_bytes,
        &response_baby_jub_jub,
        &response_ed25519,
        &r1,
        &r2,
    );

    let verification = bb_verify_init(
        &nonce_peer,
        &public_key_bjj_peer,
        &kes_public_key,
        &public_init,
        &zero_knowledge_proof_init,
    )?;
    if !verification {
        return Err(BBError::SelfVerify);
    }

    Ok(InitialProof {
        t_0,
        c_1,
        phi_1: fi_1,
        enc_1,
        phi_2: fi_2,
        enc_2,
        s_0,
        rho_bjj: response_baby_jub_jub,
        rho_ed: response_ed25519,
        r1,
        r2,

        challenge_bytes,
        witness_0,
        share_1,
        share_2,
        response_div_baby_jub_jub: left_pad_bytes_32_vec(&response_div_baby_jub_jub.to_bytes_be()),
        response_div_ed25519: left_pad_bytes_32_vec(&response_div_ed25519.to_bytes_be()),
        zero_knowledge_proof_init,
    })
}

pub struct UpdateProof {
    /// **Τ_i** - The public key/curve point on Baby Jubjub for ω_i.
    pub t_current: Point,
    /// **S_i** - The public key/curve point on Ed25519 for ω_i.
    pub s_current: MontgomeryPoint,
    /// **C** - The Fiat–Shamir heuristic challenge (`challenge_bytes`).
    pub challenge: BigUint,
    /// **ρ_BabyJubjub** - The Fiat–Shamir heuristic challenge response on the Baby Jubjub curve (`response_BabyJubJub`).
    pub rho_bjj: BigUint,
    /// **ρ_Ed25519** - The Fiat–Shamir heuristic challenge response on the Ed25519 curve (`response_div_ed25519`).
    pub rho_ed: BigUint,
    /// **R_BabyJubjub** - DLEQ commitment 1, which is a public key/curve point on Baby Jubjub (`R_1`).
    pub r_bjj: Point,
    /// **R_Ed25519** - DLEQ commitment 2, which is a public key/curve point on Ed25519 (`R_2`).
    pub r_ed: MontgomeryPoint,

    pub challenge_bytes: [u8; 32],
    pub witness_i: BigUint,
    pub response_div_baby_jub_jub: [u8; 32],
    pub response_div_ed25519: [u8; 32],
    pub zero_knowledge_proof_update: ZeroKnowledgeProofUpdate,
}

pub fn generate_update(
    witness_im1: &BigUint,
    blinding_dleq: &BigUint,
    t_im1: &Point,
    nargo_path: &Path,
) -> Result<UpdateProof, BBError> {
    let (witness_i, t_i, s_i) = make_vcof(&witness_im1)?;

    //NIZK DLEQ
    let (
        challenge_bytes,
        response_baby_jub_jub,
        response_ed25519,
        r1,
        r2,
        response_div_baby_jub_jub,
        response_div_ed25519,
    ) = generate_dleqproof_simple(&witness_i, &blinding_dleq)?;

    //Verify
    {
        let res = verify_dleq_simple(
            &t_i,
            &s_i,
            &challenge_bytes,
            &response_baby_jub_jub,
            &response_ed25519,
            &r1,
            &r2,
        );
        match res {
            Ok(verified) => {
                if verified {
                    info!("DLEQ verified");
                } else {
                    info!("DLEQ failed to verify!");
                    return Err(BBError::DLEQVerify);
                }
            }
            Err(e) => {
                info!("DLEQ failed to verify with error: {e}");
                return Err(e);
            }
        };
    }

    //Prove
    let zero_knowledge_proof_update = bb_prove_update(
        &blinding_dleq,
        &challenge_bytes,
        &left_pad_bytes_32_vec(&response_div_baby_jub_jub.to_bytes_be()),
        &left_pad_bytes_32_vec(&response_div_ed25519.to_bytes_be()),
        &response_baby_jub_jub,
        &left_pad_bytes_32_vec(&response_ed25519.to_bytes_be()),
        &witness_i,
        &witness_im1,
        &t_i,
        &t_im1,
        nargo_path,
    )?;

    //Verify
    let public_update = PublicUpdate::new(
        &t_im1,
        &t_i,
        &s_i,
        &challenge_bytes,
        &response_div_baby_jub_jub,
        &response_div_ed25519,
        &r1,
        &r2,
    );

    let verification = bb_verify_update(&public_update, &zero_knowledge_proof_update)?;
    if !verification {
        return Err(BBError::SelfVerify);
    }

    Ok(UpdateProof {
        t_current: t_i,
        s_current: s_i,
        challenge: BigUint::from_bytes_be(&challenge_bytes),
        rho_bjj: response_baby_jub_jub,
        rho_ed: response_ed25519,
        r_bjj: r1,
        r_ed: r2,

        challenge_bytes,
        witness_i,
        response_div_baby_jub_jub: left_pad_bytes_32_vec(&response_div_baby_jub_jub.to_bytes_be()),
        response_div_ed25519: left_pad_bytes_32_vec(&response_div_ed25519.to_bytes_be()),
        zero_knowledge_proof_update,
    })
}

//TESTS

#[cfg(test)]
mod test {
    use crate::info;
    use crate::*;
    use num_bigint::BigUint;

    #[test]
    fn test_generate_dleqproof_simple() {
        let mut rng = &mut rand::rng();

        for _i in 0..100 {
            let nonce_peer = crate::make_scalar_bjj(rng);
            let blinding = crate::make_scalar_bjj(rng);

            let (witness_i, t_i, s_i) = crate::make_witness0(&nonce_peer, &blinding).unwrap();

            let blinding_dleq: BigUint = crate::make_scalar_bjj(&mut rng);
            let (
                challenge_bytes,
                response_baby_jub_jub,
                response_ed25519,
                r1,
                r2,
                _response_div_baby_jub_jub,
                _response_div_ed25519,
            ) = crate::generate_dleqproof_simple(&witness_i, &blinding_dleq).unwrap();

            let res = crate::verify_dleq_simple(
                &t_i,
                &s_i,
                &challenge_bytes,
                &response_baby_jub_jub,
                &response_ed25519,
                &r1,
                &r2,
            )
            .unwrap();
            assert!(res);
        }
    }

    #[test]
    fn test_not_verify_dleq_simple() {
        let mut rng = &mut rand::rng();

        for _i in 0..100 {
            let nonce_peer_i = crate::make_scalar_bjj(rng);
            let blinding_i = crate::make_scalar_bjj(rng);

            let (witness_i, t_i, s_i) = crate::make_witness0(&nonce_peer_i, &blinding_i).unwrap();

            let blinding_dleq_i: BigUint = crate::make_scalar_bjj(&mut rng);
            let (
                challenge_bytes_i,
                response_baby_jub_jub_i,
                response_ed25519_i,
                r1_i,
                r2_i,
                _response_div_baby_jub_jub,
                _response_div_ed25519,
            ) = crate::generate_dleqproof_simple(&witness_i, &blinding_dleq_i).unwrap();

            let nonce_peer_j = crate::make_scalar_bjj(rng);
            let blinding_j = crate::make_scalar_bjj(rng);

            let (witness_j, t_j, s_j) = crate::make_witness0(&nonce_peer_j, &blinding_j).unwrap();

            let blinding_dleq_j: BigUint = crate::make_scalar_bjj(&mut rng);
            let (
                challenge_bytes_j,
                response_baby_jub_jub_j,
                response_ed25519_j,
                r1_j,
                r2_j,
                _response_div_baby_jub_jub,
                _response_div_ed25519,
            ) = crate::generate_dleqproof_simple(&witness_j, &blinding_dleq_j).unwrap();

            let res = crate::verify_dleq_simple(
                &t_j,
                &s_i,
                &challenge_bytes_i,
                &response_baby_jub_jub_i,
                &response_ed25519_i,
                &r1_i,
                &r2_i,
            )
            .unwrap();
            assert!(!res);

            let res = crate::verify_dleq_simple(
                &t_i,
                &s_j,
                &challenge_bytes_i,
                &response_baby_jub_jub_i,
                &response_ed25519_i,
                &r1_i,
                &r2_i,
            )
            .unwrap();
            assert!(!res);

            let res = crate::verify_dleq_simple(
                &t_i,
                &s_i,
                &challenge_bytes_j,
                &response_baby_jub_jub_i,
                &response_ed25519_i,
                &r1_i,
                &r2_i,
            )
            .unwrap();
            assert!(!res);

            let res = crate::verify_dleq_simple(
                &t_i,
                &s_i,
                &challenge_bytes_i,
                &response_baby_jub_jub_j,
                &response_ed25519_i,
                &r1_i,
                &r2_i,
            )
            .unwrap();
            assert!(!res);

            let res = crate::verify_dleq_simple(
                &t_i,
                &s_i,
                &challenge_bytes_i,
                &response_baby_jub_jub_i,
                &response_ed25519_j,
                &r1_i,
                &r2_i,
            )
            .unwrap();
            assert!(!res);

            let res = crate::verify_dleq_simple(
                &t_i,
                &s_i,
                &challenge_bytes_i,
                &response_baby_jub_jub_i,
                &response_ed25519_i,
                &r1_j,
                &r2_i,
            )
            .unwrap();
            assert!(!res);

            let res = crate::verify_dleq_simple(
                &t_i,
                &s_i,
                &challenge_bytes_i,
                &response_baby_jub_jub_i,
                &response_ed25519_i,
                &r1_i,
                &r2_j,
            )
            .unwrap();
            assert!(!res);
        }
    }

    #[test]
    fn test_bb_prove_init() {
        let nargo_path: &Path = Path::new(".");

        let rng = &mut rand::rng();

        let nonce_peer: BigUint = crate::make_scalar_bjj(rng);
        let blinding = crate::make_scalar_bjj(rng);

        let (witness_0, t_0, s_0) = crate::make_witness0(&nonce_peer, &blinding).unwrap();

        let a_1 = crate::make_scalar_bjj(rng);
        let (c_1, share_1, share_2) = crate::feldman_secret_share_2_of_2(&witness_0, &a_1).unwrap();

        let r_1 = crate::make_scalar_bjj(rng);
        let (_, public_key_peer) = crate::make_keypair_bjj(rng);
        let (fi_1, enc_1) = crate::encrypt_message_ecdh(&share_1, &r_1, &public_key_peer, None).unwrap();

        let r_2 = crate::make_scalar_bjj(rng);
        let (_, kes_public_key) = crate::make_keypair_bjj(rng);
        let (fi_2, enc_2) = crate::encrypt_message_ecdh(&share_2, &r_2, &kes_public_key, None).unwrap();

        let blinding_dleq = crate::make_scalar_bjj(rng);

        let (
            challenge_bytes,
            response_baby_jub_jub,
            response_ed25519,
            r1,
            r2,
            response_div_baby_jub_jub,
            response_div_ed25519,
        ) = crate::generate_dleqproof_simple(&witness_0, &blinding_dleq).unwrap();

        let zero_knowledge_proof_init = crate::bb_prove_init(
            &a_1,
            &blinding,
            &blinding_dleq,
            &challenge_bytes,
            &enc_1,
            &enc_2,
            &nonce_peer,
            &r_1,
            &r_2,
            &crate::left_pad_bytes_32_vec(&response_div_baby_jub_jub.to_bytes_be()),
            &crate::left_pad_bytes_32_vec(&response_div_ed25519.to_bytes_be()),
            &response_baby_jub_jub,
            &crate::left_pad_bytes_32_vec(&response_ed25519.to_bytes_be()),
            &share_1,
            &share_2,
            &witness_0,
            &t_0,
            &c_1,
            &fi_1,
            &fi_2,
            &kes_public_key,
            &public_key_peer,
            &nargo_path,
        )
        .unwrap();

        //Verify
        let public_init = crate::PublicInit::new(
            &t_0,
            &c_1,
            &fi_1,
            &enc_1,
            &fi_2,
            &enc_2,
            &s_0,
            &challenge_bytes,
            &response_baby_jub_jub,
            &response_ed25519,
            &r1,
            &r2,
        );

        let verification = crate::bb_verify_init(
            &nonce_peer,
            &public_key_peer,
            &kes_public_key,
            &public_init,
            &zero_knowledge_proof_init,
        )
        .unwrap();
        assert!(verification);
    }

    #[test]
    fn test_bb_prove_update() {
        let nargo_path: &Path = Path::new(".");

        let mut rng = &mut rand::rng();

        let nonce_peer = crate::make_scalar_bjj(rng);
        let blinding = crate::make_scalar_bjj(rng);

        let (witness_im1, t_im1, _) = crate::make_witness0(&nonce_peer, &blinding).unwrap();
        let (witness_i, t_i, s_i) = crate::make_vcof(&witness_im1).unwrap();

        let blinding_dleq: BigUint = crate::make_scalar_bjj(&mut rng);
        let (
            challenge_bytes,
            response_baby_jub_jub,
            response_ed25519,
            r1,
            r2,
            response_div_baby_jub_jub,
            response_div_ed25519,
        ) = crate::generate_dleqproof_simple(&witness_i, &blinding_dleq).unwrap();

        //Prove
        let zero_knowledge_proof_update = crate::bb_prove_update(
            &blinding_dleq,
            &challenge_bytes,
            &crate::left_pad_bytes_32_vec(&response_div_baby_jub_jub.to_bytes_be()),
            &crate::left_pad_bytes_32_vec(&response_div_ed25519.to_bytes_be()),
            &response_baby_jub_jub,
            &crate::left_pad_bytes_32_vec(&response_ed25519.to_bytes_be()),
            &witness_i,
            &witness_im1,
            &t_i,
            &t_im1,
            &nargo_path,
        )
        .unwrap();

        //Verify
        let public_update = crate::PublicUpdate::new(
            &t_im1,
            &t_i,
            &s_i,
            &challenge_bytes,
            &response_div_baby_jub_jub,
            &response_div_ed25519,
            &r1,
            &r2,
        );

        let verification = crate::bb_verify_update(&public_update, &zero_knowledge_proof_update).unwrap();
        assert!(verification);
    }

    #[test]
    fn test_demo() {
        let nargo_path: &Path = Path::new(".");

        let (major, minor, build) = get_bb_version().unwrap();
        info!("`bb` version: {}.{}.{}", major, minor, build);

        let nargo_version = get_nargo_version().unwrap();
        info!("`nargo` version: {}", nargo_version);

        // nonce_peer = "867303429418806279313526868407228138995734763278095857482747693606556032536"
        // blinding = "1194608745245961475824979247056446722984763446987071492294235640987034156744"
        // witness_0 = "2300713427460276953780870141649614997452366291219964647997231433928304383861"
        // [T_0]
        //   x="0x0ef59b243ee8819f82a6da86c875508d0e786c7453ef791beae4fcf0ae88c933"
        //   y="0x2a8a23239d91f7c2ff94c2b094bb91ff6751c03b76fd69a8770186628753ad4f"
        let nonce_peer = BigUint::parse_bytes(
            b"867303429418806279313526868407228138995734763278095857482747693606556032536",
            10,
        )
        .unwrap();
        assert!(nonce_peer <= *BABY_JUBJUB_ORDER);

        let blinding = BigUint::parse_bytes(
            b"1194608745245961475824979247056446722984763446987071492294235640987034156744",
            10,
        )
        .unwrap();

        let (witness_0, t_0, s_0) = make_witness0(&nonce_peer, &blinding).unwrap();

        assert_eq!(
            witness_0,
            BigUint::parse_bytes(
                b"2300713427460276953780870141649614997452366291219964647997231433928304383861",
                10
            )
            .unwrap()
        );
        assert_eq!(
            t_0.x.to_string(),
            "Fr(0x0ef59b243ee8819f82a6da86c875508d0e786c7453ef791beae4fcf0ae88c933)"
        );
        assert_eq!(
            t_0.y.to_string(),
            "Fr(0x2a8a23239d91f7c2ff94c2b094bb91ff6751c03b76fd69a8770186628753ad4f)"
        );

        // a_1 = "70143195093839929636068986763442859911856008756585124285077086015668936144"
        let a_1: BigUint = BigUint::parse_bytes(
            b"70143195093839929636068986763442859911856008756585124285077086015668936144",
            10,
        )
        .unwrap();

        // share_1 = "365173736425792519363861589744101528712591672182017486917907141004474053036"
        // share_2 = "1935539691034484434417008551905513468739774619037947161079324292923830330825"
        // [c_1]
        //   x="0x2c5e461e413c866bcf8a62d8cdff41e557f79c0629b7383dbe91b18096e09540"
        //   y="0x13a5434cda8f9d6c64724d2171ac4f9bb873b26c175e87c5dd5473b502b85312"

        let (c_1, share_1, share_2) = feldman_secret_share_2_of_2(&witness_0, &a_1).unwrap();

        assert_eq!(
            c_1.x.to_string(),
            "Fr(0x2c5e461e413c866bcf8a62d8cdff41e557f79c0629b7383dbe91b18096e09540)"
        );
        assert_eq!(
            c_1.y.to_string(),
            "Fr(0x13a5434cda8f9d6c64724d2171ac4f9bb873b26c175e87c5dd5473b502b85312)"
        );
        assert_eq!(
            share_1,
            BigUint::parse_bytes(
                b"365173736425792519363861589744101528712591672182017486917907141004474053036",
                10
            )
            .unwrap()
        );
        assert_eq!(
            share_2,
            BigUint::parse_bytes(
                b"1935539691034484434417008551905513468739774619037947161079324292923830330825",
                10
            )
            .unwrap()
        );

        let r_1: BigUint = BigUint::parse_bytes(
            b"2422852404430683902810753577573102653260911761556849713949680014072177383950",
            10,
        )
        .unwrap();
        let private_key_bjj_peer: BigUint = BigUint::parse_bytes(b"1", 10).unwrap();
        let public_key_bjj_peer = get_scalar_to_point_bjj(&private_key_bjj_peer);

        // enc_1 = "1220122097491108282229984040904504012545109624322527294624787674340936491877"
        // [fi_1]
        //   x="0x09d58da0c2ab2b11cc1f8579f739e7e463235185753ab5d4719e8db6aa476a23"
        //   y="0x1bc9eb7eab983bfd017433c4ed524b8bfde9db0abda7c7940e9c43822268b4ce"

        let (fi_1, enc_1) =
            encrypt_message_ecdh(&share_1, &r_1, &public_key_bjj_peer, Some(&private_key_bjj_peer)).unwrap();

        assert_eq!(
            fi_1.x.to_string(),
            "Fr(0x09d58da0c2ab2b11cc1f8579f739e7e463235185753ab5d4719e8db6aa476a23)"
        );
        assert_eq!(
            fi_1.y.to_string(),
            "Fr(0x1bc9eb7eab983bfd017433c4ed524b8bfde9db0abda7c7940e9c43822268b4ce)"
        );
        // assert_eq!(enc_1, BigUint::parse_bytes(b"1220122097491108282229984040904504012545109624322527294624787674340936491877", 10).unwrap());

        // r_2 = "2044680745167638013838014513951032949701446715960700123553928808460151041757"
        let r_2: BigUint = BigUint::parse_bytes(
            b"2044680745167638013838014513951032949701446715960700123553928808460151041757",
            10,
        )
        .unwrap();
        // [pubkey_KES]
        //   x="0x12f87860325f2ba2d84d9332a0bedc25edd93736776e818d8993a1da678958bf"
        //   y="0x105900362a575a29943602c90d432768f271ffb8f06af513dcd81d05c3a2c4a3"
        let private_key_kes: BigUint = BigUint::parse_bytes(b"1", 10).unwrap();
        let kes_public_key = get_scalar_to_point_bjj(&private_key_kes);

        // enc_2 = "321084871571726505169933431313947177118001726846734186078876149279016535274"
        // [fi_2]
        //   x="0x0ac31edd3af81f177137239a950c8f70662c4b6fbbeec57dae63bfcb61d931ee"
        //   y="0x1975e7e9cbe0f2ed7a06a09e320036ea1a73862ee2614d2a9a6452d8f7c9aff0"

        let (fi_2, enc_2) = encrypt_message_ecdh(&share_2, &r_2, &kes_public_key, Some(&private_key_kes)).unwrap();

        assert_eq!(
            fi_2.x.to_string(),
            "Fr(0x0ac31edd3af81f177137239a950c8f70662c4b6fbbeec57dae63bfcb61d931ee)"
        );
        assert_eq!(
            fi_2.y.to_string(),
            "Fr(0x1975e7e9cbe0f2ed7a06a09e320036ea1a73862ee2614d2a9a6452d8f7c9aff0)"
        );
        // assert_eq!(enc_2, BigUint::parse_bytes(b"321084871571726505169933431313947177118001726846734186078876149279016535274", 10).unwrap());

        //NIZK DLEQ
        //witness_0 = "2300713427460276953780870141649614997452366291219964647997231433928304383861"
        //blinding_DLEQ = "2124419834422738134599198304606394937234744825834207315619962749021962198236"
        let blinding_dleq: BigUint = BigUint::parse_bytes(
            b"2124419834422738134599198304606394937234744825834207315619962749021962198236",
            10,
        )
        .unwrap();

        // challenge_bytes = ["70", "175", "116", "95", "222", "182", "167", "46", "250", "55", "224", "163", "151", "38", "249", "118", "164", "60", "161", "13", "51", "180", "44", "130", "88", "112", "39", "95", "199", "211", "205", "170"]
        // response_div_BabyJubJub = ["59", "112", "95", "49", "212", "50", "147", "95", "65", "212", "106", "163", "115", "202", "43", "9", "237", "146", "95", "42", "154", "192", "240", "97", "48", "16", "62", "89", "208", "218", "231", "122"]
        // response_div_ed25519 = ["22", "120", "183", "234", "225", "42", "119", "48", "136", "156", "27", "246", "45", "74", "146", "179", "21", "185", "166", "143", "57", "60", "44", "4", "13", "124", "185", "146", "8", "243", "13", "71"]
        // response_BabyJubJub = "1211850493455143960510207598095808109935776728332172864532400139827493102076"
        // response_ed25519 = ["3", "121", "103", "121", "181", "67", "31", "235", "146", "100", "96", "34", "64", "223", "93", "249", "211", "176", "61", "162", "126", "47", "95", "136", "157", "106", "192", "62", "33", "72", "152", "27"]

        let (
            challenge_bytes_init,
            response_baby_jub_jub,
            response_ed25519,
            r1,
            r2,
            response_div_baby_jub_jub,
            response_div_ed25519,
        ) = generate_dleqproof_simple(&witness_0, &blinding_dleq).unwrap();

        // assert_eq!(challenge_bytes, BigUint::parse_bytes(b"", 10).unwrap());
        // assert_eq!(response_div_BabyJubJub, BigUint::parse_bytes(b"", 10).unwrap());
        // assert_eq!(response_div_ed25519, BigUint::parse_bytes(b"", 10).unwrap());
        // assert_eq!(response_BabyJubJub, BigUint::parse_bytes(b"1211850493455143960510207598095808109935776728332172864532400139827493102076", 10).unwrap());
        // assert_eq!(response_ed25519, BigUint::parse_bytes(b"", 10).unwrap());

        //Verify
        {
            let res = verify_dleq_simple(
                &t_0,
                &s_0,
                &challenge_bytes_init,
                &response_baby_jub_jub,
                &response_ed25519,
                &r1,
                &r2,
            );
            match res {
                Ok(verified) => {
                    if verified {
                        info!("DLEQ verified");
                    } else {
                        info!("DLEQ failed to verify!");
                        std::process::exit(1);
                    }
                }
                Err(e) => {
                    info!("DLEQ failed to verify with error: {e}");
                    std::process::exit(1);
                }
            };
        }

        //Prove
        let zero_knowledge_proof_init = bb_prove_init(
            &a_1,
            &blinding,
            &blinding_dleq,
            &challenge_bytes_init,
            &enc_1,
            &enc_2,
            &nonce_peer,
            &r_1,
            &r_2,
            &left_pad_bytes_32_vec(&response_div_baby_jub_jub.to_bytes_be()),
            &left_pad_bytes_32_vec(&response_div_ed25519.to_bytes_be()),
            &response_baby_jub_jub,
            &left_pad_bytes_32_vec(&response_ed25519.to_bytes_be()),
            &share_1,
            &share_2,
            &witness_0,
            &t_0,
            &c_1,
            &fi_1,
            &fi_2,
            &kes_public_key,
            &public_key_bjj_peer,
            &nargo_path,
        )
        .unwrap();

        //Verify
        let public_init = PublicInit::new(
            &t_0,
            &c_1,
            &fi_1,
            &enc_1,
            &fi_2,
            &enc_2,
            &s_0,
            &challenge_bytes_init,
            &response_baby_jub_jub,
            &response_ed25519,
            &r1,
            &r2,
        );

        let verification = bb_verify_init(
            &nonce_peer,
            &public_key_bjj_peer,
            &kes_public_key,
            &public_init,
            &zero_knowledge_proof_init,
        )
        .unwrap();
        assert!(verification);

        //witness_i = "1012694528770316483559205215366203370757356884565651608309268621249697619247"
        // [T_i]
        //   x="0x1801440d7cc296b99d80ddbf15bdb5ae311bb2f95bce3baa58a6fae05554d4d5"
        //   y="0x030d84e498313c8dec9339118da693fff141cc5db8c3773daaf1980cb7b3d654"
        let (witness_1, t_1, s_1) = make_vcof(&witness_0).unwrap();

        assert_eq!(
            witness_1,
            BigUint::parse_bytes(
                b"1012694528770316483559205215366203370757356884565651608309268621249697619247",
                10
            )
            .unwrap()
        );
        assert_eq!(
            t_1.x.to_string(),
            "Fr(0x1801440d7cc296b99d80ddbf15bdb5ae311bb2f95bce3baa58a6fae05554d4d5)"
        );
        assert_eq!(
            t_1.y.to_string(),
            "Fr(0x030d84e498313c8dec9339118da693fff141cc5db8c3773daaf1980cb7b3d654)"
        );

        //NIZK DLEQ
        //witness_i = "1012694528770316483559205215366203370757356884565651608309268621249697619247"
        //blinding_DLEQ = "2725795056938475204625712545454751566443431544642757859965717362752762117487"
        let blinding_dleq_1: BigUint = BigUint::parse_bytes(
            b"2725795056938475204625712545454751566443431544642757859965717362752762117487",
            10,
        )
        .unwrap();

        // challenge_bytes = ["173", "177", "148", "180", "137", "70", "241", "143", "132", "241", "114", "212", "56", "49", "45", "192", "249", "176", "190", "143", "43", "192", "90", "61", "171", "183", "234", "227", "149", "245", "14", "127"]
        // response_div_BabyJubJub = ["64", "74", "43", "78", "21", "50", "143", "116", "56", "136", "47", "130", "159", "25", "232", "118", "110", "84", "144", "7", "93", "93", "99", "123", "21", "7", "21", "76", "4", "5", "135", "150"]
        // response_div_ed25519 = ["24", "78", "49", "150", "2", "128", "248", "182", "216", "15", "56", "209", "152", "115", "125", "71", "219", "162", "159", "226", "115", "116", "208", "211", "176", "90", "239", "55", "108", "6", "182", "60"]
        // response_BabyJubJub = "665215325844649228417070916130511037968741095567000659557494451588541621932"
        // response_ed25519 = ["14", "254", "72", "212", "229", "12", "54", "141", "103", "181", "191", "236", "63", "129", "185", "181", "85", "56", "102", "106", "13", "21", "59", "225", "113", "165", "17", "187", "121", "239", "101", "86"]

        let (
            challenge_bytes_update,
            response_baby_jub_jub_update,
            response_ed25519_update,
            r1_update,
            r2_update,
            response_div_baby_jub_jub_update,
            response_div_ed25519_update,
        ) = generate_dleqproof_simple(&witness_1, &blinding_dleq_1).unwrap();

        // assert_eq!(challenge_bytes_1, BigUint::parse_bytes(b"", 10).unwrap());
        // assert_eq!(response_div_BabyJubJub_1, BigUint::parse_bytes(b"", 10).unwrap());
        // assert_eq!(response_div_ed25519_1, BigUint::parse_bytes(b"", 10).unwrap());
        // assert_eq!(
        //     response_baby_jub_jub_update,
        //     BigUint::parse_bytes(
        //         b"665215325844649228417070916130511037968741095567000659557494451588541621932",
        //         10
        //     )
        //     .unwrap()
        // );
        // assert_eq!(response_ed25519_1, BigUint::parse_bytes(b"", 10).unwrap());

        //Verify
        {
            let res = verify_dleq_simple(
                &t_1,
                &s_1,
                &challenge_bytes_update,
                &response_baby_jub_jub_update,
                &response_ed25519_update,
                &r1_update,
                &r2_update,
            );
            match res {
                Ok(verified) => {
                    if verified {
                        info!("DLEQ verified");
                    } else {
                        info!("DLEQ failed to verify!");
                        std::process::exit(1);
                    }
                }
                Err(e) => {
                    info!("DLEQ failed to verify with error: {e}");
                    std::process::exit(1);
                }
            };
        }

        //Prove
        let zero_knowledge_proof_update = bb_prove_update(
            &blinding_dleq_1,
            &challenge_bytes_update,
            &left_pad_bytes_32_vec(&response_div_baby_jub_jub_update.to_bytes_be()),
            &left_pad_bytes_32_vec(&response_div_ed25519_update.to_bytes_be()),
            &response_baby_jub_jub_update,
            &left_pad_bytes_32_vec(&response_ed25519_update.to_bytes_be()),
            &witness_1,
            &witness_0,
            &t_1,
            &t_0,
            &nargo_path,
        )
        .unwrap();

        //Verify
        let public_update = crate::PublicUpdate::new(
            &t_0,
            &t_1,
            &s_1,
            &challenge_bytes_update,
            &response_div_baby_jub_jub_update,
            &response_div_ed25519_update,
            &r1_update,
            &r2_update,
        );

        let verification = bb_verify_update(&public_update, &zero_knowledge_proof_update).unwrap();
        assert!(verification);

        println!("Success!");
    }
}
