use babyjubjub_rs::*;
use blake2::{Blake2s256, Digest};
use curve25519_dalek::constants::X25519_BASEPOINT;
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::Scalar;
use ff_ce::PrimeField;
use num_bigint::{BigInt, BigUint};
// use ciphersuite::group::ff::PrimeField;
use ff_ce::Field;
use hex;
use num_traits::ops::euclid::Euclid;
use poseidon_rs::Fr;
use rand::{CryptoRng, RngCore};
use serde::Serialize;
use std::io::Write;
use std::io::{self, Read};
use std::process::{Command, Stdio};
use tempfile::NamedTempFile;
use thiserror::Error;
use toml;

use lazy_static::lazy_static;
lazy_static! {
    static ref B8: Point = Point {
        x: Fr::from_str("5299619240641551281634865583518297030282874472190772894086521144482721001553",).unwrap(),
        y: Fr::from_str("16950150798460657717958625567821834550301663161624707787222815936182638968203",).unwrap(),
    };
    static ref BABY_JUBJUB_ORDER: BigUint = BigUint::parse_bytes(
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
    // #[error("An error occurred.")]
    // String(#[from] std::string::String),
    #[error("An error occurred. {0}")]
    String(String),
}

impl Into<BBError> for std::string::String {
    fn into(self) -> BBError {
        BBError::String(self)
    }
}

impl Into<BBError> for &str {
    fn into(self) -> BBError {
        BBError::String(self.to_string())
    }
}

fn left_pad_bytes_32(input: &[u8]) -> [u8; 32] {
    assert!(input.len() <= 32, "Input length exceeds target length");

    let mut result = [0u8; 32];
    let offset = 32 - input.len();
    result[offset..].copy_from_slice(input);
    result
}
pub fn left_pad_bytes_32_vec(input: &Vec<u8>) -> [u8; 32] {
    assert!(input.len() <= 32, "Input length exceeds target length");

    let mut result = [0u8; 32];
    let offset = 32 - input.len();
    result[offset..].copy_from_slice(input);
    result
}
fn right_pad_bytes_32(input: &[u8]) -> [u8; 32] {
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
        field_object.len() != 72,
        "get_field_bytes: field is not correctly self-describing"
    );

    // Decode hex string to bytes
    let substring = &field_object[5..69];
    let bytes = hex::decode(substring).map_err(|_| "Invalid hex string").unwrap();

    bytes.try_into().unwrap()
}
pub fn get_bjjpoint_from_scalar(scalar: &BigUint) -> Point {
    assert!(*scalar < *BABY_JUBJUB_ORDER);

    let scalar_i: BigInt = scalar.clone().into();

    let p = B8.mul_scalar(&scalar_i);
    p
}
fn get_scalar_to_point_ed25519(scalar_big_uint: &BigUint) -> MontgomeryPoint {
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
fn subtract_montgomery_points(point1: MontgomeryPoint, point2: MontgomeryPoint, sign: u8) -> Option<MontgomeryPoint> {
    // Convert both MontgomeryPoints to EdwardsPoints
    let edwards1 = point1.to_edwards(sign)?;
    let edwards2 = point2.to_edwards(sign)?;

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

pub fn make_keypair<R: CryptoRng + RngCore>(_rng: &mut R) -> (BigUint, babyjubjub_rs::Point) {
    todo!();
}

pub fn make_witness0(
    nonce_peer: &BigUint,
    blinding: &BigUint,
) -> Result<(BigUint, babyjubjub_rs::Point, MontgomeryPoint), BBError> {
    assert!(*nonce_peer < *BABY_JUBJUB_ORDER);
    assert!(*blinding < *BABY_JUBJUB_ORDER);

    // Input byte array
    let header: [u8; 32] = [0; 32]; // VerifyWitness0 HASH_HEADER_CONSTANT
    let nonce_peer_bytes = nonce_peer.to_bytes_be();
    let blinding_bytes = blinding.to_bytes_be();
    let mut result = Vec::with_capacity(96);
    result.extend_from_slice(&header);
    result.extend_from_slice(&left_pad_bytes_32(&nonce_peer_bytes));
    result.extend_from_slice(&left_pad_bytes_32(&blinding_bytes));

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
pub fn feldman_secret_share_2_of_2(
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
pub fn encrypt_message_ecdh(
    message: &BigUint,
    r: &BigUint,
    pubkey: &babyjubjub_rs::Point,
    private_key: Option<&BigUint>,
) -> Result<(babyjubjub_rs::Point, BigUint), BBError> {
    let R = B8.mul_scalar(&r.clone().into());
    let r_p = pubkey.mul_scalar(&r.clone().into());

    // Input byte array
    let r_p_x_bytes = get_field_bytes(&r_p.x);
    let r_p_y_bytes = get_field_bytes(&r_p.y);
    let mut result = Vec::with_capacity(64);
    result.extend_from_slice(&left_pad_bytes_32(&r_p_x_bytes));
    result.extend_from_slice(&left_pad_bytes_32(&r_p_y_bytes));

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

    let fi = R;
    let enc = cipher;

    if let Some(private_key) = private_key {
        //Verify
        let private_key_i: BigInt = private_key.clone().into();

        let fi_s: Point = fi.mul_scalar(&private_key_i);
        assert_eq!(fi_s.x, r_p.x);
        assert_eq!(fi_s.y, r_p.y);

        // Input byte array
        let fi_s_x_bytes = get_field_bytes(&fi_s.x);
        let fi_s_y_bytes = get_field_bytes(&fi_s.y);
        let mut result = Vec::with_capacity(64);
        result.extend_from_slice(&left_pad_bytes_32(&fi_s_x_bytes));
        result.extend_from_slice(&left_pad_bytes_32(&fi_s_y_bytes));

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
        assert_eq!(shared_secret_calc, shared_secret);

        let share_calc = &enc + BABY_JUBJUB_ORDER.clone() - &shared_secret_calc;
        let share_calc: BigUint = share_calc.rem_euclid(&BABY_JUBJUB_ORDER);
        assert_eq!(share_calc, *message);
    }
    Ok((fi, enc))
}

//Update/VerifyCOF
pub fn make_vcof(witness_im1: &BigUint) -> Result<(BigUint, babyjubjub_rs::Point, MontgomeryPoint), BBError> {
    assert!(*witness_im1 < *BABY_JUBJUB_ORDER);

    // Input byte array
    let header: [u8; 32] = [0; 32]; // VerifyWitness0 HASH_HEADER_CONSTANT
    let witness_im1_bytes = witness_im1.to_bytes_be();
    let mut result = Vec::with_capacity(64);
    result.extend_from_slice(&header);
    result.extend_from_slice(&left_pad_bytes_32(&witness_im1_bytes));

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

pub fn generate_dleqproof_simple(
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

        let r2_calc = subtract_montgomery_points(c_s, response_ed25519_g2, 0u8).unwrap();
        assert_eq!(r2_calc, r2);
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

    assert_eq!(challenge_bytes_calc, *challenge_bytes);

    //Verify: r.G == c.x.G - (c*x-r).G => R == c.T - z.G
    //        R1 == challenge_BabyJubJub.T - response_BabyJubJub_g1.G
    let response_baby_jub_jub_g1: Point = B8.mul_scalar(&response_baby_jub_jub.clone().into());
    let challenge_baby_jub_jub: BigUint = challenge_bigint.rem_euclid(&BABY_JUBJUB_ORDER);
    let challenge_baby_jub_jub_t: Point = t.mul_scalar(&challenge_baby_jub_jub.clone().into());

    let r1_calc =
        challenge_baby_jub_jub_t.projective().add(&point_negate(response_baby_jub_jub_g1).projective()).affine();
    assert_eq!(r1.x, r1_calc.x);
    assert_eq!(r1.y, r1_calc.y);

    //Verify: r.G == c.x.G - (c*x-r).G => R == c.T - z.G
    //        R2 == challenge_ed25519.S - response_ed25519.G
    let response_ed25519_g2: MontgomeryPoint = get_scalar_to_point_ed25519(&response_ed25519);
    let challenge_ed25519: BigUint = challenge_bigint.rem_euclid(&ED25519_ORDER);
    let challenge_ed25519_s: MontgomeryPoint = multiply_point_by_scalar_ed25519(&s, &challenge_ed25519);

    let r2_calc = subtract_montgomery_points(challenge_ed25519_s, response_ed25519_g2, 0u8).unwrap();
    assert_eq!(*r2, r2_calc);

    return Ok(true);
}

enum Shell {
    Bb,
    Nargo,
}

fn call_shell(shell: Shell, args: &[&str]) -> io::Result<(Vec<u8>, String)> {
    let program = match shell {
        Shell::Bb => "bb",
        Shell::Nargo => "nargo",
    };
    // Spawn the bash command with the provided arguments
    let mut command = Command::new(program)
        .current_dir("./circuits")
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

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
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("Script failed with status: {}", status),
        ));
    }

    Ok((stdout_output, stderr_output.trim().to_string()))
}

pub fn get_bb_version() -> Result<(u8, u8, u8), BBError> {
    //bb --version
    let args: Vec<&'static str> = vec!["--version"];
    match call_shell(Shell::Bb, &args) {
        Ok((stdout, _stderr)) => {
            let stdout = match str::from_utf8(&stdout) {
                Ok(v) => v,
                Err(e) => return Err(format!("Invalid UTF-8 sequence: {}", e).into()),
            };
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
                    Err(_) => return Err("Each part must be a valid u8 (0-255)".into()),
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
pub fn get_nargo_version() -> Result<String, BBError> {
    //nargo --version
    let args: Vec<&'static str> = vec!["--version"];
    match call_shell(Shell::Nargo, &args) {
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
    assert!(x.len() != 72, "get_field_bytes: field is not correctly self-describing");
    let x_str = &x[3..69];

    let y: String = point.y.to_string();
    assert!(y.len() != 72, "get_field_bytes: field is not correctly self-describing");
    let y_str = &y[3..69];

    PointConfig { x: x_str.to_string(), y: y_str.to_string() }
}

#[derive(Serialize)]
struct InitConfig {
    a_1: String,
    blinding: String,
    blinding_dleq: String,
    challenge_bytes: [String; 32],
    enc_1: String,
    enc_2: String,
    nonce_peer: String,
    r_1: String,
    r_2: String,
    response_div_baby_jub_jub: [String; 32],
    response_div_ed25519: [String; 32],
    response_baby_jub_jub: String,
    response_ed25519: [String; 32],
    share_1: String,
    share_2: String,
    witness_0: String,

    t_0: PointConfig,
    c_1: PointConfig,
    fi_1: PointConfig,
    fi_2: PointConfig,
    pubkey_kes: PointConfig,
    pubkey_peer: PointConfig,
}

#[derive(Serialize)]
struct UpdateConfig {
    blinding_dleq: String,
    challenge_bytes: [String; 32],
    response_div_baby_jub_jub: [String; 32],
    response_div_ed25519: [String; 32],
    response_baby_jub_jub: String,
    response_ed25519: [String; 32],
    witness_i: String,
    witness_im1: String,

    t_i: PointConfig,
    t_im1: PointConfig,
}

pub fn bb_prove_init(
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
    pubkey_kes: &Point,
    pubkey_peer: &Point,
) -> Result<Vec<u8>, BBError> {
    let config = InitConfig {
        a_1: a_1.to_string(),
        blinding: blinding.to_string(),
        blinding_dleq: blinding_dleq.to_string(),
        challenge_bytes: byte_array_to_string_array(&challenge_bytes),
        enc_1: enc_1.to_string(),
        enc_2: enc_2.to_string(),
        nonce_peer: nonce_peer.to_string(),
        r_1: r_1.to_string(),
        r_2: r_2.to_string(),
        response_div_baby_jub_jub: byte_array_to_string_array(&response_div_baby_jub_jub),
        response_div_ed25519: byte_array_to_string_array(&response_div_ed25519),
        response_baby_jub_jub: response_baby_jub_jub.to_string(),
        response_ed25519: byte_array_to_string_array(&response_ed25519),
        share_1: share_1.to_string(),
        share_2: share_2.to_string(),
        witness_0: witness_0.to_string(),

        t_0: get_point_config_baby_jubjub(t_0),
        c_1: get_point_config_baby_jubjub(c_1),
        fi_1: get_point_config_baby_jubjub(fi_1),
        fi_2: get_point_config_baby_jubjub(fi_2),
        pubkey_kes: get_point_config_baby_jubjub(pubkey_kes),
        pubkey_peer: get_point_config_baby_jubjub(pubkey_peer),
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
    let _ = match call_shell(Shell::Nargo, &args) {
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
    let args: Vec<&str> = vec!["prove", "-b", "./target/Grease.json", "-w", &witness_binary_file_path, "-v", "-o", "-"];
    let proof: Vec<u8> = match call_shell(Shell::Bb, &args) {
        Ok((stdout, _stderr)) => stdout,
        Err(e) => {
            eprintln!("Error: {}", e);
            return Err(BBError::IoError(e));
        }
    };

    //Delete temp file
    witness_binary_file.close()?;

    Ok(proof)
}

pub fn bb_verify(proof: &Vec<u8>, view_key_file: &str) -> Result<bool, BBError> {
    // Create a named temporary file
    let mut proof_file = NamedTempFile::new()?;

    // Write content to the temporary file
    proof_file.write_all(proof)?;

    let proof_file_path = proof_file.path().to_string_lossy().to_string();

    //nargo verify
    let args: Vec<&str> = vec!["verify", "-v", "-k", view_key_file, "-p", &proof_file_path];
    let ret: Result<bool, BBError> = match call_shell(Shell::Bb, &args) {
        Ok((_stdout, _stderr)) => Ok(true),
        Err(e) => {
            eprintln!("Error: {}", e);
            Err(e.into())
        }
    };

    //Delete temp file
    proof_file.close()?;

    ret
}

pub fn bb_verify_init(proof: &Vec<u8>) -> Result<bool, BBError> {
    bb_verify(proof, "./target/vk/vk.key")
}

pub fn bb_prove_update(
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
) -> Result<Vec<u8>, BBError> {
    let config = UpdateConfig {
        blinding_dleq: blinding_dleq.to_string(),
        challenge_bytes: byte_array_to_string_array(&challenge_bytes),
        response_div_baby_jub_jub: byte_array_to_string_array(&response_div_baby_jub_jub),
        response_div_ed25519: byte_array_to_string_array(&response_div_ed25519),
        response_baby_jub_jub: response_baby_jub_jub.to_string(),
        response_ed25519: byte_array_to_string_array(&response_ed25519),
        witness_i: witness_i.to_string(),
        witness_im1: witness_im1.to_string(),

        t_i: get_point_config_baby_jubjub(t_i),
        t_im1: get_point_config_baby_jubjub(t_im1),
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
    let _: String = match call_shell(Shell::Nargo, &args) {
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
    let args: Vec<&str> =
        vec!["prove", "-b", "./target/GreaseUpdate.json", "-w", &witness_binary_file_path, "-v", "-o", "-"];
    let proof = match call_shell(Shell::Bb, &args) {
        Ok((stdout, _stderr)) => stdout,
        Err(e) => {
            eprintln!("Error: {}", e);
            return Err(BBError::IoError(e));
        }
    };

    //Delete temp file
    witness_binary_file.close()?;

    Ok(proof)
}

pub fn bb_verify_update(proof: &Vec<u8>) -> Result<bool, BBError> {
    bb_verify(proof, "./target/vk/vkUpdate.key")
}
