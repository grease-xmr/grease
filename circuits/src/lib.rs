use babyjubjub_rs::*;
use blake2::{Blake2s256, Digest};
use curve25519_dalek::montgomery::MontgomeryPoint;
use ff_ce::PrimeField;
use log::error;
use log::*;
use num_bigint::{BigInt, BigUint};
use num_traits::ops::euclid::Euclid;
use num_traits::Zero;
use poseidon_rs::Fr;
use serde::{Deserialize, Serialize};
use std::env;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use thiserror::Error;

pub mod helpers;
use helpers::*;

use lazy_static::lazy_static;
use libgrease::cryptography::zk_objects::{Comm0PrivateOutputs, Comm0PublicOutputs, GenericPoint, GenericScalar};

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

impl From<&str> for BBError {
    fn from(val: &str) -> Self {
        BBError::String(val.to_string())
    }
}

impl From<String> for BBError {
    fn from(value: std::string::String) -> Self {
        BBError::String(value)
    }
}

pub(crate) fn make_witness0(
    nonce_peer: &BigUint,
    blinding: &BigUint,
) -> Result<(BigUint, Point, MontgomeryPoint), BBError> {
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

//Encrypt to peer/KES
pub(crate) fn encrypt_message_ecdh(
    message: &BigUint,
    r: &BigUint,
    public_key: &Point,
    private_key: Option<&BigUint>,
) -> Result<(Point, BigUint), BBError> {
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
    public_key: &Point,
    fi: &Point,
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
pub(crate) fn make_vcof(witness_im1: &BigUint) -> Result<(BigUint, Point, MontgomeryPoint), BBError> {
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
) -> Result<([u8; 32], BigUint, BigUint, Point, MontgomeryPoint, BigUint, BigUint), BBError> {
    assert!(secret > &BigUint::from(0u8));
    assert!(*secret <= *BABY_JUBJUB_ORDER);
    assert!(blinding_dleq > &BigUint::from(0u8));
    assert!(*blinding_dleq <= *BABY_JUBJUB_ORDER);

    // Compute T = secret * G1 (Baby Jubjub)
    let t: Point = B8.mul_scalar(&secret.clone().into());

    let s: MontgomeryPoint = get_scalar_to_point_ed25519(secret);

    // Compute commitments: R1 = blinding_DLEQ * G1 (Baby Jubjub)
    let r1: Point = B8.mul_scalar(&blinding_dleq.clone().into());

    // Compute commitments: R2 = blinding_DLEQ * G2 (Ed25519)
    let r2: MontgomeryPoint = get_scalar_to_point_ed25519(blinding_dleq);

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
    t: &Point,
    s: &MontgomeryPoint,
    challenge_bytes: &[u8; 32],
    response_baby_jub_jub: &BigUint,
    response_ed25519: &BigUint,
    r1: &Point,
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
    let response_ed25519_g2: MontgomeryPoint = get_scalar_to_point_ed25519(response_ed25519);
    let challenge_ed25519: BigUint = challenge_bigint.rem_euclid(&ED25519_ORDER);
    let challenge_ed25519_s: MontgomeryPoint = multiply_point_by_scalar_ed25519(s, &challenge_ed25519);

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

    Ok(count_match > 0u8)
}

fn call_shell(program: &str, args: &[&str], working_dir: Option<PathBuf>) -> io::Result<(Vec<u8>, String)> {
    #[cfg(debug_assertions)]
    {
        // Validate command exists
        info!("Validating command '{}'", program);
        if !Command::new("which").arg(program).status()?.success() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("{} command not found", program),
            ));
        }
    }

    // Spawn the bash command with the provided arguments
    debug!(
        "Calling command '{}' in '{}' with args '{:?}'",
        program,
        env::current_dir()?.display(),
        args
    );
    let mut command = Command::new(program);
    let mut command = command.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());

    if let Some(working_dir) = working_dir {
        debug!("Setting working directory to '{}'", working_dir.display());
        command = command.current_dir(working_dir);
    }

    let mut command = command.spawn()?;

    // Get stdout and stderr handles
    let stdout = command.stdout.take().ok_or_else(|| io::Error::other("Failed to capture stdout"))?;
    let stderr = command.stderr.take().ok_or_else(|| io::Error::other("Failed to capture stderr"))?;

    debug!("Execution of {program} complete.");
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
            stderr_output.trim()
        );
        return Err(io::Error::other(format!("Script failed with status: {}", status,)));
    }

    Ok((stdout_output, stderr_output.trim().to_string()))
}

pub(crate) fn get_bb_version() -> Result<(u8, u8, u8), BBError> {
    //bb --version
    let args: Vec<&'static str> = vec!["--version"];
    match call_shell("bb", &args, None) {
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
    match call_shell("nargo", &args, None) {
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

#[expect(non_snake_case)]
#[derive(Serialize)]
struct InitConfig {
    blinding: String,
    blinding_DLEQ: String,
    challenge_bytes: [String; 32],
    enc_2: String,
    nonce_peer: String,
    r_2: String,
    response_div_BabyJubJub: [String; 32],
    response_div_ed25519: [String; 32],
    response_BabyJubJub: String,
    response_ed25519: [String; 32],
    witness_0: String,

    T_0: PointConfig,
    fi_2: PointConfig,
    pubkey_KES: PointConfig,
}

#[expect(non_snake_case)]
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
    pub public_input: [u8; 1184],
}

impl ZeroKnowledgeProofInitPublic {
    pub fn from_vec(public: Vec<u8>) -> Result<Self, BBError> {
        if public.len() != 1184 {
                        return Err(BBError::String("Invalid public input length".to_string()));
        }
        let public_input: [u8; 1184] =
            public.try_into().map_err(|_| BBError::String("Invalid public input length".to_string()))?;
        Ok(Self { public_input })
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.public_input.to_vec()
    }

    pub fn new(
        nonce_peer: &BigUint,
        t_0: &Point,
        kes_public_key: &Point,
        c: &BigUint,
    ) -> Result<Self, BBError> {
        let mut public_input = Vec::with_capacity(288 + (32 * 32));
        public_input.extend_from_slice(&left_pad_bytes_32(&nonce_peer.to_bytes_be())?);
        public_input.extend_from_slice(&get_field_bytes(&t_0.x));
        public_input.extend_from_slice(&get_field_bytes(&t_0.y));
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
        kes_public_key: &Point,
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
        let kes_public_key_x_bytes = get_field_bytes(&kes_public_key.x);
        if kes_public_key_x_bytes != p.public_input[96..128] {
            return Err(BBError::String("kes_public_key.x does not match".to_string()));
        }
        let kes_public_key_y_bytes = get_field_bytes(&kes_public_key.y);
        if kes_public_key_y_bytes != p.public_input[128..160] {
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
                let public_input_index = 160 + (i * 32);
                let public_input_index_until = public_input_index + 32;

                if BigUint::zero()
                    != BigUint::from_bytes_be(&p.public_input[public_input_index..public_input_index_until])
                {
                    return Err(BBError::String("challenge_bytes does not match".to_string()));
                }
            }
        }
        for i in leading_zeroes..32 {
            let public_input_index = 160 + (i * 32);
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
    pub public_input: ZeroKnowledgeProofInitPublic,
    #[serde(serialize_with = "crate::helpers::proof_to_hex", deserialize_with = "crate::helpers::proof_from_hex")]
    pub proof: Box<[u8; 14080]>,
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
    pub public_input: ZeroKnowledgeProofUpdatePublic,
    #[serde(serialize_with = "crate::helpers::proof_to_hex", deserialize_with = "crate::helpers::proof_from_hex")]
    pub proof: Box<[u8; 14080]>,
}

pub(crate) fn bb_prove_init(
    blinding: &BigUint,
    blinding_dleq: &BigUint,
    challenge_bytes: &[u8; 32],
    enc_2: &BigUint,
    nonce_peer: &BigUint,
    r_2: &BigUint,
    response_div_baby_jub_jub: &[u8; 32],
    response_div_ed25519: &[u8; 32],
    response_baby_jub_jub: &BigUint,
    response_ed25519: &[u8; 32],
    witness_0: &BigUint,

    t_0: &Point,
    fi_2: &Point,
    kes_public_key: &Point,
) -> Result<ZeroKnowledgeProofInit, BBError> {
    let config = InitConfig {
        blinding: blinding.to_string(),
        blinding_DLEQ: blinding_dleq.to_string(),
        challenge_bytes: byte_array_to_string_array(challenge_bytes),
        enc_2: enc_2.to_string(),
        nonce_peer: nonce_peer.to_string(),
        r_2: r_2.to_string(),
        response_div_BabyJubJub: byte_array_to_string_array(response_div_baby_jub_jub),
        response_div_ed25519: byte_array_to_string_array(response_div_ed25519),
        response_BabyJubJub: response_baby_jub_jub.to_string(),
        response_ed25519: byte_array_to_string_array(response_ed25519),
        witness_0: witness_0.to_string(),

        T_0: get_point_config_baby_jubjub(t_0),
        fi_2: get_point_config_baby_jubjub(fi_2),
        pubkey_KES: get_point_config_baby_jubjub(kes_public_key),
    };

    // Serialize to TOML string
    let toml_string = toml::to_string_pretty(&config).map_err(io::Error::other)?;

    let target_path = get_target_path();
    create_dir_if_not_exists(&target_path)?;
    let witness_config_path = target_path.join("Grease.toml");
    let witness_config_filename = format!("{}", witness_config_path.display());
    debug!("Writing witness config to {witness_config_filename}");
    std::fs::write(&witness_config_path, &toml_string)?;
    let output_path = format!("{}", target_path.join("Grease").display());
    //nargo execute
    let args: Vec<&str> = vec!["execute", "-p", &witness_config_filename, "--package", "Grease", &output_path];
    let nargo_path = get_noir_project_path();
    match call_shell("nargo", &args, Some(nargo_path.clone())) {
        Ok((stdout, _stderr)) => match str::from_utf8(&stdout) {
            Ok(v) => {
                println!("nargo output\n---\n{v}\n---")
            }
            Err(e) => return Err(format!("Invalid UTF-8 sequence: {}", e).into()),
        },
        Err(e) => {
            eprintln!("Error: {}", e);
            return Err(BBError::IoError(e));
        }
    };

    let witness_binary_file_path = target_path.join("Grease.gz").to_string_lossy().to_string();
    if !Path::new(&witness_binary_file_path).exists() {
        return Err(BBError::String(format!(
            "no witness_binary_file_path file for nargo PATH and ARGS: {:?}\t{:?}\t{:?}",
            witness_binary_file_path, nargo_path, args
        )));
    }

    // generate verification key
    debug!("Generating verification key");
    create_dir_if_not_exists(target_path.join("vk_init"))?;
    let vk_init_dir = target_path.join("vk_init").to_string_lossy().to_string();
    let grease_init_json_path = get_noir_project_path().join("target").join("Grease.json");
    let grease_init_json_filename = grease_init_json_path.to_string_lossy().to_string();
    let args = vec!["write_vk", "-b", &grease_init_json_filename, "-o", &vk_init_dir];
    match call_shell("bb", &args, None) {
        Ok((stdout, _stderr)) => {
            let output = str::from_utf8(&stdout).unwrap_or_default();
            println!("bb write_vk output:\n---\n{}\n---", output);
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            return Err(BBError::IoError(e));
        }
    };

    //bb prove
    debug!("Generating bb_init proof");
    match std::fs::create_dir(target_path.join("proof_init")) {
        Ok(_) => {}
        Err(e) => {
            if e.kind() != io::ErrorKind::AlreadyExists {
                return Err(BBError::IoError(e));
            }
        }
    }
    let proof_path = target_path.join("proof_init").to_string_lossy().to_string();
    let args: Vec<&str> =
        vec!["prove", "-b", &grease_init_json_filename, "-w", &witness_binary_file_path, "-o", &proof_path];
    match call_shell("bb", &args, None) {
        Ok((stdout, _stderr)) => {
            let output = str::from_utf8(&stdout).unwrap_or_default();
            println!("bb prove output:\n---\n{}\n---", output);
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            return Err(BBError::IoError(e));
        }
    };

    // Load proof and public input
    debug!("Retrieving proof");
    let proof = std::fs::read(target_path.join("proof_init").join("proof"))?;
    debug!("Retrieving public inputs");
    let public_input = std::fs::read(target_path.join("proof_init").join("public_inputs"))?;

    if proof.len() != 14080 {
        return Err(BBError::String("Invalid proof length".to_string()));
    }

    info!("Proofs generated successfully");
    Ok(ZeroKnowledgeProofInit {
        public_input: ZeroKnowledgeProofInitPublic::from_vec(public_input)?,
        proof: proof.try_into().map_err(|_| BBError::String("proof must be exactly 14080 bytes".to_string()))?,
    })
}

fn create_dir_if_not_exists(path: impl AsRef<Path>) -> Result<(), BBError> {
    match std::fs::create_dir(path) {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(BBError::IoError(e)),
    }
}

fn get_noir_project_path() -> PathBuf {
    env::var("NARGO_PATH").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from("./circuits"))
}

fn get_target_path() -> PathBuf {
    env::var("NARGO_TARGET_PATH").map(PathBuf::from).unwrap_or_else(|_| get_noir_project_path().join("./grease-proofs"))
}

pub(crate) fn bb_verify(proof: &[u8; 14080], public_inputs: &Vec<u8>, view_key_file: &str, verify_dir: &str) -> Result<bool, BBError> {
    // Create named temporary files
    let target_dir = get_target_path();
    let proof_file_path = target_dir.join(verify_dir).join("proof");
    let inputs_file_path = target_dir.join(verify_dir).join("public_inputs");
    let proof_file = proof_file_path.to_string_lossy().to_string();
    let inputs_file = inputs_file_path.to_string_lossy().to_string();

    // Write content to the temporary files
    std::fs::write(proof_file_path, *proof)?;
    std::fs::write(target_dir.join(verify_dir).join("public_inputs"), public_inputs)?;

    //nargo verify
    let args: Vec<&str> = vec!["verify", "-v", "-k", view_key_file, "-p", &proof_file, "-i", &inputs_file];
    let ret: Result<bool, BBError> = match call_shell("bb", &args, None) {
        Ok((_stdout, _stderr)) => Ok(true),
        Err(e) => {
            eprintln!("Error: {}", e);
            Err(e.into())
        }
    };

    ret
}

pub fn bb_verify_init(
    nonce_peer: &BigUint,
    kes_public_key: &Point,
    public_init: &PublicInit,
    verification_key: &[u8],
    zero_knowledge_proof_init: &ZeroKnowledgeProofInit,
) -> Result<bool, BBError> {
    ZeroKnowledgeProofInitPublic::check(
        &zero_knowledge_proof_init.public_input,
        &nonce_peer,
        &public_init.T_0,
        &kes_public_key,
        &public_init.c,
    )?;

    let target_path = get_target_path();

    let vk_key_file_path = target_path.join("vk_init").join("vk");
    create_dir_if_not_exists(&vk_key_file_path)?;
    std::fs::write(&vk_key_file_path, verification_key)?;

    let vk_key_filename = vk_key_file_path.to_string_lossy().to_string();

    let verify_dir = "verify_init";
    create_dir_if_not_exists(&target_path.join(verify_dir))?;

    let res = bb_verify(&zero_knowledge_proof_init.proof, &zero_knowledge_proof_init.public_input.public_input.to_vec(), &vk_key_filename, verify_dir)?;

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
) -> Result<ZeroKnowledgeProofUpdate, BBError> {
    let config = UpdateConfig {
        blinding_DLEQ: blinding_dleq.to_string(),
        challenge_bytes: byte_array_to_string_array(challenge_bytes),
        response_div_BabyJubJub: byte_array_to_string_array(response_div_baby_jub_jub),
        response_div_ed25519: byte_array_to_string_array(response_div_ed25519),
        response_BabyJubJub: response_baby_jub_jub.to_string(),
        response_ed25519: byte_array_to_string_array(response_ed25519),
        witness_i: witness_i.to_string(),
        witness_im1: witness_im1.to_string(),

        T_i: get_point_config_baby_jubjub(t_i),
        T_im1: get_point_config_baby_jubjub(t_im1),
    };

    // Serialize to TOML string
    let toml_string = toml::to_string_pretty(&config).map_err(io::Error::other)?;

    // hard-code this working directory and leave temp files in place until all the bugs have been ironed out.
    let target_path = get_target_path();
    create_dir_if_not_exists(&target_path)?;
    let witness_config_file = target_path.join("GreaseUpdate.toml");
    let witness_config_filename = witness_config_file.to_string_lossy().to_string();
    debug!("Writing witness config to {witness_config_filename}");
    std::fs::write(witness_config_file, toml_string)?;
    let output_path = format!("{}", target_path.join("GreaseUpdate").display());
    //nargo execute
    let args: Vec<&str> = vec!["execute", "-p", &witness_config_filename, "--package", "GreaseUpdate", &output_path];
    let nargo_path = get_noir_project_path();
    match call_shell("nargo", &args, Some(nargo_path.clone())) {
        Ok((stdout, _stderr)) => match str::from_utf8(&stdout) {
            Ok(v) => v.to_string(),
            Err(e) => return Err(format!("Invalid UTF-8 sequence: {}", e).into()),
        },
        Err(e) => {
            eprintln!("Error: {}", e);
            return Err(BBError::IoError(e));
        }
    };

    let witness_binary_file_path = target_path.join("GreaseUpdate.gz").to_string_lossy().to_string();
    if !Path::new(&witness_binary_file_path).exists() {
        return Err(BBError::String(format!(
            "no witness_binary_file_path file for nargo PATH and ARGS: {:?}\t{:?}\t{:?}",
            witness_binary_file_path, nargo_path, args
        )));
    }

    // generate verification key
    debug!("Generating verification key");
    create_dir_if_not_exists(target_path.join("vk_update"))?;
    let vk_update_dir = target_path.join("vk_update").to_string_lossy().to_string();
    let grease_init_json_path = get_noir_project_path().join("target").join("GreaseUpdate.json");
    let grease_init_json_filename = grease_init_json_path.to_string_lossy().to_string();
    let args = vec!["write_vk", "-b", &grease_init_json_filename, "-o", &vk_update_dir];

    match call_shell("bb", &args, None) {
        Ok((stdout, _stderr)) => {
            let output = str::from_utf8(&stdout).unwrap_or_default();
            println!("bb write_vk output:\n---\n{}\n---", output);
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            return Err(BBError::IoError(e));
        }
    };

    //bb prove
    let noir_path = get_noir_project_path();
    let grease_update_json_path = noir_path.join("target").join("GreaseUpdate.json").to_string_lossy().to_string();
    create_dir_if_not_exists(target_path.join("proof_update"))?;
    let grease_update_proof_path = target_path.join("proof_update").to_string_lossy().to_string();

    let args: Vec<&str> = vec![
        "prove",
        "-b",
        &grease_update_json_path,
        "-w",
        &witness_binary_file_path,
        "-v",
        "-o",
        &grease_update_proof_path,
    ];
    match call_shell("bb", &args, None) {
        Ok((stdout, _stderr)) => {
            println!("bb output:\n---\n{}\n---", str::from_utf8(&stdout).unwrap_or_default());
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            return Err(BBError::IoError(e));
        }
    };
    debug!("Loading proof");
    let proof = std::fs::read(target_path.join("proof_update").join("proof"))?;
    debug!("Loading public inputs");
    let public_input = std::fs::read(target_path.join("proof_update").join("public_inputs"))?;

    Ok(ZeroKnowledgeProofUpdate {
        public_input: ZeroKnowledgeProofUpdatePublic::from_vec(public_input)?,
        proof: proof.try_into().map_err(|_| BBError::String("proof must be exactly 14080 bytes".to_string()))?,
    })
}

/// The outputs of the Commitment0 proofs that must be shared with the peer.
#[expect(non_snake_case)]
#[derive(Debug, Clone)]
pub struct PublicInit {
    /// **Τ₀** - The public key/curve point on Baby Jubjub for ω₀.
    pub T_0: Point,
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

#[expect(non_snake_case)]
impl PublicInit {
    pub fn new(
        T_0: &Point,
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
            phi_2: phi_2.clone(),
            enc_2: enc_2.clone(),
            S_0: *S_0,
            c: challenge,
            rho_bjj: rho_bjj.clone(),
            rho_ed: rho_ed.clone(),
            R1: R1.clone(),
            R2: *R2,
        }
    }
}

/// Struct holding the public outputs from a ZK update proof.
#[expect(non_snake_case)]
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

#[expect(non_snake_case)]
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
            S_current: *S_current,
            challenge,
            rho_bjj: rho_bjj.clone(),
            rho_ed: rho_ed.clone(),
            R_bjj: R_bjj.clone(),
            R_ed: *R_ed,
        }
    }
}

pub fn bb_verify_update(
    public_update: &PublicUpdate,
    zk_proof_update: &ZeroKnowledgeProofUpdate,
    verification_key: &[u8],
) -> Result<bool, BBError> {
    ZeroKnowledgeProofUpdatePublic::check(
        &zk_proof_update.public_input,
        &public_update.T_prev,
        &public_update.T_current,
        &public_update.challenge,
    )?;

    let target_path = get_target_path();
    let vk_update_key_path = target_path.join("vk_update");
    create_dir_if_not_exists(&vk_update_key_path)?;
    std::fs::write(vk_update_key_path.join("vk"), verification_key)?;

    let vk_update_filename = vk_update_key_path.join("vk").to_string_lossy().to_string();

    let verify_dir = "verify_update";
    create_dir_if_not_exists(&target_path.join(verify_dir))?;

    let res = bb_verify(
        &zk_proof_update.proof,
        &zk_proof_update.public_input.to_vec(),
        &vk_update_filename,
        verify_dir,
    )?;

    Ok(res)
}

pub struct InitialProof {
    /// **Τ₀** - The public key/curve point on Baby Jubjub for ω₀.
    pub t_0: Point,
    /// **Φ₂** - The ephemeral public key/curve point on Baby Jubjub for message transportation to the KES.
    pub phi_2: Point,
    /// **χ₂** - The encrypted value of σ₂ (enc₂).
    pub enc_2: BigUint,
    /// **S₀** - The public key/curve point on Ed25519 for ω₀.
    pub s_0: MontgomeryPoint,
    /// **ρ_BabyJubjub** - The Fiat–Shamir heuristic challenge response on the Baby Jubjub curve (response_BabyJubJub).
    pub rho_bjj: BigUint,
    /// **ρ_Ed25519** - The Fiat–Shamir heuristic challenge response on the Ed25519 curve (response_div_ed25519).
    pub rho_ed: BigUint,
    /// **R_BabyJubjub** - The ... on the Baby Jubjub curve (R1).
    pub r1: Point,
    /// **R_Ed25519** - The ... on the Ed25519 curve (R2).
    pub r2: MontgomeryPoint,

    pub challenge_bytes: [u8; 32],
    pub witness_0: BigUint,
    pub response_div_baby_jub_jub: [u8; 32],
    pub response_div_ed25519: [u8; 32],
    pub zero_knowledge_proof_init: ZeroKnowledgeProofInit,
}

impl InitialProof {
    pub fn as_public_outputs(&self) -> Comm0PublicOutputs {
        Comm0PublicOutputs {
            T_0: GenericPoint::new(self.t_0.compress()),
            phi_2: GenericPoint::new(self.phi_2.compress()),
            enc_2: big_int_to_generic(&self.enc_2).unwrap(),
            S_0: GenericPoint::new(self.s_0.to_bytes()),
            c: GenericScalar::new(self.challenge_bytes),
            rho_bjj: big_int_to_generic(&self.rho_bjj).unwrap(),
            rho_ed: big_int_to_generic(&self.rho_ed).unwrap(),
        }
    }

    pub fn as_private_outputs(&self) -> Comm0PrivateOutputs {
        Comm0PrivateOutputs {
            witness_0: big_int_to_generic(&self.witness_0).unwrap(),
            delta_bjj: GenericScalar::new(self.response_div_baby_jub_jub),
            delta_ed: GenericScalar::new(self.response_div_ed25519),
        }
    }
}

/// Generates initial proofs for the circuit.
pub fn generate_initial_proofs(
    nonce_peer: &BigUint,
    blinding: &BigUint,
    r_2: &BigUint,
    kes_public_key: &Point,
    blinding_dleq: &BigUint,
) -> Result<InitialProof, BBError> {
    let (major, minor, build) = get_bb_version()?;
    info!("`bb` version: {}.{}.{}", major, minor, build);

    let nargo_version = get_nargo_version()?;
    info!("`nargo` version: {}", nargo_version);

    let (witness_0, t_0, s_0) = make_witness0(nonce_peer, blinding)?;

    let (fi_2, enc_2) = encrypt_message_ecdh(&witness_0, r_2, kes_public_key, None)?;

    //NIZK DLEQ
    let (
        challenge_bytes,
        response_baby_jub_jub,
        response_ed25519,
        r1,
        r2,
        response_div_baby_jub_jub,
        response_div_ed25519,
    ) = generate_dleqproof_simple(&witness_0, blinding_dleq)?;

    //Verify
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
        Ok(verified) if verified => info!("DLEQ verified"),
        Ok(_) => {
            info!("DLEQ failed to verify!");
            return Err(BBError::DLEQVerify);
        }
        Err(e) => {
            info!("DLEQ failed to verify with error: {e}");
            return Err(e);
        }
    };

    //Prove
    let zero_knowledge_proof_init = bb_prove_init(
        blinding,
        blinding_dleq,
        &challenge_bytes,
        &enc_2,
        nonce_peer,
        r_2,
        &left_pad_bytes_32_vec(&response_div_baby_jub_jub.to_bytes_be()),
        &left_pad_bytes_32_vec(&response_div_ed25519.to_bytes_be()),
        &response_baby_jub_jub,
        &left_pad_bytes_32_vec(&response_ed25519.to_bytes_be()),
        &witness_0,
        &t_0,
        &fi_2,
        kes_public_key,
    )?;

    //Verify
    let public_init = PublicInit::new(
        &t_0,
        &fi_2,
        &enc_2,
        &s_0,
        &challenge_bytes,
        &response_baby_jub_jub,
        &response_ed25519,
        &r1,
        &r2,
    );

    let verification_key = load_vk(get_target_path(), "vk_init")?;

    let verification = bb_verify_init(
        nonce_peer,
        kes_public_key,
        &public_init,
        &verification_key,
        &zero_knowledge_proof_init,
    )?;
    if !verification {
        return Err(BBError::SelfVerify);
    }

    Ok(InitialProof {
        t_0,
        phi_2: fi_2,
        enc_2,
        s_0,
        rho_bjj: response_baby_jub_jub,
        rho_ed: response_ed25519,
        r1,
        r2,

        challenge_bytes,
        witness_0,
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

pub fn generate_update(witness_im1: &BigUint, blinding_dleq: &BigUint, t_im1: &Point) -> Result<UpdateProof, BBError> {
    let (witness_i, t_i, s_i) = make_vcof(witness_im1)?;

    //NIZK DLEQ
    let (
        challenge_bytes,
        response_baby_jub_jub,
        response_ed25519,
        r1,
        r2,
        response_div_baby_jub_jub,
        response_div_ed25519,
    ) = generate_dleqproof_simple(&witness_i, blinding_dleq)?;

    //Verify
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

    //Prove
    let zero_knowledge_proof_update = bb_prove_update(
        blinding_dleq,
        &challenge_bytes,
        &left_pad_bytes_32_vec(&response_div_baby_jub_jub.to_bytes_be()),
        &left_pad_bytes_32_vec(&response_div_ed25519.to_bytes_be()),
        &response_baby_jub_jub,
        &left_pad_bytes_32_vec(&response_ed25519.to_bytes_be()),
        &witness_i,
        witness_im1,
        &t_i,
        t_im1,
    )?;

    //Verify
    let public_update = PublicUpdate::new(
        t_im1,
        &t_i,
        &s_i,
        &challenge_bytes,
        &response_div_baby_jub_jub,
        &response_div_ed25519,
        &r1,
        &r2,
    );

    let verification_key = load_vk("grease_proofs", "vk_update")?;
    let verification = bb_verify_update(&public_update, &zero_knowledge_proof_update, &verification_key)?;
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
    use super::*;
    use num_bigint::BigUint;
    use serial_test::serial;

    #[test]
    fn test_generate_dleqproof_simple() {
        let mut rng = &mut rand::rng();

        for _i in 0..100 {
            let nonce_peer = make_scalar_bjj(rng);
            let blinding = make_scalar_bjj(rng);

            let (witness_i, t_i, s_i) = make_witness0(&nonce_peer, &blinding).unwrap();

            let blinding_dleq: BigUint = make_scalar_bjj(&mut rng);
            let (
                challenge_bytes,
                response_baby_jub_jub,
                response_ed25519,
                r1,
                r2,
                _response_div_baby_jub_jub,
                _response_div_ed25519,
            ) = generate_dleqproof_simple(&witness_i, &blinding_dleq).unwrap();

            let res = verify_dleq_simple(
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
            let nonce_peer_i = make_scalar_bjj(rng);
            let blinding_i = make_scalar_bjj(rng);

            let (witness_i, t_i, s_i) = make_witness0(&nonce_peer_i, &blinding_i).unwrap();

            let blinding_dleq_i: BigUint = make_scalar_bjj(&mut rng);
            let (
                challenge_bytes_i,
                response_baby_jub_jub_i,
                response_ed25519_i,
                r1_i,
                r2_i,
                _response_div_baby_jub_jub,
                _response_div_ed25519,
            ) = generate_dleqproof_simple(&witness_i, &blinding_dleq_i).unwrap();

            let nonce_peer_j = make_scalar_bjj(rng);
            let blinding_j = make_scalar_bjj(rng);

            let (witness_j, t_j, s_j) = make_witness0(&nonce_peer_j, &blinding_j).unwrap();

            let blinding_dleq_j: BigUint = make_scalar_bjj(&mut rng);
            let (
                challenge_bytes_j,
                response_baby_jub_jub_j,
                response_ed25519_j,
                r1_j,
                r2_j,
                _response_div_baby_jub_jub,
                _response_div_ed25519,
            ) = generate_dleqproof_simple(&witness_j, &blinding_dleq_j).unwrap();

            let res = verify_dleq_simple(
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

            let res = verify_dleq_simple(
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

            let res = verify_dleq_simple(
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

            let res = verify_dleq_simple(
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

            let res = verify_dleq_simple(
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

            let res = verify_dleq_simple(
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

            let res = verify_dleq_simple(
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
    #[serial]
    fn test_bb_prove_init() {
        env_logger::try_init().ok();

        let rng = &mut rand::rng();

        let nonce_peer: BigUint = make_scalar_bjj(rng);
        let blinding = make_scalar_bjj(rng);

        let (witness_0, t_0, s_0) = make_witness0(&nonce_peer, &blinding).unwrap();

        let r_2 = make_scalar_bjj(rng);
        let (_, kes_public_key) = make_keypair_bjj(rng);
        let (fi_2, enc_2) = encrypt_message_ecdh(&witness_0, &r_2, &kes_public_key, None).unwrap();

        let blinding_dleq = make_scalar_bjj(rng);

        let (
            challenge_bytes,
            response_baby_jub_jub,
            response_ed25519,
            r1,
            r2,
            response_div_baby_jub_jub,
            response_div_ed25519,
        ) = generate_dleqproof_simple(&witness_0, &blinding_dleq).unwrap();

        let zero_knowledge_proof_init = bb_prove_init(
            &blinding,
            &blinding_dleq,
            &challenge_bytes,
            &enc_2,
            &nonce_peer,
            &r_2,
            &left_pad_bytes_32_vec(&response_div_baby_jub_jub.to_bytes_be()),
            &left_pad_bytes_32_vec(&response_div_ed25519.to_bytes_be()),
            &response_baby_jub_jub,
            &left_pad_bytes_32_vec(&response_ed25519.to_bytes_be()),
            &witness_0,
            &t_0,
            &fi_2,
            &kes_public_key,
        )
        .unwrap();

        //Verify
        let public_init = PublicInit::new(
            &t_0,
            &fi_2,
            &enc_2,
            &s_0,
            &challenge_bytes,
            &response_baby_jub_jub,
            &response_ed25519,
            &r1,
            &r2,
        );

        let verification_key = load_vk(get_target_path(), "vk_init").unwrap();

        let verification = bb_verify_init(
            &nonce_peer,
            &kes_public_key,
            &public_init,
            &verification_key,
            &zero_knowledge_proof_init,
        )
        .unwrap();
        assert!(verification);
    }

    #[test]
    #[serial]
    fn test_bb_prove_update() {
        env_logger::try_init().ok();

        let mut rng = &mut rand::rng();

        let nonce_peer = make_scalar_bjj(rng);
        let blinding = make_scalar_bjj(rng);

        let (witness_im1, t_im1, _) = make_witness0(&nonce_peer, &blinding).unwrap();
        let (witness_i, t_i, s_i) = make_vcof(&witness_im1).unwrap();

        let blinding_dleq: BigUint = make_scalar_bjj(&mut rng);
        let (
            challenge_bytes,
            response_baby_jub_jub,
            response_ed25519,
            r1,
            r2,
            response_div_baby_jub_jub,
            response_div_ed25519,
        ) = generate_dleqproof_simple(&witness_i, &blinding_dleq).unwrap();

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
        )
        .unwrap();

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

        let vk = load_vk(get_target_path(), "vk_update").unwrap();
        let verification = bb_verify_update(&public_update, &zero_knowledge_proof_update, &vk).unwrap();
        assert!(verification);
    }

    #[test]
    #[serial]
    fn test_demo() {
        env_logger::try_init().ok();

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

        let (fi_2, enc_2) = encrypt_message_ecdh(&witness_0, &r_2, &kes_public_key, Some(&private_key_kes)).unwrap();

        assert_eq!(
            fi_2.x.to_string(),
            "Fr(0x0ac31edd3af81f177137239a950c8f70662c4b6fbbeec57dae63bfcb61d931ee)"
        );
        assert_eq!(
            fi_2.y.to_string(),
            "Fr(0x1975e7e9cbe0f2ed7a06a09e320036ea1a73862ee2614d2a9a6452d8f7c9aff0)"
        );

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
            &blinding,
            &blinding_dleq,
            &challenge_bytes_init,
            &enc_2,
            &nonce_peer,
            &r_2,
            &left_pad_bytes_32_vec(&response_div_baby_jub_jub.to_bytes_be()),
            &left_pad_bytes_32_vec(&response_div_ed25519.to_bytes_be()),
            &response_baby_jub_jub,
            &left_pad_bytes_32_vec(&response_ed25519.to_bytes_be()),
            &witness_0,
            &t_0,
            &fi_2,
            &kes_public_key,
        )
        .unwrap();

        //Verify
        let public_init = PublicInit::new(
            &t_0,
            &fi_2,
            &enc_2,
            &s_0,
            &challenge_bytes_init,
            &response_baby_jub_jub,
            &response_ed25519,
            &r1,
            &r2,
        );

        let verification_key = load_vk(get_target_path(), "vk_init").unwrap();

        let verification = bb_verify_init(
            &nonce_peer,
            &kes_public_key,
            &public_init,
            &verification_key,
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
        )
        .unwrap();

        //Verify
        let public_update = PublicUpdate::new(
            &t_0,
            &t_1,
            &s_1,
            &challenge_bytes_update,
            &response_div_baby_jub_jub_update,
            &response_div_ed25519_update,
            &r1_update,
            &r2_update,
        );

        let vk = load_vk(get_target_path(), "vk_update").unwrap();

        let verification = bb_verify_update(&public_update, &zero_knowledge_proof_update, &vk).unwrap();
        assert!(verification);

        println!("Success!");
    }
}
