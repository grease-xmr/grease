use crate::{B8, BABY_JUBJUB_ORDER, BABY_JUBJUB_PRIME, ED25519_ORDER};
use babyjubjub_rs::Point;
use curve25519_dalek::constants::X25519_BASEPOINT;
use curve25519_dalek::{MontgomeryPoint, Scalar};
use ff_ce::Field;
use libgrease::cryptography::zk_objects::GenericScalar;
use num_bigint::{BigInt, BigUint};
use num_traits::Euclid;
use poseidon_rs::Fr;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Deserializer, Serialize};
use std::path::Path;

pub fn init_public_to_hex<S>(bytes: &[u8; 1312], s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    hex::encode(*bytes).serialize(s)
}

pub fn init_public_from_hex<'de, D>(de: D) -> Result<[u8; 1312], D::Error>
where
    D: Deserializer<'de>,
{
    let hex_str = String::deserialize(de)?;
    if hex_str.is_empty() {
        return Err(serde::de::Error::custom("Hex string must not be empty"));
    }
    if hex_str.len() != 28160 {
        return Err(serde::de::Error::custom("Invalid hex string length for public"));
    }
    // Ensure the hex string can be decoded into a 1312-byte array
    if hex_str.len() % 2 != 0 {
        return Err(serde::de::Error::custom("Hex string must have an even length"));
    }
    // Create an array to hold the decoded bytes
    let mut result = [0u8; 1312];
    hex::decode_to_slice(hex_str, &mut result)
        .map_err(|e| serde::de::Error::custom(format!("Invalid hex string: {e}")))?;
    Ok(result)
}

pub fn update_public_to_hex<S>(bytes: &[u8; 1152], s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    hex::encode(*bytes).serialize(s)
}

pub fn update_public_from_hex<'de, D>(de: D) -> Result<[u8; 1152], D::Error>
where
    D: Deserializer<'de>,
{
    let hex_str = String::deserialize(de)?;
    if hex_str.is_empty() {
        return Err(serde::de::Error::custom("Hex string must not be empty"));
    }
    if hex_str.len() != 28160 {
        return Err(serde::de::Error::custom("Invalid hex string length for public"));
    }
    // Ensure the hex string can be decoded into a 1152-byte array
    if hex_str.len() % 2 != 0 {
        return Err(serde::de::Error::custom("Hex string must have an even length"));
    }
    // Create an array to hold the decoded bytes
    let mut result = [0u8; 1152];
    hex::decode_to_slice(hex_str, &mut result)
        .map_err(|e| serde::de::Error::custom(format!("Invalid hex string: {e}")))?;
    Ok(result)
}

pub fn proof_to_hex<S>(proof: &[u8; 14080], s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    hex::encode(*proof).serialize(s)
}

pub fn proof_from_hex<'de, D>(de: D) -> Result<Box<[u8; 14080]>, D::Error>
where
    D: Deserializer<'de>,
{
    let hex_str = String::deserialize(de)?;
    if hex_str.is_empty() {
        return Err(serde::de::Error::custom("Hex string must not be empty"));
    }
    if hex_str.len() != 28160 {
        return Err(serde::de::Error::custom("Invalid hex string length for proof"));
    }
    // Ensure the hex string can be decoded into a 14080-byte array
    if hex_str.len() % 2 != 0 {
        return Err(serde::de::Error::custom("Hex string must have an even length"));
    }
    // Create an array to hold the decoded bytes
    let mut result = [0u8; 14080];
    hex::decode_to_slice(hex_str, &mut result)
        .map_err(|e| serde::de::Error::custom(format!("Invalid hex string: {e}")))?;
    Ok(Box::new(result))
}

pub fn left_pad_bytes_32(input: &[u8]) -> Result<[u8; 32], String> {
    if input.len() > 32 {
        return Err("Input length exceeds target length".to_string());
    }

    let mut result = [0u8; 32];
    let offset = 32 - input.len();
    result[offset..].copy_from_slice(input);
    Ok(result)
}
pub(crate) fn left_pad_bytes_32_vec(input: &[u8]) -> [u8; 32] {
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
pub fn point_negate(point: Point) -> Point {
    // The negative of a point (x, y) on Baby Jubjub is (-x, y)
    let mut negative_x: Fr = *BABY_JUBJUB_PRIME;
    negative_x.sub_assign(&point.x);

    Point { x: negative_x, y: point.y }
}
pub fn get_field_bytes(field: &Fr) -> [u8; 32] {
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

    B8.mul_scalar(&scalar_i)
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
pub fn multiply_point_by_scalar_ed25519(point: &MontgomeryPoint, scalar_big_uint: &BigUint) -> MontgomeryPoint {
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
pub enum MontgomeryPointSigns {
    PP,
    PN,
    NP,
    NN,
}
pub fn subtract_montgomery_points(
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
pub fn byte_array_to_string_array(bytes: &[u8; 32]) -> [String; 32] {
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

pub fn make_keypair_bjj<R: CryptoRng + RngCore>(rng: &mut R) -> (BigUint, Point) {
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

pub fn load_vk<P: AsRef<Path>>(working_dir: P, vk_path: &str) -> Result<Vec<u8>, std::io::Error> {
    std::fs::read(working_dir.as_ref().join(vk_path).join("vk"))
}

pub fn big_int_to_generic(i: &BigUint) -> Result<GenericScalar, String> {
    let arr = i.to_bytes_le();
    if arr.len() > 32 {
        return Err("big_int_to_generic: input too large".to_string());
    };
    let mut result = [0u8; 32];
    result[0..arr.len()].copy_from_slice(&arr);
    Ok(GenericScalar::new(result))
}
