use crate::{
    PROOF_SIZE_INIT, PROOF_SIZE_INIT_HEX, PROOF_SIZE_UPDATE, PROOF_SIZE_UPDATE_HEX, PUBLIC_INPUT_SIZE_INIT,
    PUBLIC_INPUT_SIZE_UPDATE,
};
use ark_bn254::Fr;
use curve25519_dalek::constants::X25519_BASEPOINT;
use curve25519_dalek::{MontgomeryPoint, Scalar as MontgomeryScalar};
use elliptic_curve::group::GroupEncoding;
use elliptic_curve::rand_core::RngCore;
use elliptic_curve::Field as ECField;
use grease_babyjubjub::SUBORDER_BJJ;
use grease_babyjubjub::{BjjPoint, Fq, Point, Scalar};
use libgrease::cryptography::zk_objects::GenericScalar;
use num_bigint::BigUint;
use num_traits::{Euclid, Num};
use rand::CryptoRng;
use rand_core::CryptoRngCore;
use serde::{Deserialize, Deserializer, Serialize};
use std::ops::{Mul, Neg};
use std::path::Path;
use std::str::FromStr;

pub(crate) fn init_public_to_hex<S>(bytes: &[u8; PUBLIC_INPUT_SIZE_INIT], s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    hex::encode(*bytes).serialize(s)
}

pub(crate) fn init_public_from_hex<'de, D>(de: D) -> Result<[u8; PUBLIC_INPUT_SIZE_INIT], D::Error>
where
    D: Deserializer<'de>,
{
    let hex_str = String::deserialize(de)?;
    if hex_str.is_empty() {
        return Err(serde::de::Error::custom("Hex string must not be empty"));
    }
    if hex_str.len() != PROOF_SIZE_INIT_HEX {
        return Err(serde::de::Error::custom("Invalid hex string length for public"));
    }
    // Ensure the hex string can be decoded into a PUBLIC_INPUT_SIZE_INIT-byte array
    if hex_str.len() % 2 != 0 {
        return Err(serde::de::Error::custom("Hex string must have an even length"));
    }
    // Create an array to hold the decoded bytes
    let mut result = [0u8; PUBLIC_INPUT_SIZE_INIT];
    hex::decode_to_slice(hex_str, &mut result)
        .map_err(|e| serde::de::Error::custom(format!("Invalid hex string: {e}")))?;
    Ok(result)
}

pub(crate) fn update_public_to_hex<S>(bytes: &[u8; PUBLIC_INPUT_SIZE_UPDATE], s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    hex::encode(*bytes).serialize(s)
}

pub(crate) fn update_public_from_hex<'de, D>(de: D) -> Result<[u8; PUBLIC_INPUT_SIZE_UPDATE], D::Error>
where
    D: Deserializer<'de>,
{
    let hex_str = String::deserialize(de)?;
    if hex_str.is_empty() {
        return Err(serde::de::Error::custom("Hex string must not be empty"));
    }
    if hex_str.len() != PROOF_SIZE_UPDATE {
        return Err(serde::de::Error::custom("Invalid hex string length for public"));
    }
    // Ensure the hex string can be decoded into a PUBLIC_INPUT_SIZE_UPDATE-byte array
    if hex_str.len() % 2 != 0 {
        return Err(serde::de::Error::custom("Hex string must have an even length"));
    }
    // Create an array to hold the decoded bytes
    let mut result = [0u8; PUBLIC_INPUT_SIZE_UPDATE];
    hex::decode_to_slice(hex_str, &mut result)
        .map_err(|e| serde::de::Error::custom(format!("Invalid hex string: {e}")))?;
    Ok(result)
}

pub(crate) fn init_proof_to_hex<S>(proof: &[u8; PROOF_SIZE_INIT], s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    hex::encode(*proof).serialize(s)
}

pub(crate) fn update_proof_to_hex<S>(proof: &[u8; PROOF_SIZE_UPDATE], s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    hex::encode(*proof).serialize(s)
}

pub(crate) fn init_proof_from_hex<'de, D>(de: D) -> Result<Box<[u8; PROOF_SIZE_INIT]>, D::Error>
where
    D: Deserializer<'de>,
{
    let hex_str = String::deserialize(de)?;
    if hex_str.is_empty() {
        return Err(serde::de::Error::custom("Hex string must not be empty"));
    }
    if hex_str.len() != PROOF_SIZE_INIT_HEX {
        return Err(serde::de::Error::custom("Invalid hex string length for proof"));
    }
    // Ensure the hex string can be decoded into a PROOF_SIZE_INIT-byte array
    if hex_str.len() % 2 != 0 {
        return Err(serde::de::Error::custom("Hex string must have an even length"));
    }
    // Create an array to hold the decoded bytes
    let mut result = [0u8; PROOF_SIZE_INIT];
    hex::decode_to_slice(hex_str, &mut result)
        .map_err(|e| serde::de::Error::custom(format!("Invalid hex string: {e}")))?;
    Ok(Box::new(result))
}

pub(crate) fn update_proof_from_hex<'de, D>(de: D) -> Result<Box<[u8; PROOF_SIZE_UPDATE]>, D::Error>
where
    D: Deserializer<'de>,
{
    let hex_str = String::deserialize(de)?;
    if hex_str.is_empty() {
        return Err(serde::de::Error::custom("Hex string must not be empty"));
    }
    if hex_str.len() != PROOF_SIZE_UPDATE_HEX {
        return Err(serde::de::Error::custom("Invalid hex string length for proof"));
    }
    // Ensure the hex string can be decoded into a PROOF_SIZE_UPDATE-byte array
    if hex_str.len() % 2 != 0 {
        return Err(serde::de::Error::custom("Hex string must have an even length"));
    }
    // Create an array to hold the decoded bytes
    let mut result = [0u8; PROOF_SIZE_UPDATE];
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
pub(crate) fn right_pad_bytes_32(input: &[u8]) -> [u8; 32] {
    assert!(input.len() <= 32, "Input length exceeds target length");

    let mut result = [0u8; 32];
    result[..input.len()].copy_from_slice(input);
    result
}
pub(crate) fn point_negate(point: Point) -> Point {
    point.neg()
}

pub(crate) fn point_to_bytes(point: &Point) -> [u8; 32] {
    (BjjPoint::from(point.clone())).to_bytes()
}

pub(crate) fn get_big_uint_from_fr(field: &ark_bn254::Fr) -> BigUint {
    let field_object: String = field.to_string();
    assert!(
        field_object.len() <= 77,
        "get_field_bytes: field is not correctly self-describing"
    ); //TODO: Confirm this is correct for MAX(Fr) in BJJ

    BigUint::from_str_radix(&field_object, 10).unwrap()
}

pub(crate) fn get_fr_from_big_uint(field: &BigUint) -> Fr {
    Fr::from_str(&field.to_str_radix(10)).unwrap()
}

// pub(crate) fn get_field_bytes_fr(field: &Fr) -> [u8; 32] {
//     let field_object: String = field.to_string();
//     assert!(
//         field_object.len() <= 77,
//         "get_field_bytes: field is not correctly self-describing"
//     ); //TODO: Confirm this is correct for MAX(Fr) in BJJ

//     BigUint::from_str_radix(&field_object, 10).unwrap().to_bytes_be().try_into().unwrap_or([0u8; 32])
// }
pub(crate) fn get_field_bytes(field: &Fq) -> [u8; 32] {
    let field_object: String = field.to_string();
    assert!(
        field_object.len() <= 77,
        "get_field_bytes: field is not correctly self-describing"
    ); //TODO: Confirm this is correct for MAX(Fq) in BJJ

    BigUint::from_str_radix(&field_object, 10).unwrap().to_bytes_be().try_into().unwrap_or([0u8; 32])
}
pub(crate) fn get_fr_from_fq(field: &Fq) -> Fr {
    let field_object: String = field.to_string();
    assert!(
        field_object.len() <= 77,
        "get_field_bytes: field is not correctly self-describing"
    ); //TODO: Confirm this is correct for MAX(Fq) in BJJ

    Fr::from_str(&field_object).unwrap()
}

pub(crate) fn get_scalar_to_point_bjj(scalar: &BigUint) -> Point {
    let bjj_gen = grease_babyjubjub::generators();
    bjj_gen[0].mul(Scalar::from(scalar)).into()
}
pub(crate) fn get_scalar_to_point_ed25519(scalar_big_uint: &BigUint) -> MontgomeryPoint {
    // Convert the 32-byte array to an Ed25519 Scalar
    let scalar_bytes_be = scalar_big_uint.to_bytes_be();
    let mut scalar_bytes_le = scalar_bytes_be.clone();
    scalar_bytes_le.reverse();
    let scalar_byte_array_le = right_pad_bytes_32(&scalar_bytes_le);
    let scalar = MontgomeryScalar::from_bytes_mod_order(scalar_byte_array_le);
    // Multiply the scalar by the Curve25519 base point to get a curve point
    let point: MontgomeryPoint = scalar * X25519_BASEPOINT;
    point
}
pub(crate) fn multiply_point_by_scalar_ed25519(point: &MontgomeryPoint, scalar_big_uint: &BigUint) -> MontgomeryPoint {
    // Convert the 32-byte array to an Ed25519 Scalar
    let scalar_bytes_be = scalar_big_uint.to_bytes_be();
    let mut scalar_bytes_le = scalar_bytes_be.clone();
    scalar_bytes_le.reverse();
    let scalar_byte_array_le = right_pad_bytes_32(&scalar_bytes_le);
    let scalar = MontgomeryScalar::from_bytes_mod_order(scalar_byte_array_le);
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
pub(crate) fn subtract_montgomery_points(
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

pub(crate) fn make_scalar_bjj<R: CryptoRng + RngCore>(rng: &mut R) -> BigUint {
    Scalar::random(rng).into()
}

pub(crate) fn make_keypair_bjj<R: CryptoRng + RngCore>(rng: &mut R) -> (BigUint, Point) {
    let secret_key = Scalar::random(rng);
    let bjj_gen = grease_babyjubjub::generators();

    (secret_key.into(), bjj_gen[0].mul(secret_key).into())
}

pub(crate) fn make_scalar_ed25519<R: CryptoRngCore + ?Sized>(rng: &mut R) -> BigUint {
    let scalar = MontgomeryScalar::random(rng);
    BigUint::from_bytes_le(&scalar.to_bytes())
}

pub(crate) fn make_keypair_ed25519<R: CryptoRngCore + ?Sized>(rng: &mut R) -> (BigUint, MontgomeryPoint) {
    let secret_key: MontgomeryScalar = MontgomeryScalar::random(rng);
    let public_key: MontgomeryPoint = secret_key * X25519_BASEPOINT;

    (BigUint::from_bytes_le(&secret_key.to_bytes()), public_key)
}

pub(crate) fn make_keypair_ed25519_bjj_order<R: CryptoRngCore + ?Sized>(rng: &mut R) -> (BigUint, MontgomeryPoint) {
    let secret_key: MontgomeryScalar = MontgomeryScalar::random(rng);
    let secret_key = BigUint::from_bytes_le(&secret_key.to_bytes()).rem_euclid(&SUBORDER_BJJ.into());
    let secret_key_scalar: MontgomeryScalar =
        MontgomeryScalar::from_bytes_mod_order(right_pad_bytes_32(&secret_key.to_bytes_le()));

    let public_key: MontgomeryPoint = secret_key_scalar * X25519_BASEPOINT;

    (secret_key, public_key)
}

pub(crate) fn load_vk<P: AsRef<Path>>(working_dir: P, vk_path: &str) -> Result<Vec<u8>, std::io::Error> {
    std::fs::read(working_dir.as_ref().join(vk_path).join("vk"))
}

pub(crate) fn big_int_to_generic(i: &BigUint) -> Result<GenericScalar, String> {
    let arr = i.to_bytes_le();
    if arr.len() > 32 {
        return Err("big_int_to_generic: input too large".to_string());
    };
    let mut result = [0u8; 32];
    result[0..arr.len()].copy_from_slice(&arr);
    Ok(GenericScalar::new(result))
}
