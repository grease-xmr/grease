use ciphersuite::group::ff::PrimeField;
use ciphersuite::group::GroupEncoding;
use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use dalek_ff_group::{EdwardsPoint, Scalar};
use monero_wallet::ringct::RctType;
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

pub fn keypair() -> (Zeroizing<Scalar>, EdwardsPoint) {
    let secret = Zeroizing::new(Scalar::random(&mut OsRng));
    let public = EdwardsPoint(ED25519_BASEPOINT_TABLE * &*secret);
    (secret, public)
}

pub fn random_key() -> [u8; 32] {
    let mut result = [0u8; 32];
    OsRng.fill_bytes(&mut result);
    result
}

pub fn scalar_as_hex(scalar: &Scalar) -> String {
    hex::encode(scalar.to_bytes())
}

pub fn point_as_hex(point: &EdwardsPoint) -> String {
    hex::encode(point.0.compress().as_bytes())
}

pub fn hex_to_point(hex: &str) -> Result<EdwardsPoint, String> {
    let mut repr = [0u8; 32];
    hex::decode_to_slice(hex, &mut repr).map_err(|e| format!("Hex decode failed: {}", e))?;
    let point: Option<EdwardsPoint> = EdwardsPoint::from_bytes(&repr).into();
    match point {
        Some(p) => Ok(p),
        None => Err("String does not decode into a valid point".to_string()),
    }
}

pub fn hex_to_scalar(hex: &str) -> Result<Scalar, String> {
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(hex, &mut bytes).map_err(|e| e.to_string())?;
    let decoded: Option<Scalar> = Scalar::from_canonical_bytes(bytes).into();
    match decoded {
        Some(scalar) => Ok(scalar),
        None => Err("string does not represent a canonical scalar".to_string()),
    }
}

pub fn ring_len(rct_type: RctType) -> usize {
    match rct_type {
        RctType::ClsagBulletproof => 11,
        RctType::ClsagBulletproofPlus => 16,
        _ => panic!("ring size unknown for RctType"),
    }
}

pub fn keys_from(s: &str) -> (Zeroizing<Scalar>, EdwardsPoint) {
    let bytes = hex::decode(s).unwrap();
    let mut repr = [0u8; 32];
    repr.copy_from_slice(&bytes[0..32]);
    let secret = Scalar::from_repr(repr).unwrap();
    let public = EdwardsPoint(ED25519_BASEPOINT_TABLE * &secret);
    (Zeroizing::new(secret), public)
}

pub fn scalar_from(s: &str) -> Scalar {
    let bytes = hex::decode(s).unwrap();
    let mut repr = [0u8; 32];
    repr.copy_from_slice(&bytes[0..32]);
    Scalar::from_repr(repr).unwrap()
}
