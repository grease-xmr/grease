use crate::crypto::traits::{PublicKey, SecretKey};
use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::{EdwardsPoint, Scalar};
use rand::{CryptoRng, RngCore};
use thiserror::Error;

#[derive(Clone, PartialEq, Eq)]
pub struct Curve25519Secret(Scalar);

impl Curve25519Secret {
    pub fn as_scalar(&self) -> &Scalar {
        &self.0
    }
    pub fn to_scalar(self) -> Scalar {
        self.0
    }
    pub fn random<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        let mut scalar_bytes = [0u8; 64];
        rng.fill_bytes(&mut scalar_bytes);
        let s = Scalar::from_bytes_mod_order_wide(&scalar_bytes);
        Self(s)
    }
}

impl SecretKey for Curve25519Secret {}

impl From<Scalar> for Curve25519Secret {
    fn from(value: Scalar) -> Self {
        Self(value)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Curve25519PublicKey {
    compressed_point: CompressedEdwardsY,
    point: EdwardsPoint,
}

impl Curve25519PublicKey {
    pub fn as_compressed(&self) -> &CompressedEdwardsY {
        &self.compressed_point
    }

    pub fn as_point(&self) -> &EdwardsPoint {
        &self.point
    }
}

impl From<EdwardsPoint> for Curve25519PublicKey {
    fn from(value: EdwardsPoint) -> Self {
        let compressed_point = value.compress();
        Self { compressed_point, point: value }
    }
}

impl TryFrom<CompressedEdwardsY> for Curve25519PublicKey {
    type Error = KeyError;
    fn try_from(value: CompressedEdwardsY) -> Result<Self, Self::Error> {
        let point = value.decompress().ok_or(KeyError::InvalidPoint)?;
        Ok(Self { compressed_point: value, point })
    }
}

impl PublicKey for Curve25519PublicKey {
    type SecretKey = Curve25519Secret;

    fn keypair<R: CryptoRng + RngCore>(rng: &mut R) -> (Curve25519Secret, Self) {
        let secret_key = Curve25519Secret::random(rng);
        let public_key = Self::from_secret(&secret_key);
        (secret_key, public_key)
    }

    fn from_secret(secret_key: &Self::SecretKey) -> Self {
        let point = secret_key.as_scalar() * ED25519_BASEPOINT_TABLE;
        point.into()
    }
}

#[derive(Debug, Error)]
pub enum KeyError {
    #[error("Invalid point on curve")]
    InvalidPoint,
}
