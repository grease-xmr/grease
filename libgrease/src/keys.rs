use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::{EdwardsPoint, Scalar};
use thiserror::Error;

pub struct SecretKey(Scalar);

impl SecretKey {
    pub fn as_scalar(&self) -> &Scalar {
        &self.0
    }
}

impl From<Scalar> for SecretKey {
    fn from(value: Scalar) -> Self {
        Self(value)
    }
}

pub struct PublicKey {
    compressed_point: CompressedEdwardsY,
    point: EdwardsPoint,
}

impl PublicKey {
    pub fn from_secret(secret_key: &SecretKey) -> Self {
        let point = secret_key.as_scalar() * ED25519_BASEPOINT_TABLE;
        point.into()
    }

    pub fn as_compressed(&self) -> &CompressedEdwardsY {
        &self.compressed_point
    }

    pub fn as_point(&self) -> &EdwardsPoint {
        &self.point
    }
}

impl From<EdwardsPoint> for PublicKey {
    fn from(value: EdwardsPoint) -> Self {
        let compressed_point = value.compress();
        Self { compressed_point, point: value }
    }
}

impl TryFrom<CompressedEdwardsY> for PublicKey {
    type Error = KeyError;
    fn try_from(value: CompressedEdwardsY) -> Result<Self, Self::Error> {
        let point = value.decompress().ok_or(KeyError::InvalidPoint)?;
        Ok(Self { compressed_point: value, point })
    }
}

#[derive(Debug, Error)]
pub enum KeyError {
    #[error("Invalid point on curve")]
    InvalidPoint,
}
