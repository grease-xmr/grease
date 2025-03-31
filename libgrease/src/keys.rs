use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::{EdwardsPoint, Scalar};
use rand::{CryptoRng, RngCore};
use thiserror::Error;

pub struct SecretKey(Scalar);

impl SecretKey {
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

impl From<Scalar> for SecretKey {
    fn from(value: Scalar) -> Self {
        Self(value)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey {
    compressed_point: CompressedEdwardsY,
    point: EdwardsPoint,
}

impl PublicKey {
    pub fn keypair<R: CryptoRng + RngCore>(rng: &mut R) -> (SecretKey, Self) {
        let secret_key = SecretKey::random(rng);
        let public_key = Self::from_secret(&secret_key);
        (secret_key, public_key)
    }

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
