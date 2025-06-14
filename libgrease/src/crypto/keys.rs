use crate::crypto::zk_objects::{GenericScalar};
use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::{EdwardsPoint, Scalar};
use hex::FromHexError;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use thiserror::Error;
use zeroize::Zeroizing;

pub trait SecretKey: Clone + Send + Sync + Serialize + for<'de> Deserialize<'de> {}

pub trait PublicKey: Clone + PartialEq + Eq + Send + Sync + Serialize + for<'de> Deserialize<'de> {
    type SecretKey: SecretKey + Debug;

    fn keypair<R: CryptoRng + RngCore>(rng: &mut R) -> (Self::SecretKey, Self);
    fn from_secret(secret_key: &Self::SecretKey) -> Self;
}

#[derive(Clone, PartialEq, Eq)]
pub struct Curve25519Secret(Zeroizing<Scalar>);

impl Curve25519Secret {
    pub fn as_scalar(&self) -> &Scalar {
        &self.0
    }

    pub fn as_zscalar(&self) -> &Zeroizing<Scalar> {
        &self.0
    }

    pub fn to_scalar(self) -> Zeroizing<Scalar> {
        self.0
    }
    pub fn random<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        let mut scalar_bytes = [0u8; 64];
        rng.fill_bytes(&mut scalar_bytes);
        let s = Zeroizing::new(Scalar::from_bytes_mod_order_wide(&scalar_bytes));
        Self(s)
    }

    pub fn from_hex(hex: &str) -> Result<Self, KeyError> {
        if hex.len() != 64 {
            return Err(KeyError::InvalidStringLength);
        }
        let mut canonical = [0u8; 32];
        hex::decode_to_slice(hex.as_bytes(), &mut canonical)?;
        match Scalar::from_canonical_bytes(canonical).into_option() {
            None => Err(KeyError::NonCanonicalScalar),
            Some(scalar) => Ok(Self::from(scalar)),
        }
    }

    pub fn as_hex(&self) -> String {
        hex::encode(self.0.to_bytes())
    }

    pub fn from_generic_scalar(generic: &GenericScalar) -> Result<Self, KeyError> {
        let scalar = Scalar::from_canonical_bytes(generic.0).into_option().ok_or(KeyError::NonCanonicalScalar)?;
        Ok(Self::from(scalar))
    }
}

impl SecretKey for Curve25519Secret {}

impl Debug for Curve25519Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Curve25519Secret")
    }
}

impl Serialize for Curve25519Secret {
    /// Serializes the secret key as a hex-encoded string.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.as_hex())
    }
}

impl From<Scalar> for Curve25519Secret {
    fn from(value: Scalar) -> Self {
        Self(Zeroizing::new(value))
    }
}

impl<'de> Deserialize<'de> for Curve25519Secret {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let hex_str = String::deserialize(deserializer)?;
        Curve25519Secret::from_hex(&hex_str).map_err(serde::de::Error::custom)
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

    pub fn as_point(&self) -> EdwardsPoint {
        self.point
    }

    /// Tries to deserialize a hex string into a `Curve25519PublicKey`. The hex string must represent a valid compressed
    /// point on the curve.
    pub fn from_hex(hex: &str) -> Result<Self, KeyError> {
        if hex.len() != 64 {
            return Err(KeyError::InvalidStringLength);
        }
        let mut compressed = [0u8; 32];
        hex::decode_to_slice(hex.as_bytes(), &mut compressed)?;
        let compressed_point = CompressedEdwardsY(compressed);
        let point = compressed_point.decompress().ok_or(KeyError::InvalidPoint)?;
        Ok(Self { compressed_point, point })
    }

    pub fn keypair_from_hex(secret: &str) -> Result<(Curve25519Secret, Curve25519PublicKey), KeyError> {
        let secret_key = Curve25519Secret::from_hex(secret)?;
        let public_key = Self::from_secret(&secret_key);
        Ok((secret_key, public_key))
    }

    pub fn as_hex(&self) -> String {
        hex::encode(self.compressed_point.to_bytes())
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

impl Debug for Curve25519PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_hex())
    }
}

impl Serialize for Curve25519PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.as_hex())
    }
}

impl<'de> Deserialize<'de> for Curve25519PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let hex_str = String::deserialize(deserializer)?;
        Curve25519PublicKey::from_hex(&hex_str).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Error)]
pub enum KeyError {
    #[error("Invalid point on curve")]
    InvalidPoint,
    #[error("Could not deserialize from hex: {0}")]
    HexDeserializationError(#[from] FromHexError),
    #[error("Invalid string length")]
    InvalidStringLength,
    #[error("Not a valid secret key")]
    NonCanonicalScalar,
}

#[cfg(test)]
mod test {
    use super::*;
    use rand::rng;

    #[test]
    fn test_keypair() {
        let (secret, public) = Curve25519PublicKey::keypair(&mut rng());
        let public2 = Curve25519PublicKey::from_secret(&secret);
        assert_eq!(public, public2);
    }

    #[test]
    fn test_from_hex() {
        let hex_k = "ce89029949049c902fdd5f2bf1493977dd061e782c44fd634b512bd75bc5ec08";
        let hex_p = "4dd896d542721742aff8671ba42aff0c4c846bea79065cf39a191bbeb11ea634";
        let secret = Curve25519Secret::from_hex(hex_k).unwrap();
        let public = Curve25519PublicKey::from_hex(hex_p).unwrap();
        assert_eq!(secret.as_hex(), hex_k);
        assert_eq!(public.as_hex(), hex_p);
    }

    #[test]
    fn test_from_hex_errors() {
        let hex_k = "ce89029949049c902fdd5f2bf1493977dd061e782c44fd634b512bd75bc5ecff";
        let secret = Curve25519Secret::from_hex(hex_k);
        assert!(
            matches!(secret, Err(KeyError::NonCanonicalScalar)),
            "IsErr: {}",
            secret.is_err()
        );

        let hex_k = "ce89029949049c902fdd5f2bf1493977dd061e782c44fd6";
        let secret = Curve25519Secret::from_hex(hex_k);
        assert!(matches!(secret, Err(KeyError::InvalidStringLength)));

        let hex_p = "4dd896d542721742aff8671ba42aff0c4c846bea79065cf39a191bbeb11ea635";
        let public = Curve25519PublicKey::from_hex(hex_p);
        assert!(matches!(public, Err(KeyError::InvalidPoint)), "Should fail: {public:?}");

        let hex_p = "4DD896d542721742aff8671ba42aff0c4c846bea79065cf39a191bbeb11ea6";
        let public = Curve25519PublicKey::from_hex(hex_p);
        assert!(matches!(public, Err(KeyError::InvalidStringLength)), "Should fail: {public:?}");

        let hex_p = "4dd896d542721742aff8671ba42aff0c4c846bea79065cf39a191bbeb11ea63x";
        let public = Curve25519PublicKey::from_hex(hex_p);
        assert!(matches!(
            public,
            Err(KeyError::HexDeserializationError(FromHexError::InvalidHexCharacter {
                c: 'x',
                index: 63
            }))
        ));
    }
}
