use crate::cryptography::commit::HashCommitment256;
use crate::cryptography::crypto_context::{get_crypto_context, has_crypto_context};
use crate::cryptography::ecdh_encrypt::EncryptedScalar;
use crate::cryptography::zk_objects::GenericScalar;
use crate::cryptography::Commit;
use blake2::Blake2b512;
use ciphersuite::group::ff::Field;
use ciphersuite::Ed25519;
use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::Scalar;
use dalek_ff_group::{EdwardsPoint, Scalar as XmrScalar};
use flexible_transcript::{RecommendedTranscript, Transcript};
use hex::FromHexError;
use log::error;
use modular_frost::sign::Writable;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use thiserror::Error;
use zeroize::Zeroizing;

/// A commitment to a Monero wallet public key. It's always a 256-bit Blake2b hash due to the implementation of
/// [`Commit`] for [`Curve25519PublicKey`].
pub type PublicKeyCommitment = HashCommitment256<Blake2b512>;

pub trait SecretKey: Clone + Send + Sync + Serialize + for<'de> Deserialize<'de> {}

pub trait PublicKey: Clone + PartialEq + Eq + Send + Sync + Serialize + for<'de> Deserialize<'de> {
    type SecretKey: SecretKey + Debug;

    fn keypair<R: CryptoRng + RngCore>(rng: &mut R) -> (Self::SecretKey, Self);
    fn from_secret(secret_key: &Self::SecretKey) -> Self;
}

/// A secret key for a Monero wallet.
///
/// Cloning is safe because the underlying scalar is zeroized on drop automatically.
#[derive(Clone, PartialEq, Eq)]
pub struct Curve25519Secret(Zeroizing<XmrScalar>);

impl Curve25519Secret {
    pub fn as_scalar(&self) -> &XmrScalar {
        &self.0
    }

    pub fn as_dalek_scalar(&self) -> &Scalar {
        &self.0 .0
    }

    pub fn as_zscalar(&self) -> &Zeroizing<XmrScalar> {
        &self.0
    }

    pub fn to_scalar(self) -> Zeroizing<XmrScalar> {
        self.0
    }

    pub fn to_dalek_scalar(&self) -> Zeroizing<Scalar> {
        Zeroizing::new(self.0 .0)
    }

    pub fn random<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        let s = XmrScalar::random(rng);
        let s = Zeroizing::new(s);
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

/// Prefix for encrypted secret serialization format.
/// This allows us to distinguish encrypted from plaintext secrets.
const ENCRYPTED_PREFIX: &str = "enc:";

impl Serialize for Curve25519Secret {
    /// Serializes the secret key as an encrypted hex-encoded string.
    ///
    /// # Panics
    ///
    /// Panics if called without an active crypto context. Use
    /// [`with_crypto_context`](crate::cryptography::crypto_context::with_crypto_context)
    /// to wrap serialization operations.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if !has_crypto_context() {
            panic!(
                "Attempted to serialize Curve25519Secret without crypto context. \
                 Wrap serialization in with_crypto_context() to encrypt secrets."
            );
        }
        let ctx = get_crypto_context();
        let encrypted = ctx.encrypt_scalar(&self.0);
        let bytes = encrypted.serialize();
        let hex_str = format!("{ENCRYPTED_PREFIX}{}", hex::encode(&bytes));
        serializer.serialize_str(&hex_str)
    }
}

impl From<XmrScalar> for Curve25519Secret {
    fn from(value: XmrScalar) -> Self {
        Self(Zeroizing::new(value))
    }
}

impl From<Scalar> for Curve25519Secret {
    fn from(value: Scalar) -> Self {
        Self(Zeroizing::new(XmrScalar(value)))
    }
}

impl<'de> Deserialize<'de> for Curve25519Secret {
    /// Deserializes the secret key from either encrypted or plaintext format.
    ///
    /// - Encrypted format: `enc:<hex-encoded EncryptedScalar>` (requires crypto context)
    /// - Plaintext format: `<hex-encoded scalar>` (legacy format, used for migration)
    ///
    /// # Panics
    ///
    /// Panics if attempting to deserialize encrypted format without an active crypto context.
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let hex_str = String::deserialize(deserializer)?;

        if let Some(encrypted_hex) = hex_str.strip_prefix(ENCRYPTED_PREFIX) {
            // Encrypted format - requires crypto context
            if !has_crypto_context() {
                panic!(
                    "Attempted to deserialize encrypted Curve25519Secret without crypto context. \
                     Wrap deserialization in with_crypto_context()."
                );
            }
            let bytes = hex::decode(encrypted_hex).map_err(serde::de::Error::custom)?;
            let encrypted = EncryptedScalar::<Ed25519>::read(&mut &bytes[..]).map_err(serde::de::Error::custom)?;
            let ctx = get_crypto_context();
            let scalar = ctx.decrypt_scalar(&encrypted);
            Ok(Self(scalar))
        } else {
            // Plaintext format - legacy/migration support
            // This allows reading old files that haven't been re-encrypted yet
            error!(
                "SECURITY WARNING: Deserializing plaintext secret. Plaintext storage is deprecated \
                 and will be removed in a future version. Re-save to encrypt."
            );
            Curve25519Secret::from_hex(&hex_str).map_err(serde::de::Error::custom)
        }
    }
}

/// A public key for a Monero wallet.
///
/// Note: EdwardsPoint is `Copy`, so may as well make this `Copy` too.
#[derive(Clone, PartialEq, Eq, Copy)]
pub struct Curve25519PublicKey {
    point: EdwardsPoint,
}

impl Curve25519PublicKey {
    pub fn to_compressed(&self) -> CompressedEdwardsY {
        self.point.compress()
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
        let point = EdwardsPoint(compressed_point.decompress().ok_or(KeyError::InvalidPoint)?);
        Ok(Self { point })
    }

    pub fn keypair_from_hex(secret: &str) -> Result<(Curve25519Secret, Curve25519PublicKey), KeyError> {
        let secret_key = Curve25519Secret::from_hex(secret)?;
        let public_key = Self::from_secret(&secret_key);
        Ok((secret_key, public_key))
    }

    pub fn as_hex(&self) -> String {
        hex::encode(self.to_compressed().to_bytes())
    }
}

impl From<EdwardsPoint> for Curve25519PublicKey {
    fn from(value: EdwardsPoint) -> Self {
        Self { point: value }
    }
}

impl TryFrom<CompressedEdwardsY> for Curve25519PublicKey {
    type Error = KeyError;
    fn try_from(value: CompressedEdwardsY) -> Result<Self, Self::Error> {
        let point = EdwardsPoint(value.decompress().ok_or(KeyError::InvalidPoint)?);
        Ok(Self { point })
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
        let point = EdwardsPoint(secret_key.as_dalek_scalar() * ED25519_BASEPOINT_TABLE);
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

impl Commit<Blake2b512> for Curve25519PublicKey {
    type Committed = PublicKeyCommitment;
    type Transcript = RecommendedTranscript;

    fn commit(&self) -> Self::Committed {
        let mut t = RecommendedTranscript::new(b"Curve25519PublicKeyCommitment");
        t.append_message(b"Ed25519.EdwardsPoint", self.to_compressed().to_bytes());
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&t.challenge(b"commitment"));
        HashCommitment256::new(hash)
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
    use crate::cryptography::crypto_context::{with_crypto_context, CryptoContext};
    use crate::XmrPoint;
    use ciphersuite::Ciphersuite;
    use rand_core::OsRng;
    use std::sync::Arc;

    /// Mock crypto context for testing encrypted serialization
    struct MockCryptoContext {
        encryption_privkey: XmrScalar,
        encryption_pubkey: XmrPoint,
    }

    impl MockCryptoContext {
        fn new() -> Self {
            let encryption_privkey = <Ed25519 as Ciphersuite>::random_nonzero_F(&mut OsRng);
            let encryption_pubkey = Ed25519::generator() * encryption_privkey;
            Self { encryption_privkey, encryption_pubkey }
        }
    }

    impl CryptoContext for MockCryptoContext {
        fn encryption_privkey(&self) -> Zeroizing<XmrScalar> {
            Zeroizing::new(self.encryption_privkey)
        }

        fn encryption_pubkey(&self) -> XmrPoint {
            self.encryption_pubkey
        }

        fn encrypt_scalar(&self, scalar: &XmrScalar) -> EncryptedScalar<Ed25519> {
            EncryptedScalar::encrypt(scalar, &self.encryption_pubkey(), &mut OsRng, b"test_domain")
        }

        fn decrypt_scalar(&self, encrypted: &EncryptedScalar<Ed25519>) -> Zeroizing<XmrScalar> {
            Zeroizing::new(encrypted.decrypt(&*self.encryption_privkey(), b"test_domain"))
        }
    }

    #[test]
    fn test_keypair() {
        let (secret, public) = Curve25519PublicKey::keypair(&mut OsRng);
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

    #[test]
    fn test_curve25519_secret_encrypted_serde_roundtrip() {
        let ctx = Arc::new(MockCryptoContext::new());
        let secret = Curve25519Secret::random(&mut OsRng);

        // Serialize with crypto context (encrypts the secret)
        let serialized = with_crypto_context(ctx.clone(), || serde_json::to_string(&secret).unwrap());

        // Verify it's encrypted (starts with "enc:")
        assert!(serialized.contains("enc:"), "Serialized form should be encrypted: {serialized}");

        // Deserialize with crypto context (decrypts the secret)
        let deserialized: Curve25519Secret = with_crypto_context(ctx, || serde_json::from_str(&serialized).unwrap());

        // Verify roundtrip works
        assert_eq!(secret.as_hex(), deserialized.as_hex());
    }

    #[test]
    fn test_curve25519_secret_deserialize_legacy_plaintext() {
        let ctx = Arc::new(MockCryptoContext::new());
        let secret = Curve25519Secret::random(&mut OsRng);
        let hex = secret.as_hex();

        // Legacy format: just a quoted hex string
        let legacy_json = format!("\"{hex}\"");

        // Deserialize legacy format (should work even without context for plaintext)
        let deserialized: Curve25519Secret = with_crypto_context(ctx, || serde_json::from_str(&legacy_json).unwrap());

        assert_eq!(secret.as_hex(), deserialized.as_hex());
    }

    #[test]
    #[should_panic(expected = "crypto context")]
    fn test_curve25519_secret_serialize_without_context_panics() {
        let secret = Curve25519Secret::random(&mut OsRng);
        // Serializing without context should panic
        let _ = serde_json::to_string(&secret);
    }

    #[test]
    #[should_panic(expected = "crypto context")]
    fn test_curve25519_secret_deserialize_encrypted_without_context_panics() {
        let ctx = Arc::new(MockCryptoContext::new());
        let secret = Curve25519Secret::random(&mut OsRng);

        // Serialize with context to get encrypted format
        let serialized = with_crypto_context(ctx, || serde_json::to_string(&secret).unwrap());

        // Deserializing encrypted format without context should panic
        let _: Curve25519Secret = serde_json::from_str(&serialized).unwrap();
    }

    #[test]
    fn test_curve25519_secret_different_contexts_produce_different_ciphertexts() {
        let ctx1 = Arc::new(MockCryptoContext::new());
        let ctx2 = Arc::new(MockCryptoContext::new());
        let secret = Curve25519Secret::random(&mut OsRng);

        let serialized1 = with_crypto_context(ctx1.clone(), || serde_json::to_string(&secret).unwrap());
        let serialized2 = with_crypto_context(ctx2, || serde_json::to_string(&secret).unwrap());

        // Different contexts should produce different ciphertexts (due to random ephemeral keys)
        // Note: Even the same context will produce different ciphertexts due to random nonces
        assert_ne!(serialized1, serialized2);

        // But decrypting with the correct context should give back the same value
        let deserialized: Curve25519Secret = with_crypto_context(ctx1, || serde_json::from_str(&serialized1).unwrap());
        assert_eq!(secret.as_hex(), deserialized.as_hex());
    }
}
