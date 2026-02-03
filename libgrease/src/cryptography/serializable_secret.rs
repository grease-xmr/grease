use crate::cryptography::encryption_context::{get_encryption_context, has_encryption_context};
use crate::cryptography::secret_bytes::SecretBytes;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::ops::Deref;
use zeroize::Zeroizing;

/// Prefix for encrypted serialization format.
const ENCRYPTED_PREFIX: &str = "enc:";

/// A wrapper around a secret value that encrypts on serialize and decrypts on deserialize.
///
/// The inner value must implement [`SecretBytes`] to enable byte-level encryption. During
/// serialization, the value is converted to bytes, encrypted via the thread-local
/// [`EncryptionContext`](crate::cryptography::encryption_context::EncryptionContext),
/// hex-encoded, and prefixed with `"enc:"`.
///
/// # Panics
///
/// Serialization and deserialization panic if no encryption context is set.
pub struct SerializableSecret<T: SecretBytes>(pub Zeroizing<T>);

impl<T: SecretBytes + Clone> Clone for SerializableSecret<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T: SecretBytes> fmt::Debug for SerializableSecret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SerializableSecret(***)")
    }
}

impl<T: SecretBytes + PartialEq> PartialEq for SerializableSecret<T> {
    fn eq(&self, other: &Self) -> bool {
        *self.0 == *other.0
    }
}

impl<T: SecretBytes + Eq> Eq for SerializableSecret<T> {}

impl<T: SecretBytes> Deref for SerializableSecret<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T: SecretBytes> From<Zeroizing<T>> for SerializableSecret<T> {
    fn from(inner: Zeroizing<T>) -> Self {
        Self(inner)
    }
}

impl<T: SecretBytes> From<T> for SerializableSecret<T> {
    fn from(inner: T) -> Self {
        Self(Zeroizing::new(inner))
    }
}

impl<T: SecretBytes> Serialize for SerializableSecret<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if !has_encryption_context() {
            panic!(
                "Attempted to serialize SerializableSecret without encryption context. \
                 Wrap serialization in with_encryption_context()."
            );
        }
        let ctx = get_encryption_context();
        let plaintext = self.0.to_secret_bytes();
        let ciphertext = ctx.encrypt(&plaintext);
        let hex_str = format!("{ENCRYPTED_PREFIX}{}", hex::encode(&ciphertext));
        serializer.serialize_str(&hex_str)
    }
}

impl<'de, T: SecretBytes> Deserialize<'de> for SerializableSecret<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let encrypted_hex = s.strip_prefix(ENCRYPTED_PREFIX).ok_or_else(|| {
            serde::de::Error::custom(format!("SerializableSecret: expected '{ENCRYPTED_PREFIX}' prefix"))
        })?;
        if !has_encryption_context() {
            panic!(
                "Attempted to deserialize SerializableSecret without encryption context. \
                 Wrap deserialization in with_encryption_context()."
            );
        }
        let ciphertext = hex::decode(encrypted_hex).map_err(serde::de::Error::custom)?;
        let ctx = get_encryption_context();
        let plaintext = ctx.decrypt(&ciphertext).map_err(|e| serde::de::Error::custom(format!("{e}")))?;
        let value = T::from_secret_bytes(&plaintext).ok_or_else(|| serde::de::Error::custom("invalid secret bytes"))?;
        Ok(Self(Zeroizing::new(value)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cryptography::encryption_context::{with_encryption_context, AesGcmEncryption};
    use crate::XmrScalar;
    use ciphersuite::group::ff::Field;
    use rand_core::OsRng;
    use std::sync::Arc;

    fn test_ctx() -> Arc<dyn crate::cryptography::encryption_context::EncryptionContext> {
        Arc::new(AesGcmEncryption::random())
    }

    #[test]
    fn roundtrip_xmr_scalar() {
        let ctx = test_ctx();
        let scalar = XmrScalar::random(&mut OsRng);
        let secret: SerializableSecret<XmrScalar> = SerializableSecret::from(scalar);

        let json = with_encryption_context(ctx.clone(), || serde_json::to_string(&secret).unwrap());
        assert!(json.contains("enc:"), "should be encrypted: {json}");

        let recovered: SerializableSecret<XmrScalar> =
            with_encryption_context(ctx, || serde_json::from_str(&json).unwrap());
        assert_eq!(*secret.0, *recovered.0);
    }

    #[test]
    fn different_contexts_produce_different_ciphertexts() {
        let ctx1 = test_ctx();
        let ctx2 = test_ctx();
        let scalar = XmrScalar::random(&mut OsRng);
        let secret: SerializableSecret<XmrScalar> = SerializableSecret::from(scalar);

        let json1 = with_encryption_context(ctx1, || serde_json::to_string(&secret).unwrap());
        let json2 = with_encryption_context(ctx2, || serde_json::to_string(&secret).unwrap());
        assert_ne!(json1, json2);
    }

    #[test]
    #[should_panic(expected = "encryption context")]
    fn serialize_without_context_panics() {
        let secret: SerializableSecret<XmrScalar> = SerializableSecret::from(XmrScalar::default());
        let _ = serde_json::to_string(&secret);
    }

    #[test]
    #[should_panic(expected = "encryption context")]
    fn deserialize_encrypted_without_context_panics() {
        let ctx = test_ctx();
        let secret: SerializableSecret<XmrScalar> = SerializableSecret::from(XmrScalar::default());
        let json = with_encryption_context(ctx, || serde_json::to_string(&secret).unwrap());
        let _: SerializableSecret<XmrScalar> = serde_json::from_str(&json).unwrap();
    }

    #[test]
    fn deref_provides_inner_access() {
        let scalar = XmrScalar::from(42u64);
        let secret: SerializableSecret<XmrScalar> = SerializableSecret::from(scalar);
        assert_eq!(*secret, scalar);
    }

    #[test]
    fn debug_is_redacted() {
        let secret: SerializableSecret<XmrScalar> = SerializableSecret::from(XmrScalar::default());
        let dbg = format!("{secret:?}");
        assert!(dbg.contains("***"));
        assert!(!dbg.contains("Scalar"));
    }

    #[test]
    fn clone_preserves_value() {
        let scalar = XmrScalar::random(&mut OsRng);
        let secret: SerializableSecret<XmrScalar> = SerializableSecret::from(scalar);
        let cloned = secret.clone();
        assert_eq!(*secret, *cloned);
    }
}
