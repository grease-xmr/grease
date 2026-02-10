//! Thread-local encryption context for encrypting secrets during serialization.
//!
//! This module provides a mechanism for [`Curve25519Secret`](super::keys::Curve25519Secret),
//! [`SerializableSecret`](super::serializable_secret::SerializableSecret), and other sensitive
//! types to transparently encrypt their values during serialization without requiring custom
//! serializer implementations.
//!
//! # Design
//!
//! Standard serde doesn't pass state to serialize/deserialize functions, so we use a thread-local
//! context that holds an encryption implementation. Before serializing or deserializing types
//! containing secrets, callers must wrap the operation in [`with_encryption_context`].
//!
//! # Example
//!
//! ```ignore
//! use libgrease::cryptography::encryption_context::{with_encryption_context, EncryptionContext};
//! use std::sync::Arc;
//!
//! let ctx: Arc<dyn EncryptionContext> = Arc::new(my_encryption.clone());
//!
//! // When saving channel state
//! with_encryption_context(ctx.clone(), || {
//!     file_store.write_channel(&state)?;
//!     Ok(())
//! })?;
//!
//! // When loading channel state
//! let state = with_encryption_context(ctx, || {
//!     file_store.load_channel(&channel_id)
//! })?;
//! ```
//!
//! # Panics
//!
//! Attempting to serialize or deserialize a secret type without an active encryption context
//! will panic. This is intentional — it prevents accidental plaintext serialization of secrets.
//!
//! # Thread Safety Warning
//!
//! The context is thread-local, which means it only works correctly when serialization happens
//! on the same thread that set the context. This is **NOT** compatible with work-stealing async
//! runtimes (like tokio's multi-threaded runtime) where a task may be moved between threads
//! across await points.
//!
//! For async code with work-stealing runtimes, ensure that all serialization happens synchronously
//! within a single `.await` point, or use [`tokio::task::spawn_blocking`] to run serialization
//! on a dedicated thread.

use std::cell::RefCell;
use std::sync::Arc;
use zeroize::Zeroizing;

/// Errors that can occur during decryption.
#[derive(Debug, thiserror::Error)]
pub enum DecryptionError {
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("Failed to convert decrypted bytes to target type")]
    ConversionFailed,
}

/// Bytes-based encryption trait for at-rest secret storage.
///
/// Implementations encrypt arbitrary plaintext bytes and return ciphertext bytes
/// (including any nonce/tag needed for decryption). The trait is object-safe,
/// allowing `Arc<dyn EncryptionContext>` usage in thread-locals.
pub trait EncryptionContext: Send + Sync {
    /// Encrypt plaintext bytes. Returns ciphertext (format is implementation-defined).
    fn encrypt(&self, plaintext: &[u8]) -> Vec<u8>;

    /// Decrypt ciphertext bytes. Returns the original plaintext wrapped in `Zeroizing`.
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, DecryptionError>;
}

thread_local! {
    static ENCRYPTION_CONTEXT: RefCell<Option<Arc<dyn EncryptionContext>>> = const { RefCell::new(None) };
}

/// Execute a closure with the given encryption context.
///
/// The context is set for the duration of the closure and restored to its previous
/// value afterward (supporting nested calls).
pub fn with_encryption_context<T, F: FnOnce() -> T>(ctx: Arc<dyn EncryptionContext>, f: F) -> T {
    ENCRYPTION_CONTEXT.with(|c| {
        let old = c.borrow_mut().replace(ctx);
        struct RestoreGuard<'a> {
            cell: &'a RefCell<Option<Arc<dyn EncryptionContext>>>,
            old: Option<Arc<dyn EncryptionContext>>,
        }
        impl Drop for RestoreGuard<'_> {
            fn drop(&mut self) {
                *self.cell.borrow_mut() = self.old.take();
            }
        }
        let _guard = RestoreGuard { cell: c, old };
        f()
    })
}

/// Get the current encryption context.
///
/// # Panics
///
/// Panics if called outside of a [`with_encryption_context`] block.
pub(crate) fn get_encryption_context() -> Arc<dyn EncryptionContext> {
    ENCRYPTION_CONTEXT.with(|c| {
        c.borrow().clone().expect("encryption context not set - wrap serialization in with_encryption_context()")
    })
}

/// Check if an encryption context is currently set.
pub fn has_encryption_context() -> bool {
    ENCRYPTION_CONTEXT.with(|c| c.borrow().is_some())
}

/// Set the encryption context for the current thread (without automatic cleanup).
///
/// You must call [`clear_encryption_context`] when done.
pub fn set_encryption_context(ctx: Arc<dyn EncryptionContext>) {
    ENCRYPTION_CONTEXT.with(|c| {
        *c.borrow_mut() = Some(ctx);
    });
}

/// Clear the encryption context for the current thread.
pub fn clear_encryption_context() {
    ENCRYPTION_CONTEXT.with(|c| {
        *c.borrow_mut() = None;
    });
}

// ---- AES-256-GCM Implementation ----

use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Nonce};

/// AES-256-GCM based encryption context.
///
/// Wire format: `nonce(12) || ciphertext || tag(16)`.
pub struct AesGcmEncryption {
    key: Zeroizing<[u8; 32]>,
}

impl AesGcmEncryption {
    pub fn new(key: [u8; 32]) -> Self {
        Self { key: Zeroizing::new(key) }
    }

    /// Create an `AesGcmEncryption` with a random key (useful for tests).
    pub fn random() -> Self {
        use rand_core::RngCore;
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        Self::new(key)
    }
}

impl EncryptionContext for AesGcmEncryption {
    fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        use rand_core::RngCore;
        let cipher = Aes256Gcm::new(self.key.as_ref().into());
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, plaintext).expect("AES-256-GCM encryption should not fail");
        let mut out = Vec::with_capacity(12 + ciphertext.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        out
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, DecryptionError> {
        if ciphertext.len() < 12 + 16 {
            return Err(DecryptionError::DecryptionFailed("ciphertext too short".into()));
        }
        let (nonce_bytes, ct) = ciphertext.split_at(12);
        let cipher = Aes256Gcm::new(self.key.as_ref().into());
        let nonce = Nonce::from_slice(nonce_bytes);
        let plaintext =
            cipher.decrypt(nonce, ct).map_err(|e| DecryptionError::DecryptionFailed(format!("AES-GCM: {e}")))?;
        Ok(Zeroizing::new(plaintext))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes_gcm_encrypt_decrypt_roundtrip() {
        let ctx = AesGcmEncryption::random();
        let plaintext = b"hello secret world";
        let ciphertext = ctx.encrypt(plaintext);
        let decrypted = ctx.decrypt(&ciphertext).expect("decryption should succeed");
        assert_eq!(&*decrypted, plaintext);
    }

    #[test]
    fn aes_gcm_different_ciphertexts_for_same_plaintext() {
        let ctx = AesGcmEncryption::random();
        let plaintext = b"same data";
        let ct1 = ctx.encrypt(plaintext);
        let ct2 = ctx.encrypt(plaintext);
        assert_ne!(ct1, ct2, "random nonces should produce different ciphertexts");
        // Both should decrypt correctly
        assert_eq!(&*ctx.decrypt(&ct1).unwrap(), plaintext);
        assert_eq!(&*ctx.decrypt(&ct2).unwrap(), plaintext);
    }

    #[test]
    fn aes_gcm_wrong_key_fails() {
        let ctx1 = AesGcmEncryption::random();
        let ctx2 = AesGcmEncryption::random();
        let ciphertext = ctx1.encrypt(b"secret");
        assert!(ctx2.decrypt(&ciphertext).is_err());
    }

    #[test]
    fn aes_gcm_tampered_ciphertext_fails() {
        let ctx = AesGcmEncryption::random();
        let mut ciphertext = ctx.encrypt(b"secret");
        // Flip a byte in the ciphertext portion
        let last = ciphertext.len() - 1;
        ciphertext[last] ^= 0xff;
        assert!(ctx.decrypt(&ciphertext).is_err());
    }

    #[test]
    fn aes_gcm_too_short_ciphertext_fails() {
        let ctx = AesGcmEncryption::random();
        assert!(ctx.decrypt(&[0u8; 10]).is_err());
    }

    #[test]
    fn with_encryption_context_sets_and_restores() {
        assert!(!has_encryption_context());
        let ctx = Arc::new(AesGcmEncryption::random());
        let result = with_encryption_context(ctx, || {
            assert!(has_encryption_context());
            42
        });
        assert_eq!(result, 42);
        assert!(!has_encryption_context());
    }

    #[test]
    fn nested_contexts_work() {
        let ctx1 = Arc::new(AesGcmEncryption::random());
        let ctx2 = Arc::new(AesGcmEncryption::random());

        with_encryption_context(ctx1.clone(), || {
            assert!(has_encryption_context());
            with_encryption_context(ctx2.clone(), || {
                assert!(has_encryption_context());
            });
            assert!(has_encryption_context());
        });
        assert!(!has_encryption_context());
    }

    #[test]
    #[should_panic(expected = "encryption context not set")]
    fn get_context_without_setting_panics() {
        let _ = get_encryption_context();
    }

    #[test]
    fn context_restored_on_panic() {
        let ctx = Arc::new(AesGcmEncryption::random());
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            with_encryption_context(ctx, || {
                panic!("intentional panic");
            });
        }));
        assert!(result.is_err());
        assert!(!has_encryption_context());
    }
}
