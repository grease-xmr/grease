//! Thread-local cryptographic context for encrypting secrets during serialization.
//!
//! This module provides a mechanism for [`Curve25519Secret`](super::keys::Curve25519Secret) and other
//! sensitive types to transparently encrypt their values during serialization without requiring
//! custom serializer implementations.
//!
//! # Design
//!
//! Standard serde doesn't pass state to serialize/deserialize functions, so we use a thread-local
//! context that holds encryption keys. Before serializing or deserializing types containing secrets,
//! callers must wrap the operation in [`with_crypto_context`].
//!
//! # Example
//!
//! ```ignore
//! use libgrease::cryptography::crypto_context::with_crypto_context;
//!
//! // When saving channel state
//! with_crypto_context(key_manager.clone(), || {
//!     file_store.write_channel(&state)?;
//!     Ok(())
//! })?;
//!
//! // When loading channel state
//! let state = with_crypto_context(key_manager.clone(), || {
//!     file_store.load_channel(&channel_id)
//! })?;
//! ```
//!
//! # Panics
//!
//! Attempting to serialize or deserialize a [`Curve25519Secret`] without an active crypto context
//! will panic. This is intentional - it prevents accidental plaintext serialization of secrets.
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

use crate::cryptography::ecdh_encrypt::EncryptedScalar;
use crate::{XmrPoint, XmrScalar};
use ciphersuite::Ed25519;
use std::cell::RefCell;
use std::marker::PhantomData;
use std::sync::Arc;
use zeroize::Zeroizing;

thread_local! {
    static CRYPTO_CONTEXT: RefCell<Option<Arc<dyn CryptoContext>>> = const { RefCell::new(None) };
}

/// Trait for types that can encrypt and decrypt scalars.
///
/// Implementations typically use ECDH-based encryption with a derived encryption keypair
/// to encrypt scalars for at-rest storage. The encryption keypair should be deterministically
/// derived from the implementation's root key.
pub trait CryptoContext: Send + Sync {
    /// Returns the encryption private key, derived deterministically from the root key.
    ///
    /// This key is used for ECDH decryption and should NOT be the same as the root key
    /// to maintain key separation.
    ///
    /// The return value is wrapped in `Zeroizing` to ensure it is zeroed when dropped.
    fn encryption_privkey(&self) -> Zeroizing<XmrScalar>;

    /// Returns the encryption public key, derived from `encryption_privkey()`.
    ///
    /// This key is used for ECDH encryption.
    fn encryption_pubkey(&self) -> XmrPoint;

    /// Encrypt a scalar for at-rest storage.
    ///
    /// The encryption uses ephemeral ECDH with `encryption_pubkey()`.
    fn encrypt_scalar(&self, scalar: &XmrScalar) -> EncryptedScalar<Ed25519>;

    /// Decrypt a scalar from at-rest storage.
    ///
    /// Uses `encryption_privkey()` to perform ECDH decryption.
    fn decrypt_scalar(&self, encrypted: &EncryptedScalar<Ed25519>) -> Zeroizing<XmrScalar>;
}

/// Execute a closure with the given crypto context.
///
/// The context is set for the duration of the closure and restored to its previous
/// value afterward (supporting nested calls).
///
/// # Example
///
/// ```ignore
/// let state = with_crypto_context(key_manager.clone(), || {
///     ron::ser::to_string_pretty(&channel_state, config)
/// })?;
/// ```
///
/// # Panics
///
/// The closure may panic if it tries to serialize/deserialize secrets, and this function
/// will propagate that panic after restoring the previous context.
pub fn with_crypto_context<T, F: FnOnce() -> T>(ctx: Arc<dyn CryptoContext>, f: F) -> T {
    CRYPTO_CONTEXT.with(|c| {
        let old = c.borrow_mut().replace(ctx);
        // Use a guard to ensure we restore the old context even on panic
        struct RestoreGuard<'a> {
            cell: &'a RefCell<Option<Arc<dyn CryptoContext>>>,
            old: Option<Arc<dyn CryptoContext>>,
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

/// Get the current crypto context.
///
/// # Panics
///
/// Panics if called outside of a [`with_crypto_context`] block. This is intentional
/// to prevent accidental plaintext serialization of secrets.
pub(crate) fn get_crypto_context() -> Arc<dyn CryptoContext> {
    CRYPTO_CONTEXT
        .with(|c| c.borrow().clone().expect("crypto context not set - wrap serialization in with_crypto_context()"))
}

/// Check if a crypto context is currently set.
///
/// This can be used to provide better error messages or fall back to plaintext
/// serialization in development/test scenarios.
pub fn has_crypto_context() -> bool {
    CRYPTO_CONTEXT.with(|c| c.borrow().is_some())
}

/// Set the crypto context for the current thread.
///
/// Unlike [`with_crypto_context`], this sets the context without automatic cleanup.
/// You must call `clear_crypto_context()` when done.
///
/// # Use Case
///
/// This is useful for async contexts where the serialization happens across
/// multiple await points but on the same thread:
///
/// ```ignore
/// set_crypto_context(key_manager.clone());
/// let result = some_async_operation().await;
/// clear_crypto_context();
/// ```
///
/// # Warning
///
/// Forgetting to call `clear_crypto_context()` will leave the context set,
/// which could cause issues in shared thread pools.
pub fn set_crypto_context(ctx: Arc<dyn CryptoContext>) {
    CRYPTO_CONTEXT.with(|c| {
        *c.borrow_mut() = Some(ctx);
    });
}

/// Clear the crypto context for the current thread.
///
/// Call this after using `set_crypto_context()` when the operation is complete.
pub fn clear_crypto_context() {
    CRYPTO_CONTEXT.with(|c| {
        *c.borrow_mut() = None;
    });
}

/// RAII guard for the crypto context.
///
/// Sets the crypto context when created, clears it when dropped.
/// This ensures the context is always cleared, even on early returns or panics.
///
/// # Thread Safety
///
/// This type is intentionally `!Send` and `!Sync`. Attempting to hold it across an
/// `.await` point in a multi-threaded tokio runtime will result in a compile error:
///
/// ```text
/// error: future cannot be sent between threads safely
/// ```
///
/// This is by design: the guard manages a thread-local context, so moving it to
/// another thread would cause the `Drop` to clear the wrong thread's context.
///
/// # Usage in Async Code
///
/// ## Option 1: Use `with_crypto_context` (Recommended)
///
/// The closure-based API naturally scopes the context to a synchronous block:
///
/// ```ignore
/// async fn save_state(state: &ChannelState, ctx: Arc<dyn CryptoContext>) -> Result<()> {
///     let serialized = with_crypto_context(ctx, || {
///         ron::to_string(state)
///     })?;
///     file.write_all(serialized.as_bytes()).await?;
///     Ok(())
/// }
/// ```
///
/// ## Option 2: Use `spawn_blocking`
///
/// Move the entire serialization operation to a blocking thread pool:
///
/// ```ignore
/// async fn save_state(state: ChannelState, ctx: Arc<dyn CryptoContext>) -> Result<()> {
///     let serialized = tokio::task::spawn_blocking(move || {
///         let _guard = CryptoContextGuard::new(ctx);
///         ron::to_string(&state)
///     }).await??;
///     file.write_all(serialized.as_bytes()).await?;
///     Ok(())
/// }
/// ```
///
/// ## Option 3: Use `block_in_place`
///
/// For operations that must run on the current task but need the guard:
///
/// ```ignore
/// async fn save_state(state: &ChannelState, ctx: Arc<dyn CryptoContext>) -> Result<()> {
///     let serialized = tokio::task::block_in_place(|| {
///         let _guard = CryptoContextGuard::new(ctx);
///         ron::to_string(state)
///     })?;
///     file.write_all(serialized.as_bytes()).await?;
///     Ok(())
/// }
/// ```
///
/// ## Option 4: Single-threaded runtime
///
/// If your application uses `#[tokio::main(flavor = "current_thread")]` or
/// `LocalSet`, the guard is safe since tasks never migrate between threads.
///
/// # Synchronous Example
///
/// ```ignore
/// // Synchronous code: straightforward usage
/// {
///     let _guard = CryptoContextGuard::new(ctx);
///     let serialized = ron::to_string(&channel_state)?;
/// } // context is cleared here
/// ```
pub struct CryptoContextGuard {
    // Raw pointers are !Send and !Sync, making this type !Send.
    // This prevents the guard from being moved across thread boundaries,
    // which would cause the Drop to clear the wrong thread's context.
    _not_send: PhantomData<*const ()>,
}

impl CryptoContextGuard {
    /// Creates a new guard that sets the crypto context.
    ///
    /// The context will be cleared when the guard is dropped.
    pub fn new(ctx: Arc<dyn CryptoContext>) -> Self {
        set_crypto_context(ctx);
        Self { _not_send: PhantomData }
    }
}

impl Drop for CryptoContextGuard {
    fn drop(&mut self) {
        clear_crypto_context();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciphersuite::group::ff::Field;
    use ciphersuite::Ciphersuite;
    use rand_core::OsRng;

    struct MockCryptoContext {
        encryption_privkey: XmrScalar,
        encryption_pubkey: XmrPoint,
    }

    impl MockCryptoContext {
        fn new() -> Self {
            let mut rng = OsRng;
            let encryption_privkey = <Ed25519 as Ciphersuite>::random_nonzero_F(&mut rng);
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
            let mut rng = OsRng;
            // Ed25519::F is dalek_ff_group::Scalar = XmrScalar, so pass scalar directly
            EncryptedScalar::encrypt(scalar, &self.encryption_pubkey(), &mut rng, b"test_domain")
        }

        fn decrypt_scalar(&self, encrypted: &EncryptedScalar<Ed25519>) -> Zeroizing<XmrScalar> {
            // decrypt returns Ed25519::F = XmrScalar
            Zeroizing::new(encrypted.decrypt(&*self.encryption_privkey(), b"test_domain"))
        }
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let ctx = Arc::new(MockCryptoContext::new());
        // Ed25519::F::random returns XmrScalar directly
        let scalar = <Ed25519 as Ciphersuite>::F::random(&mut OsRng);

        let encrypted = ctx.encrypt_scalar(&scalar);
        let decrypted = ctx.decrypt_scalar(&encrypted);

        assert_eq!(scalar, *decrypted);
    }

    #[test]
    fn with_crypto_context_sets_and_restores() {
        assert!(!has_crypto_context());

        let ctx = Arc::new(MockCryptoContext::new());
        let result = with_crypto_context(ctx, || {
            assert!(has_crypto_context());
            42
        });

        assert_eq!(result, 42);
        assert!(!has_crypto_context());
    }

    #[test]
    fn nested_contexts_work() {
        let ctx1 = Arc::new(MockCryptoContext::new());
        let ctx2 = Arc::new(MockCryptoContext::new());

        with_crypto_context(ctx1.clone(), || {
            assert!(has_crypto_context());

            with_crypto_context(ctx2.clone(), || {
                assert!(has_crypto_context());
            });

            // Outer context is restored
            assert!(has_crypto_context());
        });

        assert!(!has_crypto_context());
    }

    #[test]
    #[should_panic(expected = "crypto context not set")]
    fn get_context_without_setting_panics() {
        let _ = get_crypto_context();
    }

    #[test]
    fn context_restored_on_panic() {
        let ctx = Arc::new(MockCryptoContext::new());

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            with_crypto_context(ctx, || {
                panic!("intentional panic");
            });
        }));

        assert!(result.is_err());
        assert!(!has_crypto_context());
    }

    /// Compile-time assertion that CryptoContextGuard is !Send and !Sync.
    /// This prevents the guard from being moved across thread boundaries.
    #[test]
    fn guard_is_not_send() {
        // This is a compile-time check: if CryptoContextGuard implemented Send or Sync,
        // compilation would fail. The PhantomData<*const ()> field makes the type !Send.
        static_assertions::assert_not_impl_any!(CryptoContextGuard: Send, Sync);
    }
}
