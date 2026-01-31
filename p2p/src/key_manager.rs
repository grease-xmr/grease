use libgrease::cryptography::crypto_context::CryptoContext;
use libgrease::cryptography::keys::PublicKey;

/// Trait for managing cryptographic keys in the Grease protocol.
///
/// Implementations provide key derivation, validation, and encryption/decryption
/// of secrets for at-rest storage. The trait extends [`CryptoContext`] to enable
/// transparent encryption of secrets during serialization.
///
/// # Usage with Encrypted Secrets
///
/// When serializing or deserializing types containing [`Curve25519Secret`](libgrease::cryptography::keys::Curve25519Secret),
/// the KeyManager must be set as the active crypto context:
///
/// ```ignore
/// use libgrease::cryptography::crypto_context::with_crypto_context;
///
/// with_crypto_context(key_manager.clone(), || {
///     file_store.write_channel(&state)?;
///     Ok(())
/// })?;
/// ```
pub trait KeyManager: Clone + CryptoContext {
    type PublicKey: PublicKey;

    /// Creates a new `KeyManager` from the given secret key, deriving its corresponding public key.
    fn new(initial_key: <Self::PublicKey as PublicKey>::SecretKey) -> Self;

    /// Deterministically generates a new keypair based on the initial secret key and a given index.
    ///
    /// # Parameters
    /// - `index`: The index used to derive a unique keypair from the initial secret.
    ///
    /// # Returns
    /// A tuple containing the derived secret key and its corresponding public key.
    fn new_keypair(&self, index: u64) -> (<Self::PublicKey as PublicKey>::SecretKey, Self::PublicKey);

    fn initial_public_key(&self) -> &Self::PublicKey;

    fn validate_keypair(&self, secret: &<Self::PublicKey as PublicKey>::SecretKey, public: &Self::PublicKey) -> bool;
}
