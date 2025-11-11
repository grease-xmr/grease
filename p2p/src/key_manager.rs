use libgrease::cryptography::keys::PublicKey;

pub trait KeyManager: Clone {
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
