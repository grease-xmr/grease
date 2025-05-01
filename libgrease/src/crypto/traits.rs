use rand::{CryptoRng, RngCore};

pub trait SecretKey: Clone {}

pub trait PublicKey: Clone + PartialEq + Eq {
    type SecretKey: SecretKey;

    fn keypair<R: CryptoRng + RngCore>(rng: &mut R) -> (Self::SecretKey, Self);
    fn from_secret(secret_key: &Self::SecretKey) -> Self;
}
