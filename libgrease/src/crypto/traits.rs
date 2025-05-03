use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

pub trait SecretKey: Clone + Serialize + for<'de> Deserialize<'de> {}

pub trait PublicKey: Clone + PartialEq + Eq + Serialize + for<'de> Deserialize<'de> {
    type SecretKey: SecretKey;

    fn keypair<R: CryptoRng + RngCore>(rng: &mut R) -> (Self::SecretKey, Self);
    fn from_secret(secret_key: &Self::SecretKey) -> Self;
}
