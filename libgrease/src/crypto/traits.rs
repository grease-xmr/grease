use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

pub trait SecretKey: Clone + Send + Sync + Serialize + for<'de> Deserialize<'de> {}

pub trait PublicKey: Clone + PartialEq + Eq + Send + Sync + Serialize + for<'de> Deserialize<'de> {
    type SecretKey: SecretKey;

    fn keypair<R: CryptoRng + RngCore>(rng: &mut R) -> (Self::SecretKey, Self);
    fn from_secret(secret_key: &Self::SecretKey) -> Self;
}
