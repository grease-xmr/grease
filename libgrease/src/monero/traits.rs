use serde::de::DeserializeOwned;
use serde::Serialize;

pub trait MultiSigWallet: Serialize + DeserializeOwned {
    fn create(num_signers: usize, threshold: usize) -> Self;
}
