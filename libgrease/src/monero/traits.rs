use serde::{Deserialize, Serialize};

pub trait MultiSigWallet: Serialize + for<'de> Deserialize<'de> + Send + Sync {
    fn create(num_signers: usize, threshold: usize) -> Self;
}
