use crate::monero::MultiSigWallet;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DummyWallet;

impl MultiSigWallet for DummyWallet {
    fn create(_num_signers: usize, _threshold: usize) -> Self {
        DummyWallet
    }
}
