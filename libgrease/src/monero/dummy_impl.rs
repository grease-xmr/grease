use crate::monero::MultiSigWallet;

pub struct DummyWallet;

impl MultiSigWallet for DummyWallet {
    fn create(_num_signers: usize, _threshold: usize) -> Self {
        DummyWallet
    }
}
