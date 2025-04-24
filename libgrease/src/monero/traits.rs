pub trait MultiSigWallet {
    fn create(num_signers: usize, threshold: usize) -> Self;
}
