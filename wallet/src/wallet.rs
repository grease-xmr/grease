use crate::common::{create_change, create_signable_tx};
use crate::errors::WalletError;
use crate::watch_only::WatchOnlyWallet;
use crate::MoneroAddress;
use blake2::Digest;
use libgrease::amount::MoneroAmount;
use libgrease::cryptography::keys::{Curve25519PublicKey, Curve25519Secret, PublicKey};
use log::*;
use monero_rpc::{Rpc, RpcError};
use monero_serai::block::Block;
use monero_simple_request_rpc::SimpleRequestRpc;
use monero_wallet::WalletOutput;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

#[derive(Debug, Clone)]
pub struct MoneroWallet {
    private_spend_key: Curve25519Secret,
    inner: WatchOnlyWallet,
}

impl MoneroWallet {
    pub fn new(
        rpc: SimpleRequestRpc,
        private_spend_key: Curve25519Secret,
        private_view_key: Curve25519Secret,
        birthday: Option<u64>,
    ) -> Result<Self, WalletError> {
        let public_spend_key = Curve25519PublicKey::from_secret(&private_spend_key);
        let inner = WatchOnlyWallet::new(rpc.clone(), private_view_key, public_spend_key, birthday)?;
        Ok(MoneroWallet { private_spend_key, inner })
    }

    pub fn private_view_key(&self) -> &Curve25519Secret {
        self.inner.private_view_key()
    }

    pub fn public_spend_key(&self) -> &Curve25519PublicKey {
        self.inner.public_spend_key()
    }

    pub fn public_view_key(&self) -> Curve25519PublicKey {
        Curve25519PublicKey::from_secret(self.inner.private_view_key())
    }

    pub fn address(&self) -> MoneroAddress {
        self.inner.address()
    }

    pub async fn get_height(&self) -> Result<u64, RpcError> {
        self.inner.get_height().await
    }

    pub async fn get_block_by_number(&self, block_num: u64) -> Result<Block, RpcError> {
        self.inner.get_block_by_number(block_num).await
    }

    pub async fn scan(&mut self, start: Option<u64>, end: Option<u64>) -> Result<usize, RpcError> {
        self.inner.scan(start, end).await
    }

    pub fn outputs(&self) -> &[WalletOutput] {
        self.inner.outputs()
    }

    pub fn remove_outputs(&mut self, outputs: Vec<WalletOutput>) {
        self.inner.remove_outputs(outputs);
    }

    pub fn rpc(&self) -> &SimpleRequestRpc {
        self.inner.rpc()
    }

    pub async fn send(&mut self, to: MoneroAddress, amount: MoneroAmount) -> Result<[u8; 32], WalletError> {
        let mut rng = self.deterministic_rng();
        let payments = vec![(to, amount.to_piconero())];
        let change = create_change(self.public_spend_key())?;
        let must_scan = self.outputs().is_empty();
        if must_scan {
            info!("No outputs found in the wallet, scanning the blockchain. This may take a while.");
            self.scan(None, None).await?;
        }
        let outputs = self.inner.find_spendable_outputs(amount)?;
        let signable = create_signable_tx(self.rpc(), &mut rng, outputs.clone(), payments, change, vec![]).await?;
        let tx = signable.sign(&mut rng, &self.private_spend_key.to_dalek_scalar())?;
        let hash = tx.hash();
        debug!("Signable transaction successfully created. {amount} to {to}");
        self.rpc().publish_transaction(&tx).await?;
        self.remove_outputs(outputs);
        debug!(
            "Transaction {} successfully published to network: {amount} to {to}",
            hex::encode(hash)
        );
        Ok(hash)
    }

    fn deterministic_rng(&self) -> ChaCha20Rng {
        // Use the spend key as a seed for the RNG, which is unique to this wallet instance
        let bytes = self.private_spend_key.as_scalar().as_bytes();
        let hashed = blake2::Blake2b512::digest(bytes);
        let mut seed = [0; 32];
        seed.copy_from_slice(&hashed[..32]);
        ChaCha20Rng::from_seed(seed)
    }
}
