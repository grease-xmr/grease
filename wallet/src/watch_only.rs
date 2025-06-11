use crate::{AddressType, MoneroAddress, Network, WalletError};
use libgrease::crypto::keys::{Curve25519PublicKey, Curve25519Secret, PublicKey};
use log::*;
use monero_rpc::{Rpc, RpcError, ScannableBlock};
use monero_serai::block::Block;
use monero_simple_request_rpc::SimpleRequestRpc;
use monero_wallet::{Scanner, ViewPair, WalletOutput};

#[derive(Clone, Debug)]
pub struct WatchOnlyWallet {
    rpc: SimpleRequestRpc,
    private_view_key: Curve25519Secret,
    public_spend_key: Curve25519PublicKey,
    birthday: u64,
    known_outputs: Vec<WalletOutput>,
}

impl WatchOnlyWallet {
    pub fn new(
        rpc: SimpleRequestRpc,
        private_view_key: Curve25519Secret,
        public_spend_key: Curve25519PublicKey,
        birthday: Option<u64>,
    ) -> Result<Self, WalletError> {
        Ok(WatchOnlyWallet {
            rpc,
            private_view_key,
            public_spend_key,
            birthday: birthday.unwrap_or_default(),
            known_outputs: Vec::new(),
        })
    }

    pub fn private_view_key(&self) -> &Curve25519Secret {
        &self.private_view_key
    }

    pub fn public_spend_key(&self) -> &Curve25519PublicKey {
        &self.public_spend_key
    }

    pub fn public_view_key(&self) -> Curve25519PublicKey {
        Curve25519PublicKey::from_secret(&self.private_view_key)
    }

    pub fn address(&self) -> MoneroAddress {
        let view_key = self.public_view_key().as_point().clone();
        let spend_key = self.public_spend_key().as_point().clone();
        MoneroAddress::new(Network::Mainnet, AddressType::Legacy, spend_key, view_key)
    }

    pub async fn get_height(&self) -> Result<u64, RpcError> {
        self.rpc.get_height().await.map(|height| height as u64)
    }

    pub async fn get_block_by_number(&self, block_num: u64) -> Result<Block, RpcError> {
        self.rpc.get_block_by_number(block_num as usize).await
    }

    async fn get_scannable_block(&self, block: Block) -> Result<ScannableBlock, RpcError> {
        self.rpc.get_scannable_block(block).await
    }

    pub async fn scan(&mut self, start: Option<u64>, end: Option<u64>) -> Result<usize, RpcError> {
        let k = self.private_view_key.as_zscalar().clone();
        let p = self.public_spend_key.as_point().clone();
        let pair = ViewPair::new(p, k).map_err(|e| RpcError::InternalError(e.to_string()))?;
        let mut scanner = Scanner::new(pair);
        let height = match end {
            Some(h) => h,
            None => self.get_height().await?,
        };
        let mut scanned = 0usize;
        let mut found = 0usize;
        let start = start.unwrap_or(self.birthday);
        for block_num in start..height {
            let block = self.get_block_by_number(block_num).await?;
            let scannable = self.get_scannable_block(block).await?;
            let outputs = scanner.scan(scannable).map_err(|e| RpcError::InternalError(e.to_string()))?;
            scanned += 1;
            let outputs = outputs.ignore_additional_timelock();
            if !outputs.is_empty() {
                debug!("Scanned {} outputs for block {block_num}", outputs.len());
                found += outputs.len();
                self.known_outputs.extend(outputs);
            }
        }
        debug!("Scanned {scanned} blocks. {found} outputs found");
        Ok(found)
    }

    pub fn outputs(&self) -> &[WalletOutput] {
        &self.known_outputs
    }

    pub fn rpc(&self) -> &SimpleRequestRpc {
        &self.rpc
    }
}
