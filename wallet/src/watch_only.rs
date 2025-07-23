use crate::common::scan_wallet;
use crate::errors::WalletError;
use crate::{AddressType, MoneroAddress, Network};
use libgrease::amount::MoneroAmount;
use libgrease::crypto::keys::{Curve25519PublicKey, Curve25519Secret, PublicKey};
use log::debug;
use monero_rpc::{Rpc, RpcError};
use monero_serai::block::Block;
use monero_simple_request_rpc::SimpleRequestRpc;
use monero_wallet::WalletOutput;

#[derive(Clone, Debug)]
pub struct WatchOnlyWallet {
    rpc: SimpleRequestRpc,
    private_view_key: Curve25519Secret,
    public_spend_key: Curve25519PublicKey,
    birthday: u64,
    next_scan_start: Option<u64>,
    known_outputs: Vec<WalletOutput>,
}

impl WatchOnlyWallet {
    pub(crate) fn remove_outputs(&mut self, spent: Vec<WalletOutput>) {
        debug!("removing {} spent outputs from wallet", spent.len());
        spent.iter().for_each(|stxo| {
            if let Some(i) = self.known_outputs.iter().position(|o| o == stxo) {
                debug!("Removing spent output {} from wallet", stxo.index_on_blockchain());
                self.known_outputs.swap_remove(i);
            }
        })
    }
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
            next_scan_start: birthday,
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
        let view_key = self.public_view_key().as_point();
        let spend_key = self.public_spend_key().as_point();
        MoneroAddress::new(Network::Mainnet, AddressType::Legacy, spend_key, view_key)
    }

    pub async fn get_height(&self) -> Result<u64, RpcError> {
        self.rpc.get_height().await.map(|height| height as u64)
    }

    pub async fn get_block_by_number(&self, block_num: u64) -> Result<Block, RpcError> {
        self.rpc.get_block_by_number(block_num as usize).await
    }

    pub fn find_spendable_outputs(&self, min_amount: MoneroAmount) -> Result<Vec<WalletOutput>, WalletError> {
        if self.known_outputs.is_empty() {
            return Err(WalletError::InsufficientFunds);
        }
        let mut result = Vec::new();
        let mut total = 0;
        for output in &self.known_outputs {
            result.push(output.clone());
            total += output.commitment().amount;
            if total >= min_amount.to_piconero() {
                return Ok(result);
            }
        }
        Err(WalletError::InsufficientFunds)
    }

    pub async fn scan(&mut self, start: Option<u64>, end: Option<u64>) -> Result<usize, RpcError> {
        let start = start.unwrap_or(self.next_scan_start.unwrap_or(self.birthday));
        let (outputs, next_start) =
            scan_wallet(&self.rpc, start, end, &self.public_spend_key, &self.private_view_key).await?;
        let found = outputs.len();
        self.known_outputs.extend(outputs);
        self.next_scan_start = Some(next_start);
        Ok(found)
    }

    pub fn outputs(&self) -> &[WalletOutput] {
        &self.known_outputs
    }

    pub fn rpc(&self) -> &SimpleRequestRpc {
        &self.rpc
    }
}
