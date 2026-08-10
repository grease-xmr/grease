use crate::amount::MoneroAmount;
use crate::cryptography::keys::{Curve25519PublicKey, Curve25519Secret, PublicKey};
use crate::wallet::common::{block_count, scan_wallet};
use crate::wallet::errors::WalletError;
use crate::wallet::MoneroRpc;
use log::*;
use monero_interface::prelude::*;
use monero_oxide::block::Block;
use monero_oxide::ed25519::Point as MoneroPoint;
use monero_wallet::address::{AddressType, MoneroAddress, Network};
use monero_wallet::WalletOutput;

#[derive(Clone, Debug)]
pub struct WatchOnlyWallet {
    rpc: MoneroRpc,
    private_view_key: Curve25519Secret,
    public_spend_key: Curve25519PublicKey,
    birthday: u64,
    next_scan_start: Option<u64>,
    known_outputs: Vec<WalletOutput>,
}

impl WatchOnlyWallet {
    pub fn remove_outputs(&mut self, spent: Vec<WalletOutput>) {
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
        rpc: MoneroRpc,
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
        let view_key = MoneroPoint::from(self.public_view_key().as_point().0);
        let spend_key = MoneroPoint::from(self.public_spend_key().as_point().0);
        MoneroAddress::new(Network::Mainnet, AddressType::Legacy, spend_key, view_key)
    }

    /// The number of blocks on the chain — one past the tip's number, which is what the scan loops and the
    /// birthday treat as "the height to start from next".
    pub async fn get_height(&self) -> Result<u64, WalletError> {
        block_count(&self.rpc).await
    }

    pub async fn get_block_by_number(&self, block_num: u64) -> Result<Block, WalletError> {
        Ok(self.rpc.block_by_number(block_num as usize).await?)
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

    pub async fn scan(&mut self, start: Option<u64>, end: Option<u64>) -> Result<usize, WalletError> {
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

    pub fn rpc(&self) -> &MoneroRpc {
        &self.rpc
    }
}
