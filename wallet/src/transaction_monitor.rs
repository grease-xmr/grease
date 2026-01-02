use crate::connect_to_rpc;
use crate::errors::WalletError;
use crate::watch_only::WatchOnlyWallet;
use libgrease::amount::MoneroAmount;
use libgrease::cryptography::keys::{Curve25519PublicKey, Curve25519Secret};
use libgrease::monero::data_objects::{TransactionId, TransactionRecord};
use libgrease::monero::watcher::MonitorTransactions;
use log::*;
use monero_rpc::Rpc;
use std::fmt::Debug;
use std::time::Duration;

#[derive(Clone)]
pub struct TransactionMonitor {
    pub rpc_address: String,
}

impl Debug for TransactionMonitor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TransactionMonitor({})", self.rpc_address)
    }
}

impl TransactionMonitor {
    pub fn new(rpc_address: String) -> Self {
        Self { rpc_address }
    }

    pub fn rpc_address(&self) -> &str {
        &self.rpc_address
    }
}

impl MonitorTransactions for TransactionMonitor {
    type Error = WalletError;
    async fn register_watcher<Func>(
        &self,
        channel_name: String,
        private_view_key: Curve25519Secret,
        public_spend_key: Curve25519PublicKey,
        birthday: Option<u64>,
        poll_interval: Duration,
        callback: Func,
    ) -> Result<(), Self::Error>
    where
        Func: Fn(TransactionRecord) -> () + Send + 'static,
    {
        info!(
            "Registering transaction watcher for channel {channel_name} at address: {}",
            self.rpc_address
        );
        let rpc = connect_to_rpc(&self.rpc_address).await?;
        let height = rpc.get_height().await? as u64;
        let mut wallet = WatchOnlyWallet::new(rpc, private_view_key, public_spend_key, birthday)?;
        info!("Watch-only wallet created with birthday {birthday:?}. Current height is {height}");
        let mut interval = tokio::time::interval(poll_interval);
        let _handle = tokio::spawn(async move {
            let mut start_height = birthday.map(|b| height.min(b)).unwrap_or(height);
            loop {
                interval.tick().await;
                let current_height = wallet.get_height().await.expect("Failed to get blockchain height");
                debug!("Scanning for funding transaction in block range {start_height}..<{current_height}");
                if let Ok(c) = wallet.scan(Some(start_height - 5), Some(current_height)).await {
                    if c > 0 {
                        break;
                    }
                    start_height = current_height;
                }
            }
            let output = wallet.outputs().first().expect("No outputs").clone();
            let amount = MoneroAmount::from(output.commitment().amount);
            let id = hex::encode(output.transaction());
            let serialized = output.serialize();
            let record = TransactionRecord { channel_name, amount, transaction_id: TransactionId { id }, serialized };
            info!("Transaction detected: {:?}", record.transaction_id);
            callback(record);
        });
        Ok(())
    }
}
