use crate::amount::MoneroAmount;
use crate::cryptography::keys::{Curve25519PublicKey, Curve25519Secret};
use crate::monero::data_objects::{TransactionId, TransactionRecord};
use std::cell::RefCell;
use std::collections::HashMap;
use std::future::Future;
use std::time::Duration;
use thiserror::Error;

pub trait MonitorTransactions {
    type Error: std::error::Error;
    /// Register a callback to be called when the funding transaction is mined on the blockchain. When a funding
    /// transaction is detected, call `client.notify_tx_mined(tx_id)` to notify the client.
    fn register_watcher<Func>(
        &self,
        channel_name: String,
        private_view_key: Curve25519Secret,
        public_spend_key: Curve25519PublicKey,
        birthday: Option<u64>,
        poll_interval: Duration,
        callback: Func,
    ) -> impl Future<Output = Result<(), Self::Error>>
    where
        Func: Fn(TransactionRecord) + Send + 'static;
}

pub struct MockWatcher {
    watchers: RefCell<HashMap<String, Box<dyn Fn(TransactionRecord)>>>,
}

impl Default for MockWatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl MockWatcher {
    pub fn new() -> Self {
        Self { watchers: RefCell::new(HashMap::new()) }
    }

    pub fn add_watcher<Func>(&self, channel_name: String, callback: Func)
    where
        Func: Fn(TransactionRecord) + 'static,
    {
        let mut watchers = self.watchers.borrow_mut();
        watchers.insert(channel_name, Box::new(callback));
    }

    pub async fn trigger(&self, channel_name: &str, amt: MoneroAmount) {
        let watchers = self.watchers.borrow();
        if let Some(callback) = watchers.get(channel_name) {
            let record = TransactionRecord {
                channel_name: channel_name.to_string(),
                transaction_id: TransactionId::new(channel_name),
                amount: amt,
                serialized: vec![],
            };
            callback(record);
        }
    }
}

#[derive(Debug, Error)]
#[error("MockWatcher error: {0}")]
pub struct MockWatcherError(String);

impl MonitorTransactions for MockWatcher {
    type Error = MockWatcherError;

    async fn register_watcher<Func>(
        &self,
        channel: String,
        _: Curve25519Secret,
        _: Curve25519PublicKey,
        _: Option<u64>,
        _: Duration,
        callback: Func,
    ) -> Result<(), Self::Error>
    where
        Func: Fn(TransactionRecord) + 'static,
    {
        let boxed = Box::new(callback);
        self.add_watcher(channel, boxed);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::amount::MoneroAmount;
    use crate::cryptography::keys::PublicKey;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    #[test]
    fn test_mock_watcher() {
        let watcher = MockWatcher::new();
        let called = Arc::new(AtomicBool::new(false));
        let cc = Arc::clone(&called);
        let (k, pk) = Curve25519PublicKey::keypair(&mut rand_core::OsRng);
        futures::executor::block_on(watcher.register_watcher(
            "TestChannel".to_string(),
            k,
            pk,
            None,
            Duration::from_secs(10),
            move |record: TransactionRecord| {
                assert_eq!(record.channel_name, "TestChannel");
                cc.store(true, Ordering::SeqCst);
            },
        ))
        .unwrap();
        let amount = MoneroAmount::from_piconero(1000000); // 0.001 XMR
        futures::executor::block_on(watcher.trigger("TestChannel", amount));

        assert!(called.load(Ordering::SeqCst))
    }
}
