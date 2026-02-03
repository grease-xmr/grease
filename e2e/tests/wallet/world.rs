use cucumber::World;
use e2e::user::{create_users, User};
use e2e::{MoneroNode, MoneroNodeConfig, NodeStatus};
use log::*;
use monero_address::MoneroAddress;
use std::collections::HashMap;

/// Wrapper around MultisigWallet that implements Debug
pub struct MultisigWalletWrapper(pub wallet::MultisigWallet);

impl std::fmt::Debug for MultisigWalletWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MultisigWallet").field("address", &self.0.address().to_string()).finish()
    }
}

#[derive(Debug, World)]
pub struct WalletWorld {
    pub monero_node: Option<MoneroNode>,
    pub users: HashMap<String, User>,
    /// Multisig wallets keyed by user name
    pub multisig_wallets: HashMap<String, MultisigWalletWrapper>,
    /// Pending preprocess data keyed by user name
    pub pending_preprocess: HashMap<String, Vec<u8>>,
    /// Pending signature shares keyed by user name (serialized as bytes)
    pub pending_shares: HashMap<String, Vec<u8>>,
    /// Last error message for error handling tests
    pub last_error: Option<String>,
    /// Stored preprocess data for comparison tests
    pub stored_preprocess: Option<Vec<u8>>,
    /// Stored signature share for replay attack tests
    pub stored_share: Option<Vec<u8>>,
}

impl Default for WalletWorld {
    fn default() -> Self {
        Self {
            monero_node: None,
            users: create_users(),
            multisig_wallets: HashMap::new(),
            pending_preprocess: HashMap::new(),
            pending_shares: HashMap::new(),
            last_error: None,
            stored_preprocess: None,
            stored_share: None,
        }
    }
}

impl WalletWorld {
    pub async fn start_node(&mut self) {
        if self.monero_node.is_none() {
            info!("Loading env vars from .env.cucumber");
            dotenvy::from_filename_override(".env.cucumber").ok();
            info!("Starting monerod...");
            let config = MoneroNodeConfig::from_env();
            let monero_node = MoneroNode::start(config).await;
            self.monero_node = Some(monero_node);
            info!("Node started successfully");
        } else {
            info!("Monero node is already running");
        }
    }

    #[allow(dead_code)]
    pub async fn node_status(&self) -> NodeStatus {
        match &self.monero_node {
            Some(node) => node.status().await,
            None => NodeStatus::NotRunning,
        }
    }

    pub fn address_for(&self, user: &str) -> Option<MoneroAddress> {
        self.users.get(user).map(|u| u.address().clone())
    }
}
