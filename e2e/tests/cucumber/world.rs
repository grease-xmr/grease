use cucumber::World;
use e2e::{MoneroNode, MoneroNodeConfig, NodeStatus};
use log::info;

#[derive(Debug, World)]
pub struct GreaseWorld {
    pub monero_node: Option<MoneroNode>,
}

impl Default for GreaseWorld {
    fn default() -> Self {
        Self { monero_node: None }
    }
}

impl GreaseWorld {
    pub async fn start_node(&mut self) {
        if self.monero_node.is_none() {
            let _ = env_logger::try_init().ok();
            info!("Loading env vars from .env.cucumber.env");
            dotenvy::from_filename_override(".env.cucumber.env").ok();
            info!("Starting monerod...");
            let config = MoneroNodeConfig::from_env();
            let monero_node = MoneroNode::start(config).await;
            self.monero_node = Some(monero_node);
            info!("Node started successfully");
        } else {
            info!("Monero node is already running");
        }
    }

    pub async fn node_status(&self) -> NodeStatus {
        match &self.monero_node {
            Some(node) => node.status().await,
            None => NodeStatus::NotRunning,
        }
    }
}

impl GreaseWorld {}
