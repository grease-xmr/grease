use cucumber::World;
use e2e::user::{create_users, User};
use e2e::{GreaseInfra, MoneroNode, MoneroNodeConfig, NodeStatus, MONEROD_RPC};
use log::*;
use monero_address::MoneroAddress;
use std::collections::HashMap;

#[derive(Debug, World)]
pub struct GreaseWorld {
    pub monero_node: Option<MoneroNode>,
    pub users: HashMap<String, User>,
    pub servers: HashMap<String, GreaseInfra>,
    pub current_channel: Option<String>,
}

impl Default for GreaseWorld {
    fn default() -> Self {
        Self { monero_node: None, users: create_users().unwrap(), servers: HashMap::new(), current_channel: None }
    }
}

impl GreaseWorld {
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

    pub async fn node_status(&self) -> NodeStatus {
        match &self.monero_node {
            Some(node) => node.status().await,
            None => NodeStatus::NotRunning,
        }
    }

    pub fn address_for(&self, user: &str) -> Option<MoneroAddress> {
        self.users.get(user).map(|u| u.address().clone())
    }

    pub async fn start_server(&mut self, client_name: &str) {
        info!("Starting client: {}", client_name);
        let user = self.users.get(client_name).expect("User not found in the world");
        let config = user.config.clone();
        let address = config.server_address.clone().expect("Server address is not set in user config");
        debug!("{client_name} config: {config:?}");
        let id = user.identity.clone();
        let mut server = GreaseInfra::new(id, config, MONEROD_RPC).expect("Failed to create Grease server");
        info!("Starting server...");
        server.server.start_listening(address).await.unwrap();
        self.servers.insert(client_name.to_string(), server);
        info!("Client {} started successfully", client_name);
    }
}
