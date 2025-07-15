use anyhow::anyhow;
use log::*;
use monero_rpc::RpcError;
use monero_simple_request_rpc::SimpleRequestRpc;
use std::fmt::{Display, Formatter};
use std::process::ExitStatus;
use std::sync::Arc;
use tokio::process::Command;
use tokio::select;
use tokio::sync::mpsc::Sender;
use tokio::sync::{mpsc, RwLock};

const LOCALNET_CONF: [&str; 13] = [
    "--regtest",
    "--non-interactive",
    "--no-igd",
    "--offline",
    "--hide-my-port",
    "--p2p-bind-ip=127.0.0.1",
    "--p2p-bind-port=25000",
    "--zmq-rpc-bind-port=26000",
    "--rpc-bind-port=27000",
    "--allow-local-ip",
    "--rpc-ssl=disabled",
    "--fixed-difficulty=10",
    "--disable-rpc-ban",
];

/// A driver for `monerod` that allows for starting and stopping a Monero node instance.
///
/// It is primarily intended to be used in end-to-end tests where a Monero node is required.
#[derive(Debug)]
pub struct MoneroNode {
    /// The process that is running the monerod instance.
    sender: Sender<DaemonCommand>,
    status: Arc<RwLock<NodeStatus>>,
}

impl MoneroNode {
    /// Start a new `monerod` instance.
    pub async fn start(config: MoneroNodeConfig) -> Self {
        let (tx, mut rx) = mpsc::channel(1);
        let status = Arc::new(RwLock::new(NodeStatus::NotRunning));
        let inner_status = status.clone();
        let fut = async move {
            info!("Starting Monero daemon");
            let mut command = Command::new(&config.path);
            command
                .args(LOCALNET_CONF)
                .arg(format!("--data-dir={}", &config.data_dir))
                .arg(format!("--log-level={}", config.log_level));
            // Spawn the process
            let mut child = command.spawn().map_err(|e| anyhow!("cannot spawn monero daemon: {e}"))?;
            let mut status = inner_status.write().await;
            *status = NodeStatus::Running;
            drop(status);
            let exit_status = select! {
                // Wait for the process to exit
                result = child.wait() => {
                    info!("Monero daemon process has exited normally");
                    match result {
                        Ok(status) => Ok(NodeStatus::Exited(status)),
                        Err(e) => Err(anyhow!("Monero daemon process failed: {e}"))
                    }
                },
                // Handle commands from the sender
                cmd = rx.recv() => match cmd {
                    Some(DaemonCommand::Stop) => {
                        info!("Killing Monero daemon");
                        match child.kill().await {
                            Ok(()) => Ok(NodeStatus::Killed),
                            Err(e) => Err(anyhow!("Failed to kill Monero daemon: {}", e)),
                        }
                    },
                    None => {
                        warn!("Channel is closed, killing Monero daemon process");
                        match child.kill().await {
                            Ok(()) => Ok(NodeStatus::Killed),
                            Err(e) => Err(anyhow!("Failed to kill Monero daemon: {}", e)),
                        }
                    },
                },
            }?;
            let mut status = inner_status.write().await;
            *status = exit_status;
            info!("Monero daemon terminated");
            Ok::<NodeStatus, anyhow::Error>(exit_status)
        };
        tokio::spawn(fut);
        tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
        Self { sender: tx, status }
    }

    /// Return an RPC client instance for this node
    pub async fn rpc_client(&self) -> Result<SimpleRequestRpc, RpcError> {
        let rpc = SimpleRequestRpc::new("http://127.0.0.1:27000".into()).await?;
        Ok(rpc)
    }

    pub async fn status(&self) -> NodeStatus {
        *self.status.read().await
    }

    /// Force stop the Monero node.
    pub async fn kill(&mut self) -> Result<(), anyhow::Error> {
        if let Err(e) = self.sender.send(DaemonCommand::Stop).await {
            warn!("Failed to send stop command to Monero daemon: {}", e);
        }
        // Wait for the status to be updated
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        Ok(())
    }
}

pub struct MoneroNodeConfig {
    /// The path to the `monerod` binary.
    pub path: String,
    /// The directory where the Monero node data will be stored.
    pub data_dir: String,
    /// The log level for the Monero node. See Monero documentation for log levels.
    pub log_level: u8,
}

impl MoneroNodeConfig {
    pub fn from_env() -> Self {
        let path = std::env::var("MONEROD_PATH").unwrap_or_else(|_| "monerod".to_string());
        let data_dir = std::env::var("MONEROD_DATA_PATH").unwrap_or_else(|_| "./testnet".to_string());
        let log_level = std::env::var("MONEROD_LOG_LEVEL").ok().and_then(|s| s.parse::<u8>().ok()).unwrap_or(0);
        Self { path, data_dir, log_level }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum NodeStatus {
    NotRunning,
    Running,
    Exited(ExitStatus),
    Killed,
}

impl Display for NodeStatus {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            NodeStatus::NotRunning => write!(f, "not running"),
            NodeStatus::Running => write!(f, "running"),
            NodeStatus::Exited(status) if status.success() => write!(f, "exited normally"),
            NodeStatus::Exited(status) => write!(f, "exited with error: {status}"),
            NodeStatus::Killed => write!(f, "killed"),
        }
    }
}

pub enum DaemonCommand {
    Stop,
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn default_monero_node_config() {
        let config = MoneroNodeConfig::from_env();
        assert_eq!(config.path, "monerod");
        assert_eq!(config.data_dir, "./testnet");
        assert_eq!(config.log_level, 0);
    }

    #[test]
    fn monero_node_config_from_env() {
        dotenvy::from_filename(".env.test").ok();
        let config = MoneroNodeConfig::from_env();
        assert_eq!(config.path, "/path/to/monerod");
        assert_eq!(config.data_dir, "/path/to/blockchain_data");
        assert_eq!(config.log_level, 3);
    }
}
