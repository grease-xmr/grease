pub mod common;
pub mod errors;
pub mod helpers;
pub mod multisig_wallet;
/// Boundary checks against a real regtest `monerod`. All `#[ignore]`d — they are not part of the default gate.
#[cfg(test)]
mod regtest_tests;
pub mod transaction_monitor;
pub mod utils;
pub mod wallet;
pub mod watch_only;

use monero_daemon_rpc::MoneroDaemon;
use monero_interface::InterfaceError;
use monero_simple_request_rpc::SimpleRequestTransport;

/// The daemon connection grease talks to.
///
/// monero-oxide split the old `SimpleRequestRpc` into a transport and the daemon that speaks over it, and the
/// capability traits (`ProvidesBlockchain`, `ProvidesDecoys`, `PublishTransaction`, …) are implemented on the
/// daemon. This alias is the one name the rest of the crate needs.
pub type MoneroRpc = MoneroDaemon<SimpleRequestTransport>;

pub async fn connect_to_rpc(rpc_server: impl Into<String>) -> Result<MoneroRpc, InterfaceError> {
    SimpleRequestTransport::new(rpc_server.into()).await
}
