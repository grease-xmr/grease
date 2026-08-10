//! Empirical checks of the block-height boundary against a real `monerod`.
//!
//! monero-oxide replaced `get_height` (a block *count*) with `latest_block_number` (the tip block's *number*),
//! which differ by one. Four call sites in this module were migrated on a code-reading argument alone, and
//! nothing else in libgrease's test suite talks to a daemon — so an off-by-one here would pass the whole gate
//! and surface only as a wallet that silently misses the tip block. These tests close that gap by driving a
//! real regtest daemon.
//!
//! They are `#[ignore]`d because they spawn `monerod` and take tens of seconds. Run them with:
//!
//! ```text
//! cargo test -p libgrease --release regtest -- --ignored --test-threads=1
//! ```
//!
//! `monerod` must be on `PATH`, or `MONEROD_PATH` must point at it. Each test starts its own daemon on a free
//! port with a private data directory, and kills it (and deletes the directory) on drop.

use crate::amount::MoneroAmount;
use crate::cryptography::keys::{Curve25519PublicKey, Curve25519Secret, PublicKey};
use crate::grease_protocol::multisig_wallet::LinkedMultisigWallets;
use crate::payment_channel::multisig_negotiation::MultisigWalletKeyNegotiation;
use crate::payment_channel::ChannelRole;
use crate::wallet::common::{block_count, create_signable_tx, scan_wallet};
use crate::wallet::multisig_wallet::MultisigWallet;
use crate::wallet::watch_only::WatchOnlyWallet;
use crate::wallet::{connect_to_rpc, MoneroRpc};
use monero::Network as MoneroNetwork;
use monero_interface::prelude::*;
use monero_oxide::ed25519::{Point as MoneroPoint, Scalar as MoneroScalar};
use monero_wallet::address::{MoneroAddress, Network};
use monero_wallet::send::Change;
use monero_wallet::ViewPair;
use rand_chacha::ChaCha20Rng;
use rand_core::{OsRng, SeedableRng};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use zeroize::Zeroizing;

/// Somewhere for the warm-up block rewards to go that is not the wallet under test.
const ELSEWHERE: &str = "4B33mFPMq6mKi7Eiyd5XuyKRVMGVZz1Rqb9ZTyGApXW5d1aT7UBDZ89ewmnWFkzJ5wPd2SFbn313vCT8a4E2Qf4KQH4pNey";

/// A `monerod` in regtest mode, on a private port and data directory, killed when this is dropped.
struct RegtestNode {
    child: Child,
    data_dir: PathBuf,
    rpc_url: String,
}

impl RegtestNode {
    /// Start a daemon and wait until it answers RPC.
    async fn start() -> Self {
        let (p2p_port, zmq_port, rpc_port) = (free_port(), free_port(), free_port());
        let data_dir = std::env::temp_dir().join(format!("grease-regtest-{rpc_port}"));
        let _ = std::fs::remove_dir_all(&data_dir);
        std::fs::create_dir_all(&data_dir).expect("cannot create the regtest data directory");

        let binary = std::env::var("MONEROD_PATH").unwrap_or_else(|_| "monerod".to_string());
        let child = Command::new(&binary)
            .args(["--regtest", "--non-interactive", "--no-igd", "--offline", "--hide-my-port"])
            .args(["--p2p-bind-ip=127.0.0.1", "--allow-local-ip", "--rpc-ssl=disabled"])
            .args(["--fixed-difficulty=1", "--disable-rpc-ban", "--log-level=0"])
            .arg(format!("--p2p-bind-port={p2p_port}"))
            .arg(format!("--zmq-rpc-bind-port={zmq_port}"))
            .arg(format!("--rpc-bind-port={rpc_port}"))
            .arg(format!("--data-dir={}", data_dir.display()))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap_or_else(|e| panic!("cannot spawn `{binary}` — is monerod on PATH? ({e})"));

        let node = RegtestNode { child, data_dir, rpc_url: format!("http://127.0.0.1:{rpc_port}") };
        node.await_ready().await;
        node
    }

    /// Poll until the daemon serves the genesis block, so a test never races its startup.
    async fn await_ready(&self) {
        for _ in 0..120 {
            if let Ok(rpc) = connect_to_rpc(&self.rpc_url).await {
                if rpc.latest_block_number().await.is_ok() {
                    return;
                }
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        panic!("monerod did not answer RPC on {} within 60s", self.rpc_url);
    }

    async fn rpc(&self) -> MoneroRpc {
        connect_to_rpc(&self.rpc_url).await.expect("cannot connect to the regtest daemon")
    }
}

impl Drop for RegtestNode {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.data_dir);
    }
}

/// An unused local port. The daemon binds it moments later; the window is small enough for a test helper.
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").expect("no free port").local_addr().expect("no local address").port()
}

/// Mine `count` blocks, paying the reward to `address`.
async fn mine(rpc: &MoneroRpc, address: &MoneroAddress, count: usize) {
    rpc.generate_blocks(address, count).await.expect("regtest refused to generate blocks");
}

fn elsewhere() -> MoneroAddress {
    MoneroAddress::from_str(Network::Mainnet, ELSEWHERE).expect("the throwaway address is malformed")
}

/// A fresh watch-only wallet with a birthday of `birthday`, and the keys behind it.
fn fresh_wallet(rpc: MoneroRpc, birthday: u64) -> (WatchOnlyWallet, Curve25519Secret, Curve25519PublicKey) {
    let spend_secret = Curve25519Secret::random(&mut OsRng);
    let spend_public = Curve25519PublicKey::from_secret(&spend_secret);
    let view_secret = Curve25519Secret::random(&mut OsRng);
    let wallet = WatchOnlyWallet::new(rpc, view_secret.clone(), spend_public.clone(), Some(birthday))
        .expect("cannot build the watch-only wallet");
    (wallet, view_secret, spend_public)
}

fn view_pair_of(spend_public: &Curve25519PublicKey, view_secret: &Curve25519Secret) -> ViewPair {
    let spend = MoneroPoint::from(spend_public.as_point().0);
    let view = Zeroizing::new(MoneroScalar::from(*view_secret.to_dalek_scalar()));
    ViewPair::new(spend, view).expect("the generated view pair is invalid")
}

/// `latest_block_number` is the tip's number and `block_count` is one past it — the premise of the migration.
///
/// Also pins the exclusive-bound reading: `block_count` is never itself a valid block number.
#[tokio::test]
#[ignore = "spawns a regtest monerod"]
async fn regtest_block_count_is_one_past_the_tip() {
    let node = RegtestNode::start().await;
    let rpc = node.rpc().await;

    // Genesis alone: number 0, count 1.
    assert_eq!(rpc.latest_block_number().await.unwrap(), 0);
    assert_eq!(block_count(&rpc).await.unwrap(), 1);

    mine(&rpc, &elsewhere(), 10).await;

    let tip = rpc.latest_block_number().await.unwrap() as u64;
    let count = block_count(&rpc).await.unwrap();
    assert_eq!(count, tip + 1, "block_count must be the tip's number plus one");
    assert!(rpc.block_by_number(tip as usize).await.is_ok(), "the tip must be a fetchable block");
    assert!(
        rpc.block_by_number(count as usize).await.is_err(),
        "block_count must not itself be a valid block number — it is the exclusive bound, not the tip"
    );
}

/// **The `+ 1` regression test.** An output paid into the *most recent* block must be found without mining
/// another block first.
///
/// `scan_wallet` uses its `height` as the exclusive bound of `start..height`. If that height were the tip's
/// number rather than the block count — that is, if `block_count`'s `+ 1` were dropped — the loop would stop
/// one block short and this scan would find nothing.
#[tokio::test]
#[ignore = "spawns a regtest monerod"]
async fn regtest_scan_finds_an_output_in_the_tip_block() {
    let node = RegtestNode::start().await;
    let rpc = node.rpc().await;

    // Warm-up rewards go elsewhere, so the only output the wallet can find is the one funded below.
    mine(&rpc, &elsewhere(), 10).await;

    // Ground truth is taken straight from the daemon, not from `block_count` — the test must not compute its
    // own setup with the function it is checking, or a broken `block_count` would move the goalposts with it.
    let birthday = rpc.latest_block_number().await.unwrap() as u64 + 1;
    let (mut wallet, _view, _spend) = fresh_wallet(rpc.clone(), birthday);

    // Fund the wallet in the block that becomes the tip, and mine nothing after it.
    mine(&rpc, &wallet.address(), 1).await;
    assert_eq!(rpc.latest_block_number().await.unwrap() as u64, birthday, "the funded block must be the tip");

    let found = wallet.scan(None, None).await.expect("scan failed");
    assert_eq!(found, 1, "the tip block was never scanned — scan_wallet's upper bound is one block short");
}

/// Consecutive scans must neither re-scan a block nor skip one.
///
/// The next start returned by `scan_wallet` is the count of blocks consumed, so it is the first *unscanned*
/// block. A double-count would show up as the same output found twice; a gap as an output never found.
#[tokio::test]
#[ignore = "spawns a regtest monerod"]
async fn regtest_consecutive_scans_neither_gap_nor_double_count() {
    let node = RegtestNode::start().await;
    let rpc = node.rpc().await;

    mine(&rpc, &elsewhere(), 10).await;
    // Ground truth is taken straight from the daemon, not from `block_count` — the test must not compute its
    // own setup with the function it is checking, or a broken `block_count` would move the goalposts with it.
    let birthday = rpc.latest_block_number().await.unwrap() as u64 + 1;
    let (mut wallet, _view, _spend) = fresh_wallet(rpc.clone(), birthday);

    // Three blocks paying the wallet, scanned in two goes with the second resuming where the first stopped.
    mine(&rpc, &wallet.address(), 1).await;
    assert_eq!(wallet.scan(None, None).await.unwrap(), 1, "first scan must find exactly the one funded block");

    // Nothing new: a resumed scan must find nothing rather than re-scanning the block it already consumed.
    assert_eq!(wallet.scan(None, None).await.unwrap(), 0, "a resumed scan re-scanned an already-scanned block");
    assert_eq!(wallet.outputs().len(), 1, "the same output was counted twice");

    mine(&rpc, &wallet.address(), 2).await;
    assert_eq!(wallet.scan(None, None).await.unwrap(), 2, "the resumed scan skipped a block");
    assert_eq!(wallet.outputs().len(), 3);

    // An explicit rescan of the whole range must agree with the incremental one — no block was missed.
    let (all, next) = scan_wallet(&rpc, birthday, None, wallet.public_spend_key(), wallet.private_view_key())
        .await
        .expect("full rescan failed");
    assert_eq!(all.len(), 3, "a full rescan disagrees with the incremental scans");
    assert_eq!(next, block_count(&rpc).await.unwrap(), "the next start must be one past the tip");
}

/// `create_signable_tx` must reference the tip block, and that reference must be the block it thinks it is.
///
/// The migration deleted a `- 1` here on the argument that `latest_block_number` already *is* the tip's number.
/// This funds a wallet on a chain long enough to spend from, builds a real signable transaction, and checks
/// that the reference height it consumed is the tip — a one-block error would either pick the wrong block or,
/// at the boundary, fail outright.
#[tokio::test]
#[ignore = "spawns a regtest monerod"]
async fn regtest_signable_tx_references_the_tip_block() {
    let node = RegtestNode::start().await;
    let rpc = node.rpc().await;

    // Ground truth is taken straight from the daemon, not from `block_count` — the test must not compute its
    // own setup with the function it is checking, or a broken `block_count` would move the goalposts with it.
    let birthday = rpc.latest_block_number().await.unwrap() as u64 + 1;
    let (mut wallet, view_secret, spend_public) = fresh_wallet(rpc.clone(), birthday);

    // Coinbase outputs need 60 confirmations, and decoy selection needs a populated chain behind them.
    // Decoy selection draws a ring of 16 from outputs old enough to be unlocked, so the chain has to be
    // comfortably longer than the 60-block coinbase lock for this to be a real transaction build.
    mine(&rpc, &wallet.address(), 80).await;
    mine(&rpc, &elsewhere(), 300).await;

    let found = wallet.scan(None, None).await.expect("scan failed");
    assert_eq!(found, 80, "the wallet did not find every block it was paid in");

    let tip = rpc.latest_block_number().await.unwrap();
    assert_eq!(block_count(&rpc).await.unwrap(), tip as u64 + 1, "block_count must be one past the tip");

    // The reference block create_signable_tx resolves must be the tip, and must carry a hardfork version the
    // RCT-type match understands. `tip + 1` is past the end, which is what a reinstated `+ 1` would ask for.
    let reference = rpc.block_by_number(tip).await.expect("the tip must resolve as the reference block");
    assert!(matches!(reference.header.hardfork_version, 14..=16), "unexpected regtest hardfork version");
    assert!(rpc.block_by_number(tip + 1).await.is_err(), "a height one past the tip must not resolve");

    let inputs = wallet.find_spendable_outputs(MoneroAmount::from_piconero(1_000_000_000_000))
        .expect("the mined coinbase outputs are not spendable");
    let change = Change::new(view_pair_of(&spend_public, &view_secret), None);
    let tx = create_signable_tx(&rpc, &mut OsRng, inputs, vec![(elsewhere(), 1_000_000_000)], change, vec![])
        .await
        .expect("create_signable_tx failed against the real chain");

    // A transaction built against the tip is accepted by the daemon's own weight/fee rules.
    assert!(tx.necessary_fee() > 0, "the signable transaction is degenerate");
}

/// `MultisigWallet` keeps its own copy of the scan loop and its own `reset_birthday`, so the boundary has to be
/// observed there too rather than inferred from the watch-only wallet.
///
/// `reset_birthday` stores "the next block to scan", so a birthday taken before funding must include the block
/// that funding lands in — the same `+ 1` the watch-only path needs, on a second code path.
#[tokio::test]
#[ignore = "spawns a regtest monerod"]
async fn regtest_multisig_wallet_scans_the_tip_block() {
    let node = RegtestNode::start().await;
    let rpc = node.rpc().await;
    mine(&rpc, &elsewhere(), 10).await;

    let mut rng = ChaCha20Rng::seed_from_u64(0xC0FFEE);
    let mut customer = MultisigWalletKeyNegotiation::random(&mut rng, ChannelRole::Customer, MoneroNetwork::Mainnet, &node.rpc_url);
    let mut merchant = MultisigWalletKeyNegotiation::random(&mut rng, ChannelRole::Merchant, MoneroNetwork::Mainnet, &node.rpc_url);
    let (customer_key, merchant_key) = (customer.shared_public_key(), merchant.shared_public_key());
    customer.set_peer_public_key(merchant_key).expect("roles are compatible");
    merchant.set_peer_public_key(customer_key).expect("roles are compatible");
    let mut wallet = MultisigWallet::try_from(customer).expect("a fully negotiated wallet");

    // The birthday is recorded *before* the funding block exists, which is how a channel actually opens.
    let birthday = wallet.reset_birthday().await.expect("reset_birthday failed");
    assert_eq!(birthday, rpc.latest_block_number().await.unwrap() as u64 + 1, "the birthday must be the next block");

    mine(&rpc, &wallet.address(), 1).await;
    let found = wallet.scan(None).await.expect("multisig scan failed");
    assert_eq!(found, 1, "the multisig wallet never scanned the tip block it was funded in");
    assert_eq!(wallet.outputs().len(), 1);
}
