mod wallet;

use crate::wallet::WalletWorld;
use cucumber::{codegen::LocalBoxFuture, event::ScenarioFinished, gherkin, writer, World};
use e2e::NodeStatus;
use futures_util::FutureExt;
use log::*;
use tokio::runtime::Runtime;

fn main() {
    dotenvy::from_filename(".env.cucumber").ok();
    env_logger::init();
    let sys = Runtime::new().unwrap();
    sys.block_on(
        WalletWorld::cucumber()
            .max_concurrent_scenarios(1) // Run scenarios sequentially to avoid node conflicts
            .with_writer(writer::Libtest::or_basic())
            .after(|_f, _r, scenario, ev, w| post_test_hook(scenario, ev, w))
            .run_and_exit("tests/features/multisig_wallet.feature"),
    );
    info!("Tests complete");
}

fn post_test_hook<'a>(
    scenario: &'a gherkin::Scenario,
    _ev: &'a ScenarioFinished,
    world: Option<&'a mut WalletWorld>,
) -> LocalBoxFuture<'a, ()> {
    let fut = async move {
        debug!("After-scenario hook running for \"{}\"", scenario.name);
        if let Some(world) = world {
            if let Some(node) = &mut world.monero_node {
                let status = node.status().await;
                debug!("Node status: {:?}", status);
                match status {
                    NodeStatus::Running => {
                        warn!("Node is still running after \"{}\", killing it now...", scenario.name);
                        node.kill().await.expect("Failed to stop the Monero node");
                    }
                    _ => debug!("Node was already dead for scenario \"{}\"", scenario.name),
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
    };
    fut.boxed_local()
}
