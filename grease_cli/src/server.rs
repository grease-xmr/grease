use crate::config::GlobalOptions;
use crate::interactive::InteractiveApp;
use libgrease::crypto::traits::PublicKey;
use log::*;

pub const APP_NAME: &str = env!("CARGO_PKG_NAME");

/// Starts the peer-to-peer payment channel server and runs the interactive application.
pub async fn start<P: PublicKey + 'static>(config: GlobalOptions) -> Result<(), anyhow::Error> {
    info!("Starting interactive server");
    run_interactive(config).await;
    info!("Server has shut down.");
    Ok(())
}

async fn run_interactive(global_options: GlobalOptions) {
    let mut app = match InteractiveApp::new(global_options) {
        Ok(app) => app,
        Err(err) => {
            eprintln!("** Error ** \n {err}");
            return;
        }
    };
    let result = app.run().await;
    match app.save_channels().await {
        Ok(_) => info!("Channels saved."),
        Err(e) => error!("Error saving channels: {}", e),
    }
    match result {
        Ok(_) => println!("Bye!"),
        Err(e) => error!("Session ended with error: {}", e),
    }
}
