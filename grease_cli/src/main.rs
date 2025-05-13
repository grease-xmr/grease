use clap::Parser;
use grease_cli::config::{CliCommand, CliOptions, GlobalOptions};
use grease_cli::id_management::exec_id_command;
use grease_cli::launch_app::start;
use grease_cli::other_commands::print_random_keypair;
use libgrease::crypto::keys::Curve25519PublicKey;

#[tokio::main]
/// Entry point for the CLI application.
///
/// Initializes logging, parses command-line arguments, loads configuration, and executes the specified command. Exits the process with an error message if configuration loading or command execution fails.
async fn main() {
    env_logger::init();
    let options: CliOptions = CliOptions::parse();
    let config = match GlobalOptions::load_config(options.config_file) {
        Ok(config) => config,
        Err(err) => {
            eprintln!("** Error in configuration file** \n {err}");
            std::process::exit(1);
        }
    };

    let result = match options.command {
        CliCommand::Id(id_command) => exec_id_command(id_command, config),
        CliCommand::Serve => start(config).await,
        CliCommand::Keypair => print_random_keypair(),
    };

    match result {
        Ok(()) => {
            println!("Bye :)")
        }
        Err(err) => {
            eprintln!("** Error ** \n {err}");
            std::process::exit(1);
        }
    }
}
