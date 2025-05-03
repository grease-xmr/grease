use clap::Parser;
use grease_cli::channel_management::exec_channel_command;
use grease_cli::config::{CliCommand, Config};
use grease_cli::id_management::exec_id_command;
use grease_cli::server::start_server;

#[tokio::main]
async fn main() {
    env_logger::init();
    let config: Config = Config::parse();
    let (global_options, command) = config.to_parts();

    let result = match command {
        CliCommand::Id(id_command) => exec_id_command(id_command, global_options),
        CliCommand::Serve(serve_command) => start_server(serve_command, global_options).await,
        CliCommand::Channel(channel_cmd) => exec_channel_command(channel_cmd, global_options).await,
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
