mod agent;
mod comms;
mod security;
mod monitoring;
mod utils;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing::info;

#[derive(Parser)]
#[command(name = "status", version, about = "Status Panel (TryDirect Agent)")]
struct AppCli {
    /// Run in daemon mode (background)
    #[arg(long)]
    daemon: bool,

    /// Config file path
    #[arg(short, long, default_value = "config.json", global = true)]
    config: String,

    /// Subcommands
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Start HTTP server (local API)
    Serve {
        #[arg(long, default_value_t = 8080)]
        port: u16,        /// Enable UI with HTML templates
        #[arg(long, default_value_t = false)]
        with_ui: bool,    },
    /// Show Docker containers
    #[cfg(feature = "docker")]
    Containers,
    /// Restart container
    #[cfg(feature = "docker")]
    Restart { name: String },
    /// Stop container
    #[cfg(feature = "docker")]
    Stop { name: String },
    /// Pause container
    #[cfg(feature = "docker")]
    Pause { name: String },
}

fn run_daemon() -> Result<()> {
    use daemonize::Daemonize;
    let daemonize = Daemonize::new()
        .pid_file("status.pid")
        .working_directory(".")
        .umask(0o027)
        .privileged_action(|| {
            info!("daemon started");
        });

    daemonize.start().map_err(|e| anyhow::anyhow!(e))?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    utils::logging::init();

    let args = AppCli::parse();
    if args.daemon {
        run_daemon()?;
    }

    match args.command {
        Some(Commands::Serve { port, with_ui }) => {
            if with_ui {
                info!("Starting local API server with UI on port {port}");
            } else {
                info!("Starting local API server on port {port}");
            }
            let config = agent::config::Config::from_file(&args.config)?;
            comms::local_api::serve(config, port, with_ui).await?;
        }
        #[cfg(feature = "docker")]
        Some(Commands::Containers) => {
            let list = agent::docker::list_containers().await?;
            println!("{}", serde_json::to_string_pretty(&list)?);
        }
        #[cfg(feature = "docker")]
        Some(Commands::Restart { name }) => agent::docker::restart(&name).await?,
        #[cfg(feature = "docker")]
        Some(Commands::Stop { name }) => agent::docker::stop(&name).await?,
        #[cfg(feature = "docker")]
        Some(Commands::Pause { name }) => agent::docker::pause(&name).await?,
        None => {
            // Default: run the agent daemon
            agent::daemon::run(args.config).await?;
        }
    }

    Ok(())
}
