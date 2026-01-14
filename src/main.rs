use dotenvy::dotenv;
use status_panel::{agent, comms, utils};

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing::info;

/// Application version from Cargo.toml
const VERSION: &str = env!("CARGO_PKG_VERSION");
const PKG_NAME: &str = env!("CARGO_PKG_NAME");

/// Print startup banner with version and system info
fn print_banner() {
    let rust_version = rustc_version_runtime::version();
    let build_profile = if cfg!(debug_assertions) { "debug" } else { "release" };
    let docker_feature = if cfg!(feature = "docker") { "enabled" } else { "disabled" };
    
    eprintln!();
    eprintln!("╔══════════════════════════════════════════════════════════╗");
    eprintln!("║          Status Panel (TryDirect Agent)                  ║");
    eprintln!("╠══════════════════════════════════════════════════════════╣");
    eprintln!("║  Version:      {:<43}║", VERSION);
    eprintln!("║  Package:      {:<43}║", PKG_NAME);
    eprintln!("║  Rust:         {:<43}║", rust_version);
    eprintln!("║  Build:        {:<43}║", build_profile);
    eprintln!("║  Docker:       {:<43}║", docker_feature);
    eprintln!("║  PID:          {:<43}║", std::process::id());
    eprintln!("╚══════════════════════════════════════════════════════════╝");
    eprintln!();
}

#[derive(Parser)]
#[command(name = "status", version, about = "Status Panel (TryDirect Agent)")]
struct AppCli {
    /// Run in daemon mode (background)
    #[arg(long)]
    daemon: bool,

    /// Config file path
    #[arg(short, long, default_value = "config.json", global = true)]
    config: String,

    /// Enable compose-agent mode (handles Docker Compose operations)
    #[arg(long)]
    compose_mode: bool,

    /// Subcommands
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Start HTTP server (local API)
    Serve {
        #[arg(long, default_value_t = 5000)]
        port: u16,
        /// Enable UI with HTML templates
        #[arg(long, default_value_t = false)]
        with_ui: bool,
    },
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
    // Load environment variables from .env if present
    let _ = dotenv();
    utils::logging::init();
    
    // Show startup banner
    print_banner();

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
            if args.compose_mode {
                info!("Starting compose-agent daemon mode");
                // Set CONTROL_PLANE environment variable for identification
                std::env::set_var("CONTROL_PLANE", "compose_agent");
            } else {
                info!("Starting status-panel daemon mode");
                std::env::set_var("CONTROL_PLANE", "status_panel");
            }
            agent::daemon::run(args.config).await?;
        }
    }

    Ok(())
}
