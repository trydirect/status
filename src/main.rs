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
    let build_profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    let docker_feature = if cfg!(feature = "docker") {
        "enabled"
    } else {
        "disabled"
    };

    // Gather runtime/config info
    let dashboard_url =
        std::env::var("DASHBOARD_URL").unwrap_or_else(|_| "http://localhost:5000".to_string());
    let vault_url =
        std::env::var("VAULT_ADDRESS").unwrap_or_else(|_| "(not configured)".to_string());
    let agent_token = std::env::var("AGENT_TOKEN").unwrap_or_default();
    let vault_enabled = std::env::var("VAULT_ADDRESS").is_ok();
    let agent_id = std::env::var("AGENT_ID").unwrap_or_else(|_| "(not set)".to_string());
    let control_plane =
        std::env::var("CONTROL_PLANE").unwrap_or_else(|_| "status_panel".to_string());
    let compose_mode =
        std::env::var("COMPOSE_AGENT_ENABLED").unwrap_or_else(|_| "false".to_string());
    let debug_mode = if cfg!(debug_assertions) {
        "ENABLED"
    } else {
        "disabled"
    };

    // Try to get base_url from domain in config.json, fallback to dashboard_url
    let base_url = match std::fs::read_to_string("config.json") {
        Ok(cfg) => {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&cfg) {
                json.get("domain")
                    .and_then(|d| d.as_str())
                    .map(|s| format!("https://{}", s))
                    .unwrap_or_else(|| dashboard_url.clone())
            } else {
                dashboard_url.clone()
            }
        }
        Err(_) => dashboard_url.clone(),
    };

    let stacker_status = if !agent_token.is_empty() {
        if vault_enabled {
            "Vault+Token: OK"
        } else {
            "Token: OK (Vault: not configured)"
        }
    } else if vault_enabled {
        "Vault: configured, but AGENT_TOKEN missing"
    } else {
        "No agent token (auth will fail)"
    };

    let mode = if std::env::args().any(|a| a == "serve") {
        if std::env::args().any(|a| a == "--with-ui") {
            "API+UI Server"
        } else {
            "API Server"
        }
    } else if std::env::args().any(|a| a == "--daemon") {
        "Daemon (background)"
    } else if control_plane == "compose_agent" || compose_mode == "true" {
        "Compose Agent Daemon"
    } else {
        "Status Panel Daemon"
    };

    eprintln!();
    eprintln!("╔════════════════════════════════════════════════════════════════════════════════════════════╗");
    eprintln!("║  Status Panel (TryDirect Agent)                                                         ║");
    eprintln!("╠════════════════════════════════════════════════════════════════════════════════════════════╣");
    eprintln!("║  Version:         {:<66}║", VERSION);
    eprintln!("║  Package:         {:<66}║", PKG_NAME);
    eprintln!("║  Rust:            {:<66}║", rust_version);
    eprintln!("║  Build:           {:<66}║", build_profile);
    eprintln!("║  Docker:          {:<66}║", docker_feature);
    eprintln!("║  PID:             {:<66}║", std::process::id());
    eprintln!("║  Mode:            {:<66}║", mode);
    eprintln!("║  Dashboard URL:   {:<66}║", dashboard_url);
    eprintln!("║  Base URL:        {:<66}║", base_url);
    eprintln!("║  Vault URL:       {:<66}║", vault_url);
    eprintln!("║  Agent ID:        {:<66}║", agent_id);
    eprintln!("║  Stacker/Auth:    {:<66}║", stacker_status);
    eprintln!("║  Debug Mode:      {:<66}║", debug_mode);
    eprintln!("╚════════════════════════════════════════════════════════════════════════════════════════════╝");
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
