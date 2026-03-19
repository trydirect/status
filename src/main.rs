use dotenvy::dotenv;
use status_panel::{agent, commands, comms, monitoring, utils};

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
    eprintln!("  Status Panel                                                                            ");
    eprintln!("═══════════════════════════════════════════════════════════");
    eprintln!("  Version:         {}", VERSION);
    eprintln!("  Package:         {}", PKG_NAME);
    eprintln!("  Rust:            {}", rust_version);
    eprintln!("  Build:           {}", build_profile);
    eprintln!("  Docker:          {}", docker_feature);
    eprintln!("  PID:             {}", std::process::id());
    eprintln!("  Mode:            {}", mode);
    eprintln!("  Dashboard URL:   {}", dashboard_url);
    eprintln!("  Base URL:        {}", base_url);
    eprintln!("  Vault URL:       {}", vault_url);
    eprintln!("  Agent ID:        {}", agent_id);
    eprintln!("  Stacker/Auth:    {}", stacker_status);
    eprintln!("  Debug Mode:      {}", debug_mode);
    eprintln!("═══════════════════════════════════════════════════════════");
    eprintln!();
}

#[derive(Parser)]
#[command(name = "status", version, about = "")]
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
    /// Start a stopped container
    #[cfg(feature = "docker")]
    Start { name: String },
    /// Pause container
    #[cfg(feature = "docker")]
    Pause { name: String },
    /// Check container health
    #[cfg(feature = "docker")]
    Health {
        /// Container name (omit for all containers)
        name: Option<String>,
    },
    /// Fetch container logs
    #[cfg(feature = "docker")]
    Logs {
        /// Container name
        name: String,
        /// Number of log lines to show
        #[arg(short = 'n', long, default_value_t = 100)]
        lines: u32,
    },
    /// Print system metrics (CPU, memory, disk)
    Metrics {
        /// Output as JSON
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Self-update management
    Update {
        #[command(subcommand)]
        action: UpdateAction,
    },
    /// Register this agent with Stacker Server using a purchase token
    Register {
        /// Purchase token from marketplace
        #[arg(long)]
        purchase_token: String,
        /// Stack template ID
        #[arg(long)]
        stack_id: String,
        /// Stacker Server URL (default: from DASHBOARD_URL env or https://stacker.try.direct)
        #[arg(long)]
        server: Option<String>,
    },
}

#[derive(Subcommand)]
enum UpdateAction {
    /// Check for available updates
    Check,
    /// Download and verify the latest update (deploy separately)
    Apply {
        /// Target version (default: latest)
        #[arg(long)]
        version: Option<String>,
    },
    /// Rollback to the previous version
    Rollback,
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
        Some(Commands::Start { name }) => agent::docker::start(&name).await?,
        #[cfg(feature = "docker")]
        Some(Commands::Pause { name }) => agent::docker::pause(&name).await?,
        #[cfg(feature = "docker")]
        Some(Commands::Health { name }) => {
            let all_health = agent::docker::list_container_health().await?;
            if let Some(container) = name {
                let normalized = container.trim_start_matches('/');
                let filtered: Vec<_> = all_health
                    .into_iter()
                    .filter(|h| h.name == normalized)
                    .collect();
                println!("{}", serde_json::to_string_pretty(&filtered)?);
            } else {
                println!("{}", serde_json::to_string_pretty(&all_health)?);
            }
        }
        #[cfg(feature = "docker")]
        Some(Commands::Logs { name, lines }) => {
            let logs = agent::docker::get_container_logs(&name, &lines.to_string()).await?;
            print!("{}", logs);
        }
        Some(Commands::Metrics { json }) => {
            let collector = monitoring::MetricsCollector::new();
            let snapshot = collector.snapshot().await;
            if json {
                println!("{}", serde_json::to_string_pretty(&snapshot)?);
            } else {
                println!("CPU Usage:    {:.1}%", snapshot.cpu_usage_pct);
                println!(
                    "Memory:       {} / {} MB ({:.1}%)",
                    snapshot.memory_used_bytes / 1_048_576,
                    snapshot.memory_total_bytes / 1_048_576,
                    if snapshot.memory_total_bytes > 0 {
                        (snapshot.memory_used_bytes as f64 / snapshot.memory_total_bytes as f64)
                            * 100.0
                    } else {
                        0.0
                    }
                );
                println!(
                    "Disk:         {} / {} GB ({:.1}%)",
                    snapshot.disk_used_bytes / 1_073_741_824,
                    snapshot.disk_total_bytes / 1_073_741_824,
                    if snapshot.disk_total_bytes > 0 {
                        (snapshot.disk_used_bytes as f64 / snapshot.disk_total_bytes as f64) * 100.0
                    } else {
                        0.0
                    }
                );
                println!("Disk Usage:   {:.1}%", snapshot.disk_used_pct);
            }
        }
        Some(Commands::Update { action }) => match action {
            UpdateAction::Check => {
                println!("Current version: {}", VERSION);
                match commands::check_remote_version().await? {
                    Some(remote) => {
                        println!("Latest version:  {}", remote.version);
                        if remote.version != VERSION {
                            println!("Update available!");
                        } else {
                            println!("Already up to date.");
                        }
                    }
                    None => {
                        println!("Could not check for updates (UPDATE_SERVER_URL not set).");
                    }
                }
            }
            UpdateAction::Apply { version } => {
                println!("Starting update...");
                let jobs = commands::UpdateJobs::default();
                let job_id = commands::start_update_job(jobs.clone(), version).await?;
                println!("Update job started: {}", job_id);
                // Poll until complete
                loop {
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                    if let Some(status) = commands::get_update_status(jobs.clone(), &job_id).await {
                        match status.phase {
                            commands::UpdatePhase::Completed => {
                                println!("Update downloaded and verified successfully.");
                                println!(
                                    "Use the update deployment API endpoint (or dashboard) to apply the update."
                                );
                                break;
                            }
                            commands::UpdatePhase::Failed(ref msg) => {
                                eprintln!("Update failed: {}", msg);
                                std::process::exit(1);
                            }
                            _ => continue,
                        }
                    }
                }
            }
            UpdateAction::Rollback => {
                let manifest = commands::load_manifest().await?;
                if manifest.entries.is_empty() {
                    println!("No rollback entries found.");
                } else {
                    let latest = &manifest.entries[manifest.entries.len() - 1];
                    println!("Rolling back to backup: {}", latest.backup_path);
                    commands::rollback_latest().await?;
                    println!("Rollback complete.");
                }
            }
        },
        Some(Commands::Register {
            purchase_token,
            stack_id,
            server,
        }) => {
            let dashboard_url = server.unwrap_or_else(|| {
                std::env::var("DASHBOARD_URL")
                    .unwrap_or_else(|_| "https://stacker.try.direct".to_string())
            });
            match agent::registration::register_with_stacker(
                &dashboard_url,
                &purchase_token,
                &stack_id,
            )
            .await
            {
                Ok(reg) => {
                    println!("Registered successfully!");
                    println!("Agent ID:         {}", reg.agent_id);
                    println!("Deployment Hash:  {}", reg.deployment_hash);
                    if let Some(url) = &reg.dashboard_url {
                        println!("Dashboard URL:    {}", url);
                    }
                    let save_path = std::path::Path::new("/etc/status-panel/registration.json");
                    if let Err(e) = agent::registration::save_registration(save_path, &reg) {
                        eprintln!(
                            "Warning: could not save registration to {}: {}",
                            save_path.display(),
                            e
                        );
                        eprintln!(
                            "You may need to run with elevated permissions or save manually."
                        );
                    } else {
                        println!("Config saved to:  {}", save_path.display());
                    }
                }
                Err(e) => {
                    eprintln!("Registration failed: {}", e);
                    std::process::exit(1);
                }
            }
        }
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
