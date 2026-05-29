use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "stacker-cli",
    version = env!("CARGO_PKG_VERSION"),
    about = "Stacker multi-tool CLI",
    subcommand_required = false,
    arg_required_else_help = false
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
enum Commands {
    AppClient {
        #[command(subcommand)]
        command: AppClientCommands,
    },
    Debug {
        #[command(subcommand)]
        command: DebugCommands,
    },
    MQ {
        #[command(subcommand)]
        command: AppMqCommands,
    },
    Agent {
        #[command(subcommand)]
        command: AgentCommands,
    },
    /// Stacker CLI — deploy apps from a stacker.yml config
    Stacker {
        #[command(subcommand)]
        command: StackerCommands,
    },
}

#[derive(Debug, Subcommand)]
enum AgentCommands {
    RotateToken {
        #[arg(long)]
        deployment_hash: String,
        #[arg(long)]
        new_token: String,
    },
}

#[derive(Debug, Subcommand)]
enum AppClientCommands {
    New {
        #[arg(long)]
        user_id: i32,
    },
}

#[derive(Debug, Subcommand)]
enum DebugCommands {
    Json {
        #[arg(long)]
        line: usize,
        #[arg(long)]
        column: usize,
        #[arg(long)]
        payload: String,
    },
    Casbin {
        #[arg(long)]
        action: String,
        #[arg(long)]
        path: String,
        #[arg(long)]
        subject: String,
    },
    Dockerhub {
        #[arg(long)]
        json: String,
    },
}

#[derive(Debug, Subcommand)]
enum AppMqCommands {
    Listen {},
}

#[derive(Debug, Subcommand)]
enum StackerCommands {
    /// Authenticate with the TryDirect platform
    Login {
        #[arg(long)]
        org: Option<String>,
        #[arg(long)]
        domain: Option<String>,
        /// User Service auth URL (or set STACKER_AUTH_URL)
        #[arg(long = "auth-url")]
        auth_url: Option<String>,
        /// Stacker API base URL (or set STACKER_URL)
        #[arg(long = "server-url", visible_alias = "api-url")]
        server_url: Option<String>,
    },
    /// Show the saved login and current project's recorded deploy identity
    Whoami {},
    /// Initialize a new stacker project (stacker.yml + Dockerfile)
    Init {
        #[arg(long, value_name = "TYPE")]
        app_type: Option<String>,
        #[arg(long)]
        with_proxy: bool,
        #[arg(long)]
        with_ai: bool,
        #[arg(long)]
        with_cloud: bool,
        /// AI provider: openai, anthropic, ollama, custom (default: ollama)
        #[arg(long, value_name = "PROVIDER")]
        ai_provider: Option<String>,
        /// AI model name (e.g. gpt-4o, claude-sonnet-4-20250514, llama3)
        #[arg(long, value_name = "MODEL")]
        ai_model: Option<String>,
        /// AI API key (or set OPENAI_API_KEY / ANTHROPIC_API_KEY env var)
        #[arg(long, value_name = "KEY")]
        ai_api_key: Option<String>,
    },
    /// Build & deploy the stack
    Deploy {
        #[arg(long, value_name = "TARGET")]
        target: Option<String>,
        #[arg(long, value_name = "FILE")]
        file: Option<String>,
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        force_rebuild: bool,
        /// Project name on the Stacker server
        #[arg(long, value_name = "NAME")]
        project: Option<String>,
        /// Deployment environment/profile to use
        #[arg(long = "env", visible_alias = "environment", value_name = "NAME")]
        environment: Option<String>,
        /// Name of saved cloud credential to reuse
        #[arg(long, value_name = "KEY_NAME")]
        key: Option<String>,
        /// ID of saved cloud credential to reuse
        #[arg(long, value_name = "CLOUD_ID")]
        key_id: Option<i32>,
        /// Name of saved server to reuse
        #[arg(long, value_name = "SERVER_NAME")]
        server: Option<String>,
    },
    /// Attach this directory to an existing deployment from the dashboard
    Connect {
        /// Handoff token or full handoff URL copied from the dashboard
        #[arg(long, value_name = "TOKEN_OR_URL")]
        handoff: String,
    },
    /// Show container logs
    Logs {
        #[arg(long)]
        service: Option<String>,
        #[arg(long, short)]
        follow: bool,
        #[arg(long)]
        tail: Option<u32>,
        #[arg(long)]
        since: Option<String>,
    },
    /// Show deployment status
    Status {
        #[arg(long)]
        json: bool,
        #[arg(long)]
        watch: bool,
    },
    /// Tear down the deployed stack
    Destroy {
        #[arg(long)]
        volumes: bool,
        #[arg(long, short = 'y')]
        confirm: bool,
    },
    /// Roll back a marketplace deployment to a prior template version
    Rollback {
        #[arg(long, value_name = "VERSION")]
        version: String,
        #[arg(long, short = 'y')]
        confirm: bool,
    },
    /// Configuration management
    Config {
        #[command(subcommand)]
        command: StackerConfigCommands,
    },
    /// AI-assisted operations — run without a subcommand to start interactive chat
    Ai {
        #[command(subcommand)]
        command: Option<StackerAiCommands>,
        /// Enable write mode: AI may create/edit files in `.stacker/` and
        /// `stacker.yml`. Applies to both interactive chat and `ask`.
        #[arg(long, global = true)]
        write: bool,
    },
    /// Reverse-proxy management
    Proxy {
        #[command(subcommand)]
        command: StackerProxyCommands,
    },
    /// Self-update
    Update {
        #[arg(long)]
        channel: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum StackerConfigCommands {
    /// Validate stacker.yml
    Validate {
        #[arg(long, value_name = "FILE")]
        file: Option<String>,
    },
    /// Show resolved configuration
    Show {
        #[arg(long, value_name = "FILE")]
        file: Option<String>,
        /// Show paths, hash/version metadata, and contributing layers without values
        #[arg(long)]
        resolved: bool,
    },
    /// Print a full commented `stacker.yml` reference example
    Example,
    /// Interactively fix missing required config fields
    Fix {
        #[arg(long, value_name = "FILE")]
        file: Option<String>,
        #[arg(long, default_value_t = true)]
        interactive: bool,
    },
    /// Persist deployment lock into stacker.yml (writes deploy.server from last deploy)
    Lock {
        #[arg(long, value_name = "FILE")]
        file: Option<String>,
    },
    /// Remove deploy.server section from stacker.yml (allows fresh cloud provision)
    Unlock {
        #[arg(long, value_name = "FILE")]
        file: Option<String>,
    },
    /// Guided setup helpers
    Setup {
        #[command(subcommand)]
        command: StackerConfigSetupCommands,
    },
}

#[derive(Debug, Subcommand)]
enum StackerConfigSetupCommands {
    /// Configure cloud deployment defaults in stacker.yml
    Cloud {
        #[arg(long, value_name = "FILE")]
        file: Option<String>,
    },
    /// Configure AI defaults in stacker.yml
    Ai {
        #[arg(long, value_name = "FILE")]
        file: Option<String>,
        /// AI provider: openai, anthropic, ollama, custom
        #[arg(long, value_name = "PROVIDER")]
        provider: Option<String>,
        /// AI endpoint, e.g. http://localhost:11434 for Ollama
        #[arg(long, value_name = "URL")]
        endpoint: Option<String>,
        /// AI model name, e.g. llama3.1
        #[arg(long, value_name = "MODEL")]
        model: Option<String>,
        /// AI request timeout in seconds
        #[arg(long, value_name = "SECONDS")]
        timeout: Option<u64>,
        /// AI task name. Repeat or use comma-separated values.
        #[arg(long = "task", value_name = "TASK")]
        tasks: Vec<String>,
    },
    /// Advanced/debug: generate remote orchestrator payload and wire stacker.yml
    RemotePayload {
        #[arg(long, value_name = "FILE")]
        file: Option<String>,
        #[arg(long, value_name = "OUT")]
        out: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum StackerAiCommands {
    /// Ask the AI a question about your stack
    Ask {
        question: String,
        #[arg(long)]
        context: Option<String>,
        #[arg(long)]
        configure: bool,
        /// Enable agentic mode: the AI may call write_file / read_file tools to
        /// directly modify project files. Requires a tool-capable model
        /// (Ollama: llama3.1 / qwen2.5-coder; OpenAI: any).
        #[arg(long)]
        write: bool,
    },
}

#[derive(Debug, Subcommand)]
enum StackerProxyCommands {
    /// Add a reverse-proxy entry for a domain
    Add {
        domain: String,
        #[arg(long)]
        upstream: Option<String>,
        #[arg(long, num_args = 0..=1, default_missing_value = "auto")]
        ssl: Option<String>,
        #[arg(long)]
        force: bool,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        deployment: Option<String>,
    },
    /// Detect existing reverse-proxy containers
    Detect {
        /// Output as JSON
        #[arg(long)]
        json: bool,
        /// Target a specific deployment by hash
        #[arg(long)]
        deployment: Option<String>,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    let Some(command) = cli.command else {
        println!("stacker-cli {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    };

    get_command(command)?.call()
}

fn get_command(
    command: Commands,
) -> Result<Box<dyn stacker::console::commands::CallableTrait>, String> {
    match command {
        Commands::AppClient { command } => match command {
            AppClientCommands::New { user_id } => Ok(Box::new(
                stacker::console::commands::appclient::NewCommand::new(user_id),
            )),
        },
        Commands::Debug { command } => match command {
            DebugCommands::Json {
                line,
                column,
                payload,
            } => Ok(Box::new(
                stacker::console::commands::debug::JsonCommand::new(line, column, payload),
            )),
            DebugCommands::Casbin {
                action,
                path,
                subject,
            } => Ok(Box::new(
                stacker::console::commands::debug::CasbinCommand::new(action, path, subject),
            )),
            DebugCommands::Dockerhub { json } => Ok(Box::new(
                stacker::console::commands::debug::DockerhubCommand::new(json),
            )),
        },
        Commands::MQ { command } => match command {
            AppMqCommands::Listen {} => Ok(Box::new(
                stacker::console::commands::mq::ListenCommand::new(),
            )),
        },
        Commands::Agent { command } => match command {
            AgentCommands::RotateToken {
                deployment_hash,
                new_token,
            } => Ok(Box::new(
                stacker::console::commands::agent::RotateTokenCommand::new(
                    deployment_hash,
                    new_token,
                ),
            )),
        },
        Commands::Stacker { command } => match command {
            StackerCommands::Login {
                org,
                domain,
                auth_url,
                server_url,
            } => Ok(Box::new(
                stacker::console::commands::cli::login::LoginCommand::new(
                    org,
                    domain,
                    auth_url,
                    server_url,
                ),
            )),
            StackerCommands::Whoami {} => Ok(Box::new(
                stacker::console::commands::cli::whoami::WhoamiCommand::new(),
            )),
            StackerCommands::Init {
                app_type,
                with_proxy,
                with_ai,
                with_cloud,
                ai_provider,
                ai_model,
                ai_api_key,
            } => Ok(Box::new(
                stacker::console::commands::cli::init::InitCommand::new(
                    app_type, with_proxy, with_ai, with_cloud,
                )
                .with_ai_options(ai_provider, ai_model, ai_api_key),
            )),
            StackerCommands::Deploy {
                target,
                file,
                dry_run,
                force_rebuild,
                project,
                environment,
                key,
                key_id,
                server,
            } => Ok(Box::new(
                stacker::console::commands::cli::deploy::DeployCommand::new(
                    target,
                    file,
                    dry_run,
                    force_rebuild,
                )
                .with_remote_overrides(project, key, server)
                .with_environment(environment)
                .with_key_id(key_id),
            )),
            StackerCommands::Connect { handoff } => Ok(Box::new(
                stacker::console::commands::cli::connect::ConnectCommand::new(handoff),
            )),
            StackerCommands::Logs {
                service,
                follow,
                tail,
                since,
            } => Ok(Box::new(
                stacker::console::commands::cli::logs::LogsCommand::new(
                    service, follow, tail, since,
                ),
            )),
            StackerCommands::Status { json, watch } => Ok(Box::new(
                stacker::console::commands::cli::status::StatusCommand::new(json, watch),
            )),
            StackerCommands::Destroy { volumes, confirm } => Ok(Box::new(
                stacker::console::commands::cli::destroy::DestroyCommand::new(volumes, confirm),
            )),
            StackerCommands::Rollback { version, confirm } => Ok(Box::new(
                stacker::console::commands::cli::rollback::RollbackCommand::new(version, confirm),
            )),
            StackerCommands::Config { command: cfg_cmd } => match cfg_cmd {
                StackerConfigCommands::Validate { file } => Ok(Box::new(
                    stacker::console::commands::cli::config::ConfigValidateCommand::new(file),
                )),
                StackerConfigCommands::Show { file, resolved } => Ok(Box::new(
                    stacker::console::commands::cli::config::ConfigShowCommand::new(file, resolved),
                )),
                StackerConfigCommands::Example => Ok(Box::new(
                    stacker::console::commands::cli::config::ConfigExampleCommand::new(),
                )),
                StackerConfigCommands::Fix { file, interactive } => Ok(Box::new(
                    stacker::console::commands::cli::config::ConfigFixCommand::new(file, interactive),
                )),
                StackerConfigCommands::Lock { file } => Ok(Box::new(
                    stacker::console::commands::cli::config::ConfigLockCommand::new(file),
                )),
                StackerConfigCommands::Unlock { file } => Ok(Box::new(
                    stacker::console::commands::cli::config::ConfigUnlockCommand::new(file),
                )),
                StackerConfigCommands::Setup { command } => match command {
                    StackerConfigSetupCommands::Cloud { file } => Ok(Box::new(
                        stacker::console::commands::cli::config::ConfigSetupCloudCommand::new(file),
                    )),
                    StackerConfigSetupCommands::Ai {
                        file,
                        provider,
                        endpoint,
                        model,
                        timeout,
                        tasks,
                    } => Ok(Box::new(
                        stacker::console::commands::cli::config::ConfigSetupAiCommand::new(
                            file, provider, endpoint, model, timeout, tasks,
                        ),
                    )),
                    StackerConfigSetupCommands::RemotePayload { file, out } => Ok(Box::new(
                        stacker::console::commands::cli::config::ConfigSetupRemotePayloadCommand::new(file, out),
                    )),
                },
            },
            StackerCommands::Ai { command: ai_cmd, write } => match ai_cmd {
                None => Ok(Box::new(
                    stacker::console::commands::cli::ai::AiChatCommand::new(write),
                )),
                Some(StackerAiCommands::Ask {
                    question,
                    context,
                    configure,
                    write: ask_write,
                }) => Ok(Box::new(
                    stacker::console::commands::cli::ai::AiAskCommand::new(question, context)
                        .with_configure(configure)
                        .with_write(write || ask_write),
                )),
            },
            StackerCommands::Proxy {
                command: proxy_cmd,
            } => match proxy_cmd {
                StackerProxyCommands::Add {
                    domain,
                    upstream,
                    ssl,
                    force,
                    json,
                    deployment,
                } => Ok(Box::new(
                    stacker::console::commands::cli::proxy::ProxyAddCommand::new(
                        domain, upstream, ssl, force, json, deployment,
                    ),
                )),
                StackerProxyCommands::Detect { json, deployment } => Ok(Box::new(
                    stacker::console::commands::cli::proxy::ProxyDetectCommand::new(json, deployment),
                )),
            },
            StackerCommands::Update { channel } => Ok(Box::new(
                stacker::console::commands::cli::update::UpdateCommand::new(channel),
            )),
        },
    }
}
