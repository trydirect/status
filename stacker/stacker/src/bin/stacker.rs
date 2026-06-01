//! Standalone `stacker` CLI binary.
//!
//! Exposes the Stacker CLI commands directly at the top level:
//!
//! ```text
//! stacker init
//! stacker deploy --target local
//! stacker status
//! stacker logs --follow
//! stacker destroy --confirm
//! ```
//!
//! Unlike the `console` binary (which nests these under `stacker` subcommand
//! alongside other admin tools), this binary is a lightweight entry point
//! designed for end-user distribution.

use clap::{Args, CommandFactory, Parser, Subcommand};
use stacker::console::commands::cli::secrets::RemoteSecretScope;

fn print_banner() {
    let version = env!("CARGO_PKG_VERSION");
    println!("============================================================");
    println!("stacker-cli v{}", version);
    println!("Stacker CLI - build, deploy, and manage application stacks");
    println!("============================================================");
    println!();
    println!("Getting started:");
    println!("  1) stacker-cli stacker login");
    println!("  2) stacker-cli stacker init --with-cloud");
    println!("  3) stacker-cli stacker deploy --target cloud");
    println!("  4) stacker-cli stacker status --watch");
    println!();
    println!("Run `stacker-cli --help` to see all commands and options.");
    println!();
}

#[derive(Parser, Debug)]
#[command(
    name = "stacker",
    version,
    about = "Deploy apps from a stacker.yml config",
    long_about = "Stacker CLI — build, deploy, and manage containerised applications\n\n\
        Create a stacker.yml configuration file, and Stacker will generate\n\
        Dockerfiles, docker-compose definitions, and deploy your stack locally\n\
        or to cloud providers with a single command.",
    subcommand_required = false,
    arg_required_else_help = false
)]
struct Cli {
    #[command(subcommand)]
    command: Option<StackerCommands>,
}

#[derive(Debug, Subcommand)]
enum StackerCommands {
    /// Authenticate with the TryDirect platform
    Login {
        /// Organisation slug (for multi-org accounts)
        #[arg(long)]
        org: Option<String>,
        /// Custom platform domain
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
    /// Initialize a new stacker project (generates stacker.yml + Dockerfile)
    Init {
        /// Application type: static, node, python, rust, go, php
        #[arg(long, value_name = "TYPE")]
        app_type: Option<String>,
        /// Include reverse-proxy configuration
        #[arg(long)]
        with_proxy: bool,
        /// Use AI to scan the project and generate a tailored stacker.yml
        #[arg(long)]
        with_ai: bool,
        /// Immediately run cloud setup wizard after init
        #[arg(long)]
        with_cloud: bool,
        /// Set the active deployment target: local, cloud, server
        #[arg(long, value_name = "TARGET")]
        target: Option<String>,
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
        /// Deployment target: local, cloud, server
        #[arg(long, value_name = "TARGET")]
        target: Option<String>,
        /// Deploy environment/profile, e.g. development, staging, production
        #[arg(long = "env", alias = "environment", value_name = "ENVIRONMENT")]
        environment: Option<String>,
        /// Path to stacker.yml (default: ./stacker.yml)
        #[arg(long, value_name = "FILE")]
        file: Option<String>,
        /// Show what would be deployed without executing
        #[arg(long)]
        dry_run: bool,
        /// Force rebuild of all containers
        #[arg(long)]
        force_rebuild: bool,
        /// Project name on the Stacker server (overrides project.identity in stacker.yml)
        #[arg(long, value_name = "NAME")]
        project: Option<String>,
        /// Name of saved cloud credential to reuse (overrides deploy.cloud.key in stacker.yml)
        #[arg(long, value_name = "KEY_NAME")]
        key: Option<String>,
        /// ID of saved cloud credential to reuse (from `stacker list clouds`)
        #[arg(long, value_name = "CLOUD_ID")]
        key_id: Option<i32>,
        /// Name of saved server to reuse (overrides deploy.cloud.server in stacker.yml)
        #[arg(long, value_name = "SERVER_NAME")]
        server: Option<String>,
        /// Watch deployment progress until complete (default for cloud deploys)
        #[arg(long)]
        watch: bool,
        /// Disable automatic progress watching after deploy
        #[arg(long)]
        no_watch: bool,
        /// Persist server details into stacker.yml after deploy (for redeploy)
        #[arg(long)]
        lock: bool,
        /// Skip server pre-check; force fresh cloud provision even if deploy.server exists
        #[arg(long)]
        force_new: bool,
        /// Container runtime: "runc" (default) or "kata" for hardware-isolated containers
        #[arg(long, value_name = "RUNTIME", default_value = "runc")]
        runtime: String,
        /// Print a read-only deployment plan instead of applying changes
        #[arg(long)]
        plan: bool,
        /// Revalidate and apply a previously generated deployment plan fingerprint
        #[arg(long, value_name = "FINGERPRINT", conflicts_with = "plan")]
        apply_plan: Option<String>,
    },
    /// Attach this directory to an existing deployment from the dashboard
    Connect {
        /// Handoff token or full handoff URL copied from the dashboard
        #[arg(long, value_name = "TOKEN_OR_URL")]
        handoff: String,
    },
    /// Submit current stack to the marketplace for review
    Submit {
        /// Path to stacker.yml (default: ./stacker.yml)
        #[arg(long, value_name = "FILE")]
        file: Option<String>,
        /// Stack version (default: from stacker.yml or "1.0.0")
        #[arg(long)]
        version: Option<String>,
        /// Short description for marketplace listing
        #[arg(long)]
        description: Option<String>,
        /// Category code (e.g. ai-agents, data-pipelines, saas-starter)
        #[arg(long)]
        category: Option<String>,
        /// Pricing: free, one_time, subscription (default: free)
        #[arg(long, value_name = "TYPE")]
        plan_type: Option<String>,
        /// Price amount (required if plan_type is not free)
        #[arg(long)]
        price: Option<f64>,
    },
    /// Show container logs
    Logs {
        /// Show logs for a specific service only
        #[arg(long)]
        service: Option<String>,
        /// Follow log output (stream)
        #[arg(long, short)]
        follow: bool,
        /// Number of lines to show from the end
        #[arg(long)]
        tail: Option<u32>,
        /// Show logs since timestamp (e.g. "2h", "2024-01-01")
        #[arg(long)]
        since: Option<String>,
    },
    /// Show deployment status
    Status {
        /// Output in JSON format
        #[arg(long)]
        json: bool,
        /// Watch for changes (refresh periodically)
        #[arg(long)]
        watch: bool,
    },
    /// Deployment inspection commands
    Deployment {
        #[command(subcommand)]
        command: DeploymentCommands,
    },
    /// Explain path and topology decisions
    Explain {
        #[command(subcommand)]
        command: ExplainCommands,
    },
    /// Tear down the deployed stack
    Destroy {
        /// Also remove named volumes
        #[arg(long)]
        volumes: bool,
        /// Skip confirmation prompt (required)
        #[arg(long, short = 'y')]
        confirm: bool,
    },
    /// Roll back a marketplace deployment to a prior template version
    Rollback {
        /// Marketplace template version to redeploy
        #[arg(long, value_name = "VERSION")]
        version: String,
        /// Skip confirmation prompt (required)
        #[arg(long, short = 'y')]
        confirm: bool,
    },
    /// Configuration management
    Config {
        #[command(subcommand)]
        command: ConfigCommands,
    },
    /// AI-assisted operations — run `stacker ai` for interactive chat
    Ai(AiArgs),
    /// Reverse-proxy management
    Proxy {
        #[command(subcommand)]
        command: ProxyCommands,
    },
    /// List resources (projects, servers, ssh-keys)
    List {
        #[command(subcommand)]
        command: ListCommands,
    },
    /// SSH key management (generate, show, upload, repair)
    #[command(long_about = "Manage Stacker server SSH keys.\n\n\
Cloud deploys automatically create a local backup SSH key under the Stacker config directory and authorize it on the deployed server when possible. The `generate` command manages the server-side Vault key; `inject` repairs a server by using an already-working local private key to add the Vault public key.")]
    #[command(name = "ssh-key")]
    SshKey {
        #[command(subcommand)]
        command: SshKeyCommands,
    },
    /// Service template management (add services to stacker.yml)
    Service {
        #[command(subcommand)]
        command: ServiceCommands,
    },
    /// Force-complete a stuck (paused/error) deployment
    Resolve {
        /// Skip confirmation prompt (required)
        #[arg(long, short = 'y')]
        confirm: bool,
        /// Force-complete even if the deployment is in_progress
        #[arg(long)]
        force: bool,
        /// Target a specific deployment by hash (e.g. deployment_ad479fdb-…); defaults to latest
        #[arg(long)]
        deployment: Option<String>,
    },
    /// Check for updates and self-update
    Update {
        /// Release channel: stable, beta
        #[arg(long)]
        channel: Option<String>,
    },
    /// Generate shell completion scripts
    Completion {
        /// Shell: bash, zsh, fish, elvish, powershell
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },
    /// Manage local .env secrets and remote Vault-backed secrets
    #[command(
        long_about = "Manage secrets in two modes:\n\
\n\
  Local mode (default)\n\
    Reads and writes a project .env file.\n\
\n\
  Remote mode\n\
    Uses the authenticated Stacker API to manage Vault-backed secrets for a\n\
    service or a server. Remote reads are metadata-only in v1 and never return\n\
    plaintext secret values.\n\
\n\
Use explicit --scope service or --scope server to activate remote mode.",
        after_help = "Examples:\n\
  Local .env secret:\n\
    stacker secrets set DB_PASSWORD=supersecret\n\
\n\
  Service secret for one app:\n\
    stacker secrets set S3_SECRET_KEY --scope service --project blog --service uploader --body supersecret\n\
\n\
  Server secret from a file:\n\
    stacker secrets set NPM_TOKEN --scope server --server-id 42 --body-file .npm-token\n\
\n\
  List remote metadata as JSON:\n\
    stacker secrets list --scope service --project blog --service uploader --json"
    )]
    Secrets {
        #[command(subcommand)]
        command: SecretsCommands,
    },
    /// CI/CD pipeline export and validation
    Ci {
        #[command(subcommand)]
        command: CiCommands,
    },
    /// Connect containerized apps with data pipes
    Pipe {
        #[command(subcommand)]
        command: PipeCommands,
    },
    /// Cloud provider operations
    Cloud {
        #[command(subcommand)]
        command: CloudCommands,
    },
    /// Status Panel agent control (health, logs, restart, deploy)
    Agent {
        #[command(subcommand)]
        command: AgentCommands,
    },
    /// Marketplace operations (submit, check status)
    Marketplace {
        #[command(subcommand)]
        command: MarketplaceCommands,
    },
    /// Switch or show the active deployment target (local, cloud, server)
    Target {
        /// Target to switch to: local, cloud, or server. Omit to show current.
        target: Option<String>,
    },
    /// Switch or show the active deploy environment/profile
    Env {
        /// Environment to switch to. Omit to show current.
        environment: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum CloudCommands {
    /// Configure cloud provider firewall rules without SSH
    Firewall {
        #[command(subcommand)]
        command: CloudFirewallCommands,
    },
}

#[derive(Debug, Subcommand)]
enum CloudFirewallCommands {
    /// Add cloud firewall rules
    Add {
        /// Server ID to configure
        #[arg(long)]
        server_id: Option<i32>,
        /// Public ports (open to all), comma-separated: "80/tcp,443/tcp,53/udp"
        #[arg(long, value_delimiter = ',')]
        public_ports: Vec<String>,
        /// Private ports, comma-separated: "5432/tcp:10.0.0.0/8"
        #[arg(long, value_delimiter = ',')]
        private_ports: Vec<String>,
        /// Validate and enqueue without applying provider changes
        #[arg(long)]
        dry_run: bool,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },
    /// Remove cloud firewall rules
    Remove {
        /// Server ID to configure
        #[arg(long)]
        server_id: Option<i32>,
        /// Public ports (open to all), comma-separated: "80/tcp,443/tcp,53/udp"
        #[arg(long, value_delimiter = ',')]
        public_ports: Vec<String>,
        /// Private ports, comma-separated: "5432/tcp:10.0.0.0/8"
        #[arg(long, value_delimiter = ',')]
        private_ports: Vec<String>,
        /// Validate and enqueue without applying provider changes
        #[arg(long)]
        dry_run: bool,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },
    /// List cloud firewall rules
    List {
        /// Server ID to inspect
        #[arg(long)]
        server_id: Option<i32>,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum MarketplaceCommands {
    /// Check submission status for your marketplace templates
    Status {
        /// Stack name to check (omit for all)
        name: Option<String>,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },
    /// Show review comments and history for a submission
    Logs {
        /// Stack name
        name: String,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },
    /// Submit current stack to the marketplace for review
    Submit {
        /// Path to stacker.yml (default: ./stacker.yml)
        #[arg(long, value_name = "FILE")]
        file: Option<String>,
        /// Stack version (default: from stacker.yml or "1.0.0")
        #[arg(long)]
        version: Option<String>,
        /// Short description for marketplace listing
        #[arg(long)]
        description: Option<String>,
        /// Category code (e.g. ai-agents, data-pipelines, saas-starter)
        #[arg(long)]
        category: Option<String>,
        /// Pricing: free, one_time, subscription (default: free)
        #[arg(long, value_name = "TYPE")]
        plan_type: Option<String>,
        /// Price amount (required if plan_type is not free)
        #[arg(long)]
        price: Option<f64>,
    },
}

#[derive(Debug, Subcommand)]
enum ListCommands {
    /// List all projects
    Projects {
        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },
    /// List deployments
    Deployments {
        /// Filter by project ID
        #[arg(long)]
        project: Option<i32>,
        /// Limit number of results
        #[arg(long)]
        limit: Option<i64>,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },
    /// List all servers
    Servers {
        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },
    /// List SSH keys (per-server key status)
    #[command(name = "ssh-keys")]
    SshKeys {
        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },
    /// List saved cloud credentials
    Clouds {
        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum SshKeyCommands {
    /// Generate a new SSH key pair for a server (stored in Vault)
    Generate {
        /// Server ID to generate the key for
        #[arg(long)]
        server_id: i32,
        /// Save private key to this file (if Vault storage fails)
        #[arg(long, value_name = "PATH")]
        save_to: Option<std::path::PathBuf>,
    },
    /// Show the public SSH key for a server
    Show {
        /// Server ID to show the key for
        #[arg(long)]
        server_id: i32,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },
    /// Upload an existing SSH key pair for a server
    Upload {
        /// Server ID to upload the key for
        #[arg(long)]
        server_id: i32,
        /// Path to public key file
        #[arg(long, value_name = "FILE")]
        public_key: std::path::PathBuf,
        /// Path to private key file
        #[arg(long, value_name = "FILE")]
        private_key: std::path::PathBuf,
    },
    /// Bootstrap the Vault-managed public key onto a server via an already-working SSH private key
    #[command(
        long_about = "Bootstrap the Vault-managed public key onto a server by logging in with an already-working SSH private key.\n\n\
This command does not install your local key onto the server. Instead, it uses --with-key as a bootstrap credential, connects to the server, and appends the Vault-stored public key to ~/.ssh/authorized_keys.\n\n\
Use this when Stacker already has a key for the server in Vault, but the server no longer trusts that key. If you want Stacker to use your local key pair, use `stacker ssh-key upload` instead."
    )]
    Inject {
        /// Server ID whose Vault public key should be injected
        #[arg(long)]
        server_id: i32,
        /// Path to a bootstrap private key that already grants SSH access to the server
        #[arg(long, value_name = "FILE")]
        with_key: std::path::PathBuf,
        /// SSH user on the remote server (default: root)
        #[arg(long)]
        user: Option<String>,
        /// SSH port override (default: server's stored port or 22)
        #[arg(long)]
        port: Option<u16>,
    },
}

#[derive(Debug, Subcommand)]
enum ServiceCommands {
    /// Add a service from the template catalog to stacker.yml (interactive picker when no name given)
    Add {
        /// Service name (e.g. postgres, redis, wordpress, mysql) — omit for interactive picker
        name: Option<String>,
        /// Path to stacker.yml (default: ./stacker.yml)
        #[arg(long, value_name = "FILE")]
        file: Option<String>,
    },
    /// Import custom services from a local Docker Compose file after a safety review
    Import {
        /// Target custom service name for a single selected service
        name: String,
        /// Local Docker Compose file to review and import
        #[arg(long, value_name = "PATH")]
        from_compose: Option<std::path::PathBuf>,
        /// Planned future source; currently returns a safe not-yet-implemented error
        #[arg(long, value_name = "OWNER/REPO")]
        from_github: Option<String>,
        /// Planned future source; currently returns a safe not-yet-implemented error
        #[arg(long, value_name = "URL")]
        from_url: Option<String>,
        /// Compose service name to import. Omit to import all image-backed services.
        #[arg(long, value_name = "COMPOSE_SERVICE")]
        service: Option<String>,
        /// Rename imported services as old=new. Repeat for multiple services.
        #[arg(long, value_name = "OLD=NEW")]
        rename: Vec<String>,
        /// Path to stacker.yml (default: ./stacker.yml)
        #[arg(long, value_name = "FILE")]
        file: Option<String>,
        /// Review only; do not write stacker.yml
        #[arg(long)]
        review: bool,
        /// Skip confirmation prompt and write after review
        #[arg(long, short = 'y')]
        yes: bool,
        /// Output structured JSON with secret-like environment values redacted
        #[arg(long)]
        json: bool,
    },
    /// Deploy/update a configured service through the remote app deploy path
    Deploy {
        /// Service name from stacker.yml to deploy
        name: String,
        /// Force recreate the remote container
        #[arg(long)]
        force: bool,
        /// Container runtime: "runc" (default) or "kata"
        #[arg(long, default_value = "runc")]
        runtime: String,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
        /// Deployment hash
        #[arg(long)]
        deployment: Option<String>,
        /// Deploy environment/profile, e.g. local, dev, prod
        #[arg(long = "env", alias = "environment", value_name = "ENVIRONMENT")]
        environment: Option<String>,
        /// Print a read-only deploy-app plan instead of applying changes
        #[arg(long)]
        plan: bool,
        /// Revalidate and apply a previously generated deploy-app plan fingerprint
        #[arg(long, value_name = "FINGERPRINT", conflicts_with = "plan")]
        apply_plan: Option<String>,
    },
    /// Remove a service from stacker.yml
    Remove {
        /// Service name to remove
        name: String,
        /// Path to stacker.yml (default: ./stacker.yml)
        #[arg(long, value_name = "FILE")]
        file: Option<String>,
    },
    /// List available service templates
    List {
        /// Also query the marketplace API for online templates
        #[arg(long)]
        online: bool,
    },
}

#[derive(Debug, Subcommand)]
enum DeploymentCommands {
    /// Show canonical deployment state
    State {
        /// Output in JSON format
        #[arg(long)]
        json: bool,
        /// Override deployment hash instead of using stacker.yml
        #[arg(long)]
        deployment: Option<String>,
    },
    /// Show structured deployment events
    Events {
        /// Output in JSON format
        #[arg(long)]
        json: bool,
        /// Override deployment hash instead of using stacker.yml
        #[arg(long)]
        deployment: Option<String>,
    },
    /// Preview or apply a deployment rollback
    Rollback {
        /// Roll back to `previous` or a specific marketplace template version
        #[arg(long, value_name = "TARGET")]
        to: String,
        /// Print a read-only rollback plan instead of applying it
        #[arg(long, conflicts_with = "apply_plan")]
        plan: bool,
        /// Revalidate and apply a previously generated rollback plan fingerprint
        #[arg(long, value_name = "FINGERPRINT", conflicts_with = "plan")]
        apply_plan: Option<String>,
        /// Override deployment hash instead of using stacker.yml
        #[arg(long)]
        deployment: Option<String>,
        /// Confirm rollback apply
        #[arg(long, short = 'y')]
        confirm: bool,
    },
}

#[derive(Debug, Subcommand)]
enum ExplainCommands {
    /// Explain env provenance for an app or service
    Env {
        /// App code or service name
        app: String,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },
    /// Explain compose/env topology for the current target
    Topology {
        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum ConfigCommands {
    /// Validate stacker.yml syntax and semantics
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
        /// Enable interactive prompts (default: true)
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
        command: ConfigSetupCommands,
    },
}

#[derive(Debug, Subcommand)]
enum ConfigSetupCommands {
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
enum SecretsCommands {
    /// Set or update a local .env secret or remote Vault-backed secret
    #[command(after_help = "Examples:\n\
  Local .env secret:\n\
    stacker secrets set DB_PASSWORD=supersecret\n\
\n\
  Remote deployable service/app target secret (project.identity from stacker.yml):\n\
    stacker secrets set S3_SECRET_KEY --service uploader --body supersecret\n\
\n\
  Use the target code listed by `stacker secrets apps` for --service.\n\
\n\
  Remote server secret from stdin:\n\
    cat token.txt | stacker secrets set NPM_TOKEN --scope server --server-id 42\n\
\n\
  Status Panel Nginx Proxy Manager credentials from a JSON file:\n\
    stacker secrets set npm_credentials --scope server --server-id 42 --body-file ./npm_credentials.json")]
    Set {
        /// Local mode: KEY=VALUE. Remote mode: secret name.
        input: String,
        /// Path to .env file (default: from stacker.yml env_file, or .env)
        #[arg(
            long,
            value_name = "FILE",
            conflicts_with_all = ["scope", "project", "service", "server_id", "body", "body_file"]
        )]
        file: Option<String>,
        /// Remote secret scope
        #[arg(long, value_enum)]
        scope: Option<RemoteSecretScope>,
        /// Project name or ID for service-scoped secrets (defaults to project.identity in stacker.yml)
        #[arg(long, value_name = "PROJECT")]
        project: Option<String>,
        /// Deployable service/app target code listed by `stacker secrets apps`
        #[arg(long, value_name = "TARGET_CODE")]
        service: Option<String>,
        /// Server ID for server-scoped secrets
        #[arg(long, value_name = "SERVER_ID")]
        server_id: Option<i32>,
        /// Inline secret value for remote mode
        #[arg(long, value_name = "VALUE", conflicts_with = "body_file")]
        body: Option<String>,
        /// Read the secret value from a file in remote mode
        #[arg(long = "body-file", value_name = "FILE", conflicts_with = "body")]
        body_file: Option<String>,
    },
    /// Get a local .env secret or remote secret metadata
    #[command(after_help = "Examples:\n\
  Local value (masked by default):\n\
    stacker secrets get DB_PASSWORD\n\
\n\
  Local plaintext value:\n\
    stacker secrets get DB_PASSWORD --show\n\
\n\
   Remote metadata only:\n\
    stacker secrets get S3_SECRET_KEY --service uploader --json\n\
\n\
Remote get is metadata-only in v1 and does not reveal plaintext values.")]
    Get {
        /// Key name to retrieve
        key: String,
        /// Path to .env file
        #[arg(
            long,
            value_name = "FILE",
            conflicts_with_all = ["scope", "project", "service", "server_id", "json"]
        )]
        file: Option<String>,
        /// Show the actual value instead of masking it
        #[arg(long, conflicts_with_all = ["scope", "project", "service", "server_id", "json"])]
        show: bool,
        /// Remote secret scope
        #[arg(long, value_enum)]
        scope: Option<RemoteSecretScope>,
        /// Project name or ID for service-scoped secrets (defaults to project.identity in stacker.yml)
        #[arg(long, value_name = "PROJECT")]
        project: Option<String>,
        /// Deployable service/app target code listed by `stacker secrets apps`
        #[arg(long, value_name = "TARGET_CODE")]
        service: Option<String>,
        /// Server ID for server-scoped secrets
        #[arg(long, value_name = "SERVER_ID")]
        server_id: Option<i32>,
        /// Output metadata as JSON in remote mode
        #[arg(long)]
        json: bool,
    },
    /// List local .env secrets or remote secret metadata
    #[command(after_help = "Examples:\n\
  Local list:\n\
    stacker secrets list\n\
\n\
  Remote service secrets:\n\
    stacker secrets list --service uploader\n\
\n\
  Remote server secrets as JSON:\n\
    stacker secrets list --scope server --server-id 42 --json\n\
\n\
 Remote list returns metadata only in v1.")]
    List {
        /// Path to .env file
        #[arg(
            long,
            value_name = "FILE",
            conflicts_with_all = ["scope", "project", "service", "server_id", "json"]
        )]
        file: Option<String>,
        /// Show actual values (default: mask with ***)
        #[arg(long, conflicts_with_all = ["scope", "project", "service", "server_id", "json"])]
        show: bool,
        /// Remote secret scope
        #[arg(long, value_enum)]
        scope: Option<RemoteSecretScope>,
        /// Project name or ID for service-scoped secrets (defaults to project.identity in stacker.yml)
        #[arg(long, value_name = "PROJECT")]
        project: Option<String>,
        /// Deployable service/app target code listed by `stacker secrets apps`
        #[arg(long, value_name = "TARGET_CODE")]
        service: Option<String>,
        /// Server ID for server-scoped secrets
        #[arg(long, value_name = "SERVER_ID")]
        server_id: Option<i32>,
        /// Output metadata as JSON in remote mode
        #[arg(long)]
        json: bool,
    },
    /// List valid remote deployable service/app target codes (`stacker secrets apps`)
    #[command(
        visible_alias = "services",
        after_help = "Examples:\n\
     List remote target codes using project.identity from stacker.yml:\n\
     stacker secrets apps\n\
   \n\
   Register one local stacker.yml service as a remote target:\n\
     stacker secrets apps register upload\n\
   \n\
   Sync all local stacker.yml services as remote targets:\n\
     stacker secrets apps sync\n\
   \n\
   List remote target codes for a project:\n\
     stacker secrets apps --project blog\n\
  \n\
  Output app metadata as JSON:\n\
    stacker secrets apps --json"
    )]
    Apps {
        #[command(subcommand)]
        command: Option<SecretsAppsCommands>,
        /// Project name or ID (defaults to project.identity in stacker.yml)
        #[arg(long, value_name = "PROJECT")]
        project: Option<String>,
        /// Output app metadata as JSON
        #[arg(long)]
        json: bool,
    },
    /// Push stored remote secrets for a service/app target into runtime env
    #[command(
        visible_aliases = ["deploy", "apply"],
        after_help = "Examples:\n\
  Push stored remote secrets into the runtime env for a target:\n\
    stacker secrets push --service device-api\n\
\n\
  Overwrite a drifted remote runtime .env if needed:\n\
    stacker secrets push --service device-api --force\n\
\n\
Aliases:\n\
  stacker secrets deploy --service device-api\n\
  stacker secrets apply --service device-api\n\
\n\
This does not create or change secret values. Use `stacker secrets set` first."
    )]
    Push {
        /// Deployable service/app target code listed by `stacker secrets apps`
        #[arg(long, value_name = "TARGET_CODE")]
        service: String,
        /// Project name or ID (defaults to project.identity in stacker.yml)
        #[arg(long, value_name = "PROJECT")]
        project: Option<String>,
        /// Overwrite a drifted remote runtime .env and recreate the container
        #[arg(long)]
        force: bool,
        /// Output command result as JSON
        #[arg(long)]
        json: bool,
        /// Deployment hash
        #[arg(long)]
        deployment: Option<String>,
        /// Deploy environment/profile, e.g. local, dev, prod
        #[arg(long = "env", alias = "environment", value_name = "ENVIRONMENT")]
        environment: Option<String>,
    },
    /// Delete a local .env secret or a remote Vault-backed secret
    #[command(after_help = "Examples:\n\
  Local delete:\n\
    stacker secrets delete DB_PASSWORD\n\
\n\
   Remote service secret delete:\n\
    stacker secrets delete S3_SECRET_KEY --service uploader\n\
\n\
  Remote server secret delete:\n\
    stacker secrets delete NPM_TOKEN --scope server --server-id 42")]
    Delete {
        /// Key name to delete
        key: String,
        /// Path to .env file
        #[arg(
            long,
            value_name = "FILE",
            conflicts_with_all = ["scope", "project", "service", "server_id"]
        )]
        file: Option<String>,
        /// Remote secret scope
        #[arg(long, value_enum)]
        scope: Option<RemoteSecretScope>,
        /// Project name or ID for service-scoped secrets (defaults to project.identity in stacker.yml)
        #[arg(long, value_name = "PROJECT")]
        project: Option<String>,
        /// Deployable service/app target code listed by `stacker secrets apps`
        #[arg(long, value_name = "TARGET_CODE")]
        service: Option<String>,
        /// Server ID for server-scoped secrets
        #[arg(long, value_name = "SERVER_ID")]
        server_id: Option<i32>,
    },
    /// Validate all ${VAR} references in stacker.yml are set in .env or environment
    Validate {
        /// Path to stacker.yml (default: ./stacker.yml)
        #[arg(long, value_name = "FILE")]
        file: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum SecretsAppsCommands {
    /// Register one local stacker.yml service as a remote secret target
    Register {
        /// Local service name from stacker.yml
        service: String,
        /// Project name or ID (defaults to project.identity in stacker.yml)
        #[arg(long, value_name = "PROJECT")]
        project: Option<String>,
        /// Output registered app metadata as JSON
        #[arg(long)]
        json: bool,
    },
    /// Register/update all local stacker.yml services as remote secret targets
    Sync {
        /// Project name or ID (defaults to project.identity in stacker.yml)
        #[arg(long, value_name = "PROJECT")]
        project: Option<String>,
        /// Output registered app metadata as JSON
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum CiCommands {
    /// Export a CI/CD pipeline configuration file
    Export {
        /// Platform: github, gitlab, bitbucket, jenkins
        #[arg(long)]
        platform: String,
        /// Path to stacker.yml (default: ./stacker.yml)
        #[arg(long, value_name = "FILE")]
        file: Option<String>,
    },
    /// Validate that the CI/CD pipeline is in sync with stacker.yml
    Validate {
        /// Platform: github, gitlab, bitbucket, jenkins
        #[arg(long)]
        platform: String,
    },
}

#[derive(Debug, Subcommand)]
enum PipeCommands {
    /// Discover local containers or probe a remote app
    Scan {
        /// Legacy selector: container filter in local mode, app code in remote mode
        #[arg(value_name = "APP_OR_FILTER", hide = true)]
        legacy_selector: Option<String>,
        /// Explicit remote app selector
        #[arg(long, conflicts_with = "containers")]
        app: Option<String>,
        /// Explicit local container discovery; optional filter when provided
        #[arg(long, value_name = "FILTER", num_args = 0..=1, default_missing_value = "*", conflicts_with = "app")]
        containers: Option<String>,
        /// Narrow the remote app scan to a specific container
        #[arg(long, requires = "app")]
        container: Option<String>,
        /// Protocols to probe (default: openapi,html_forms,rest)
        #[arg(long, value_delimiter = ',')]
        protocols: Vec<String>,
        /// Capture sample responses from discovered endpoints
        #[arg(long)]
        capture_samples: bool,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
        /// Deployment hash (auto-detected from lock/config)
        #[arg(long)]
        deployment: Option<String>,
    },
    /// Create a pipe between two apps (interactive)
    Create {
        /// Source app code
        source: String,
        /// Target app code
        target: String,
        /// Skip all auto-matching, manual selection only
        #[arg(long)]
        manual: bool,
        /// Force AI-powered field matching (requires ai: config in stacker.yml)
        #[arg(long, conflicts_with = "no_ai")]
        ai: bool,
        /// Force deterministic field matching (disable AI even if configured)
        #[arg(long, conflicts_with = "ai")]
        no_ai: bool,
        /// Use ML-based field matching (n-gram cosine similarity)
        #[arg(long, conflicts_with_all = ["ai", "no_ai"])]
        ml: bool,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
        /// Deployment hash
        #[arg(long)]
        deployment: Option<String>,
    },
    /// List active pipes for a deployment
    List {
        /// Output in JSON format
        #[arg(long)]
        json: bool,
        /// Deployment hash
        #[arg(long)]
        deployment: Option<String>,
    },
    /// Activate a pipe instance (start listening for triggers)
    Activate {
        /// Pipe instance ID (UUID)
        pipe_id: String,
        /// Trigger type: webhook, poll, or manual
        #[arg(long, default_value = "webhook")]
        trigger: String,
        /// Poll interval in seconds (only for --trigger=poll)
        #[arg(long, default_value = "300")]
        poll_interval: u32,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
        /// Deployment hash
        #[arg(long)]
        deployment: Option<String>,
    },
    /// Deactivate a pipe instance (stop listening)
    Deactivate {
        /// Pipe instance ID (UUID)
        pipe_id: String,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
        /// Deployment hash
        #[arg(long)]
        deployment: Option<String>,
    },
    /// Trigger a pipe instance manually (one-shot execution)
    Trigger {
        /// Pipe instance ID (UUID)
        pipe_id: String,
        /// Optional JSON input data to feed into the pipe
        #[arg(long)]
        data: Option<String>,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
        /// Deployment hash
        #[arg(long)]
        deployment: Option<String>,
    },
    /// Show execution history for a pipe instance
    History {
        /// Pipe instance ID (UUID)
        instance_id: String,
        /// Maximum number of executions to show
        #[arg(long, default_value = "20")]
        limit: i64,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
        /// Deployment hash
        #[arg(long)]
        deployment: Option<String>,
    },
    /// Replay a previous pipe execution using its original input data
    Replay {
        /// Execution ID (UUID) to replay
        execution_id: String,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
        /// Deployment hash
        #[arg(long)]
        deployment: Option<String>,
    },
    /// Deploy (promote) a local pipe instance to a remote deployment
    Deploy {
        /// Local pipe instance ID (UUID) to promote
        instance_id: String,
        /// Target deployment hash to deploy into
        #[arg(long)]
        deployment: String,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum AgentCommands {
    /// Check container health on the remote deployment
    Health {
        /// App code to check (default: all containers)
        #[arg(long)]
        app: Option<String>,
        /// Include system containers (status_panel, compose-agent)
        #[arg(long)]
        system: bool,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
        /// Deployment hash (auto-detected from lock/config)
        #[arg(long)]
        deployment: Option<String>,
    },
    /// Fetch container logs from the remote deployment
    Logs {
        /// App code to fetch logs for (default: statuspanel + statuspanel_agent)
        app: Option<String>,
        /// Maximum number of log lines
        #[arg(long, default_value_t = 400)]
        limit: i32,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
        /// Deployment hash
        #[arg(long)]
        deployment: Option<String>,
    },
    /// Restart a container on the remote deployment
    Restart {
        /// App code to restart
        app: String,
        /// Force restart (stop + start instead of graceful restart)
        #[arg(long)]
        force: bool,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
        /// Deployment hash
        #[arg(long)]
        deployment: Option<String>,
    },
    /// Deploy/update an app container on the remote deployment
    #[command(name = "deploy-app")]
    DeployApp {
        /// App code to deploy
        app: String,
        /// Docker image to use (overrides compose config)
        #[arg(long)]
        image: Option<String>,
        /// Force recreate the container
        #[arg(long)]
        force: bool,
        /// Container runtime: "runc" (default) or "kata"
        #[arg(long, default_value = "runc")]
        runtime: String,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
        /// Deployment hash
        #[arg(long)]
        deployment: Option<String>,
        /// Deploy environment/profile, e.g. local, dev, prod
        #[arg(long = "env", alias = "environment", value_name = "ENVIRONMENT")]
        environment: Option<String>,
        /// Print a read-only deploy-app plan instead of applying changes
        #[arg(long)]
        plan: bool,
        /// Revalidate and apply a previously generated deploy-app plan fingerprint
        #[arg(long, value_name = "FINGERPRINT", conflicts_with = "plan")]
        apply_plan: Option<String>,
    },
    /// Remove an app container from the remote deployment
    #[command(name = "remove-app")]
    RemoveApp {
        /// App code to remove
        app: String,
        /// Also remove volumes
        #[arg(long)]
        volumes: bool,
        /// Also remove the image
        #[arg(long)]
        remove_image: bool,
        /// Skip the active-connections pre-flight check
        #[arg(long)]
        force: bool,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
        /// Deployment hash
        #[arg(long)]
        deployment: Option<String>,
    },
    /// Configure iptables firewall rules on the remote deployment
    #[command(name = "configure-firewall")]
    ConfigureFirewall {
        /// Action: add, remove, list, flush
        #[arg(long, default_value = "add")]
        action: String,
        /// List current firewall rules (shortcut for --action list)
        #[arg(long)]
        list: bool,
        /// App code for context/logging
        #[arg(long)]
        app: Option<String>,
        /// Public ports (open to all), comma-separated: "80/tcp,443/tcp,53/udp"
        #[arg(long, value_delimiter = ',')]
        public_ports: Vec<String>,
        /// Private ports (restricted), format: "port/proto:source", comma-separated: "5432/tcp:10.0.0.0/8"
        #[arg(long, value_delimiter = ',')]
        private_ports: Vec<String>,
        /// Persist rules across reboots
        #[arg(long, default_value_t = true)]
        persist: bool,
        /// Skip the active-connections pre-flight check
        #[arg(long)]
        force: bool,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
        /// Deployment hash
        #[arg(long)]
        deployment: Option<String>,
    },
    /// Configure reverse proxy for an app
    #[command(name = "configure-proxy")]
    ConfigureProxy {
        /// App code
        app: String,
        /// Domain name
        #[arg(long)]
        domain: String,
        /// Port to forward to
        #[arg(long)]
        port: u16,
        /// Enable SSL/Let's Encrypt certificate issuance
        #[arg(long, default_value_t = true)]
        ssl: bool,
        /// Disable SSL/Let's Encrypt and create a plain HTTP proxy host
        #[arg(long = "no-ssl")]
        no_ssl: bool,
        /// Action: create, update, delete
        #[arg(long, default_value = "create")]
        action: String,
        /// Skip the active-connections pre-flight check
        #[arg(long)]
        force: bool,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
        /// Deployment hash
        #[arg(long)]
        deployment: Option<String>,
    },
    /// List deployment resources from the agent
    #[command(name = "list")]
    List {
        #[command(subcommand)]
        command: AgentListCommands,
    },
    /// Show agent and container status for the deployment
    Status {
        /// Output in JSON format
        #[arg(long)]
        json: bool,
        /// Deployment hash
        #[arg(long)]
        deployment: Option<String>,
    },
    /// Show command history for the deployment
    History {
        /// Output in JSON format
        #[arg(long)]
        json: bool,
        /// Deployment hash
        #[arg(long)]
        deployment: Option<String>,
    },
    /// Send a raw command to the agent (advanced)
    Exec {
        /// Command type (e.g. health, logs, restart, deploy_app, etc.)
        command_type: String,
        /// JSON parameters
        #[arg(long)]
        params: Option<String>,
        /// Timeout in seconds
        #[arg(long)]
        timeout: Option<u64>,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
        /// Deployment hash
        #[arg(long)]
        deployment: Option<String>,
    },
    /// Install the Status Panel agent on an existing deployed server
    Install {
        /// Path to stacker.yml (default: ./stacker.yml)
        #[arg(long, value_name = "FILE")]
        file: Option<String>,
        /// Persist monitoring.status_panel=true back to the local stacker.yml
        #[arg(long)]
        persist_config: bool,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum AgentListCommands {
    /// List apps deployed for the target deployment
    Apps {
        /// Output in JSON format
        #[arg(long)]
        json: bool,
        /// Deployment hash
        #[arg(long)]
        deployment: Option<String>,
    },
    /// List containers running on the target server
    Containers {
        /// Output in JSON format
        #[arg(long)]
        json: bool,
        /// Deployment hash
        #[arg(long)]
        deployment: Option<String>,
    },
}

/// Arguments for `stacker ai`.
/// Using a separate struct lets `subcommand_required = false` work so
/// bare `stacker ai` launches the interactive chat mode.
#[derive(Debug, Args)]
#[command(subcommand_required = false, arg_required_else_help = false)]
struct AiArgs {
    #[command(subcommand)]
    command: Option<AiCommands>,
    /// Write mode: AI may create/edit `stacker.yml` and files under `.stacker/`.
    /// Requires a tool-capable model (Ollama: llama3.1/qwen2.5-coder, OpenAI: any).
    #[arg(long)]
    write: bool,
    /// Activate a built-in AI scenario such as `website-deploy`.
    #[arg(long, global = true)]
    scenario: Option<String>,
    /// Select the active scenario step such as `init-validate` or `cloud-deploy`.
    #[arg(long, global = true)]
    step: Option<String>,
}

#[derive(Debug, Subcommand)]
enum AiCommands {
    /// Ask the AI a question about your stack
    Ask {
        /// The question to ask
        question: String,
        /// Path to a file to include as context
        #[arg(long)]
        context: Option<String>,
        /// Interactively configure AI in stacker.yml before asking
        #[arg(long)]
        configure: bool,
        /// Write mode: AI may create/edit `stacker.yml` and files under `.stacker/`
        #[arg(long)]
        write: bool,
    },
}

#[derive(Debug, Subcommand)]
enum ProxyCommands {
    /// Add a reverse-proxy entry for a domain
    Add {
        /// Domain name (e.g. example.com)
        domain: String,
        /// Upstream service address (e.g. http://app:8080)
        #[arg(long)]
        upstream: Option<String>,
        /// SSL mode: auto, manual, off
        #[arg(long)]
        ssl: Option<String>,
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

fn inferred_remote_secret_scope(
    scope: Option<RemoteSecretScope>,
    service: &Option<String>,
    server_id: Option<i32>,
) -> Option<RemoteSecretScope> {
    scope.or_else(|| {
        if service.is_some() {
            Some(RemoteSecretScope::Service)
        } else if server_id.is_some() {
            Some(RemoteSecretScope::Server)
        } else {
            None
        }
    })
}

fn should_use_remote_secret_set(
    scope: Option<RemoteSecretScope>,
    project: &Option<String>,
    service: &Option<String>,
    server_id: Option<i32>,
    body: &Option<String>,
    body_file: &Option<String>,
) -> bool {
    scope.is_some()
        || project.is_some()
        || service.is_some()
        || server_id.is_some()
        || body.is_some()
        || body_file.is_some()
}

fn should_use_remote_secret_metadata(
    scope: Option<RemoteSecretScope>,
    project: &Option<String>,
    service: &Option<String>,
    server_id: Option<i32>,
    json: bool,
) -> bool {
    scope.is_some() || project.is_some() || service.is_some() || server_id.is_some() || json
}

fn active_environment_path(project_dir: &std::path::Path) -> std::path::PathBuf {
    project_dir.join(".stacker").join("active-env")
}

fn read_active_environment(
    project_dir: &std::path::Path,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let path = active_environment_path(project_dir);
    if !path.exists() {
        return Ok(None);
    }

    let value = std::fs::read_to_string(path)?;
    let value = value.trim().to_string();
    if value.is_empty() {
        Ok(None)
    } else {
        Ok(Some(value))
    }
}

fn write_active_environment(
    project_dir: &std::path::Path,
    environment: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let stacker_dir = project_dir.join(".stacker");
    std::fs::create_dir_all(&stacker_dir)?;
    std::fs::write(
        active_environment_path(project_dir),
        format!("{environment}\n"),
    )?;
    Ok(())
}

fn validate_environment_name(
    project_dir: &std::path::Path,
    environment: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if environment.trim().is_empty() {
        return Err("Environment name cannot be empty".into());
    }

    let config_path = project_dir.join("stacker.yml");
    if !config_path.exists() {
        return Ok(());
    }

    let config = stacker::cli::config_parser::StackerConfig::from_file(&config_path)?;
    if !config.environments.is_empty() && !config.environments.contains_key(environment) {
        let available = config
            .environments
            .keys()
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        return Err(format!(
            "Unknown environment '{environment}'. Available environments: {available}"
        )
        .into());
    }

    Ok(())
}

fn resolved_config_environment(
    project_dir: &std::path::Path,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let config_path = project_dir.join("stacker.yml");
    if !config_path.exists() {
        return Ok(None);
    }

    let active_target =
        stacker::cli::deployment_lock::DeploymentLock::read_active_target(project_dir)?;
    let config = stacker::cli::config_parser::StackerConfig::from_file(&config_path)?
        .with_resolved_deploy_target(active_target.as_deref())?;

    Ok(config.selected_environment(None))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(err) => {
            use clap::error::ErrorKind;
            match err.kind() {
                ErrorKind::DisplayHelp => {
                    print_banner();
                    err.print()?;
                    return Ok(());
                }
                ErrorKind::DisplayVersion => {
                    println!("{}", stacker::version::display_version());
                    return Ok(());
                }
                _ => {
                    err.print()?;
                    std::process::exit(2);
                }
            }
        }
    };

    let Some(subcommand) = cli.command else {
        print_banner();
        let mut cmd = Cli::command();
        cmd.print_long_help()?;
        println!();
        return Ok(());
    };

    // Shell completions need access to the CLI Command object directly.
    if let StackerCommands::Completion { shell } = subcommand {
        let mut cmd = Cli::command();
        clap_complete::generate(shell, &mut cmd, "stacker", &mut std::io::stdout());
        eprintln!();
        eprintln!("# Reload your shell or run:  source ~/.zshrc  (for zsh)");
        return Ok(());
    }

    // Target switching is filesystem-only, no API needed.
    if let StackerCommands::Target { target } = subcommand {
        use stacker::cli::deployment_lock::DeploymentLock;
        let project_dir = std::env::current_dir()?;

        match target {
            Some(t) => {
                DeploymentLock::switch_target(&project_dir, &t)?;
                eprintln!("✓ Active target switched to: {}", t);
            }
            None => match DeploymentLock::read_active_target(&project_dir)? {
                Some(t) => println!("{}", t),
                None => {
                    eprintln!("No active target set. Use: stacker target <local|cloud|server>");
                }
            },
        }
        return Ok(());
    }

    if let StackerCommands::Env { environment } = subcommand {
        let project_dir = std::env::current_dir()?;
        match environment {
            Some(environment) => {
                validate_environment_name(&project_dir, &environment)?;
                write_active_environment(&project_dir, &environment)?;
                eprintln!("✓ Active environment switched to: {}", environment);
            }
            None => {
                let active = read_active_environment(&project_dir)?;
                let configured = resolved_config_environment(&project_dir)?;
                match (active, configured) {
                    (Some(active), Some(configured)) => {
                        println!("{}", active);
                        if active != configured {
                            eprintln!("Configured default environment: {}", configured);
                        }
                    }
                    (Some(active), None) => println!("{}", active),
                    (None, Some(configured)) => println!("{}", configured),
                    (None, None) => {
                        eprintln!("No active environment set. Use: stacker env <environment>");
                    }
                }
            }
        }
        return Ok(());
    }

    let command = get_command(subcommand)?;
    if let Err(err) = command.call() {
        eprintln!("Error: {}", err);
        std::process::exit(1);
    }
    Ok(())
}

fn get_command(
    subcommand: StackerCommands,
) -> Result<Box<dyn stacker::console::commands::CallableTrait>, Box<dyn std::error::Error>> {
    let cmd: Box<dyn stacker::console::commands::CallableTrait> = match subcommand {
        StackerCommands::Login {
            org,
            domain,
            auth_url,
            server_url,
        } => Box::new(stacker::console::commands::cli::login::LoginCommand::new(
            org, domain, auth_url, server_url,
        )),
        StackerCommands::Whoami {} => {
            Box::new(stacker::console::commands::cli::whoami::WhoamiCommand::new())
        }
        StackerCommands::Init {
            app_type,
            with_proxy,
            with_ai,
            with_cloud,
            target,
            ai_provider,
            ai_model,
            ai_api_key,
        } => {
            // If --target is specified, set the active target after init
            if let Some(ref t) = target {
                use stacker::cli::deployment_lock::DeploymentLock;
                let project_dir = std::env::current_dir()?;
                DeploymentLock::switch_target(&project_dir, t)?;
                eprintln!("✓ Active target set to: {}", t);
            }
            Box::new(
                stacker::console::commands::cli::init::InitCommand::new(
                    app_type, with_proxy, with_ai, with_cloud,
                )
                .with_ai_options(ai_provider, ai_model, ai_api_key),
            )
        }
        StackerCommands::Deploy {
            target,
            environment,
            file,
            dry_run,
            force_rebuild,
            project,
            key,
            key_id,
            server,
            watch,
            no_watch,
            lock,
            force_new,
            runtime,
            plan,
            apply_plan,
        } => Box::new(
            stacker::console::commands::cli::deploy::DeployCommand::new(
                target,
                file,
                dry_run,
                force_rebuild,
            )
            .with_environment(environment)
            .with_remote_overrides(project, key, server)
            .with_key_id(key_id)
            .with_watch(watch, no_watch)
            .with_lock(lock)
            .with_force_new(force_new)
            .with_runtime(runtime)
            .with_plan(plan)
            .with_apply_plan(apply_plan),
        ),
        StackerCommands::Connect { handoff } => {
            Box::new(stacker::console::commands::cli::connect::ConnectCommand::new(handoff))
        }
        StackerCommands::Logs {
            service,
            follow,
            tail,
            since,
        } => Box::new(stacker::console::commands::cli::logs::LogsCommand::new(
            service, follow, tail, since,
        )),
        StackerCommands::Status { json, watch } => Box::new(
            stacker::console::commands::cli::status::StatusCommand::new(json, watch),
        ),
        StackerCommands::Deployment { command } => match command {
            DeploymentCommands::State { json, deployment } => Box::new(
                stacker::console::commands::cli::deployment::DeploymentStateCommand::new(
                    json, deployment,
                ),
            ),
            DeploymentCommands::Events { json, deployment } => Box::new(
                stacker::console::commands::cli::deployment::DeploymentEventsCommand::new(
                    json, deployment,
                ),
            ),
            DeploymentCommands::Rollback {
                to,
                plan,
                apply_plan,
                deployment,
                confirm,
            } => Box::new(
                stacker::console::commands::cli::deployment::DeploymentRollbackCommand::new(
                    to, plan, apply_plan, confirm, deployment,
                ),
            ),
        },
        StackerCommands::Explain { command } => match command {
            ExplainCommands::Env { app, json } => Box::new(
                stacker::console::commands::cli::explain::ExplainEnvCommand::new(app, json),
            ),
            ExplainCommands::Topology { json } => Box::new(
                stacker::console::commands::cli::explain::ExplainTopologyCommand::new(json),
            ),
        },
        StackerCommands::Destroy { volumes, confirm } => Box::new(
            stacker::console::commands::cli::destroy::DestroyCommand::new(volumes, confirm),
        ),
        StackerCommands::Rollback { version, confirm } => Box::new(
            stacker::console::commands::cli::rollback::RollbackCommand::new(version, confirm),
        ),
        StackerCommands::Config { command: cfg_cmd } => match cfg_cmd {
            ConfigCommands::Validate { file } => {
                Box::new(stacker::console::commands::cli::config::ConfigValidateCommand::new(file))
            }
            ConfigCommands::Show { file, resolved } => Box::new(
                stacker::console::commands::cli::config::ConfigShowCommand::new(file, resolved),
            ),
            ConfigCommands::Example => {
                Box::new(stacker::console::commands::cli::config::ConfigExampleCommand::new())
            }
            ConfigCommands::Fix { file, interactive } => Box::new(
                stacker::console::commands::cli::config::ConfigFixCommand::new(file, interactive),
            ),
            ConfigCommands::Lock { file } => {
                Box::new(stacker::console::commands::cli::config::ConfigLockCommand::new(file))
            }
            ConfigCommands::Unlock { file } => {
                Box::new(stacker::console::commands::cli::config::ConfigUnlockCommand::new(file))
            }
            ConfigCommands::Setup { command } => match command {
                ConfigSetupCommands::Cloud { file } => Box::new(
                    stacker::console::commands::cli::config::ConfigSetupCloudCommand::new(file),
                ),
                ConfigSetupCommands::Ai {
                    file,
                    provider,
                    endpoint,
                    model,
                    timeout,
                    tasks,
                } => Box::new(
                    stacker::console::commands::cli::config::ConfigSetupAiCommand::new(
                        file, provider, endpoint, model, timeout, tasks,
                    ),
                ),
                ConfigSetupCommands::RemotePayload { file, out } => Box::new(
                    stacker::console::commands::cli::config::ConfigSetupRemotePayloadCommand::new(
                        file, out,
                    ),
                ),
            },
        },
        StackerCommands::Ai(ai_args) => match ai_args.command {
            None => Box::new(stacker::console::commands::cli::ai::AiChatCommand::new(
                ai_args.write,
                ai_args.scenario,
                ai_args.step,
            )),
            Some(AiCommands::Ask {
                question,
                context,
                configure,
                write,
            }) => Box::new(
                stacker::console::commands::cli::ai::AiAskCommand::new(question, context)
                    .with_configure(configure)
                    .with_scenario(ai_args.scenario, ai_args.step)
                    .with_write(ai_args.write || write),
            ),
        },
        StackerCommands::Proxy { command: proxy_cmd } => match proxy_cmd {
            ProxyCommands::Add {
                domain,
                upstream,
                ssl,
            } => Box::new(
                stacker::console::commands::cli::proxy::ProxyAddCommand::new(
                    domain, upstream, ssl, false, false, None,
                ),
            ),
            ProxyCommands::Detect { json, deployment } => Box::new(
                stacker::console::commands::cli::proxy::ProxyDetectCommand::new(json, deployment),
            ),
        },
        StackerCommands::List { command: list_cmd } => match list_cmd {
            ListCommands::Projects { json } => {
                Box::new(stacker::console::commands::cli::list::ListProjectsCommand::new(json))
            }
            ListCommands::Deployments {
                json,
                project,
                limit,
            } => Box::new(
                stacker::console::commands::cli::list::ListDeploymentsCommand::new(
                    json, project, limit,
                ),
            ),
            ListCommands::Servers { json } => {
                Box::new(stacker::console::commands::cli::list::ListServersCommand::new(json))
            }
            ListCommands::SshKeys { json } => {
                Box::new(stacker::console::commands::cli::list::ListSshKeysCommand::new(json))
            }
            ListCommands::Clouds { json } => {
                Box::new(stacker::console::commands::cli::list::ListCloudsCommand::new(json))
            }
        },
        StackerCommands::SshKey { command: ssh_cmd } => match ssh_cmd {
            SshKeyCommands::Generate { server_id, save_to } => Box::new(
                stacker::console::commands::cli::ssh_key::SshKeyGenerateCommand::new(
                    server_id, save_to,
                ),
            ),
            SshKeyCommands::Show { server_id, json } => Box::new(
                stacker::console::commands::cli::ssh_key::SshKeyShowCommand::new(server_id, json),
            ),
            SshKeyCommands::Upload {
                server_id,
                public_key,
                private_key,
            } => Box::new(
                stacker::console::commands::cli::ssh_key::SshKeyUploadCommand::new(
                    server_id,
                    public_key,
                    private_key,
                ),
            ),
            SshKeyCommands::Inject {
                server_id,
                with_key,
                user,
                port,
            } => Box::new(
                stacker::console::commands::cli::ssh_key::SshKeyInjectCommand::new(
                    server_id, with_key, user, port,
                ),
            ),
        },
        StackerCommands::Service { command: svc_cmd } => match svc_cmd {
            ServiceCommands::Add { name, file } => Box::new(
                stacker::console::commands::cli::service::ServiceAddCommand::new(name, file),
            ),
            ServiceCommands::Import {
                name,
                from_compose,
                from_github,
                from_url,
                service,
                rename,
                file,
                review,
                yes,
                json,
            } => Box::new(
                stacker::console::commands::cli::service::ServiceImportCommand::new(
                    name,
                    from_compose,
                    from_github,
                    from_url,
                    service,
                    rename,
                    file,
                    review,
                    yes,
                    json,
                ),
            ),
            ServiceCommands::Deploy {
                name,
                force,
                runtime,
                json,
                deployment,
                environment,
                plan,
                apply_plan,
            } => Box::new(
                stacker::console::commands::cli::service::ServiceDeployCommand::new(
                    name,
                    force,
                    runtime,
                    json,
                    deployment,
                    environment,
                    plan,
                    apply_plan,
                ),
            ),
            ServiceCommands::Remove { name, file } => Box::new(
                stacker::console::commands::cli::service::ServiceRemoveCommand::new(name, file),
            ),
            ServiceCommands::List { online } => {
                Box::new(stacker::console::commands::cli::service::ServiceListCommand::new(online))
            }
        },
        StackerCommands::Resolve {
            confirm,
            force,
            deployment,
        } => Box::new(
            stacker::console::commands::cli::resolve::ResolveCommand::new(
                confirm, force, deployment,
            ),
        ),
        StackerCommands::Update { channel } => Box::new(
            stacker::console::commands::cli::update::UpdateCommand::new(channel),
        ),
        StackerCommands::Secrets { command: sec_cmd } => match sec_cmd {
            SecretsCommands::Set {
                input,
                file,
                scope,
                project,
                service,
                server_id,
                body,
                body_file,
            } => {
                if should_use_remote_secret_set(
                    scope, &project, &service, server_id, &body, &body_file,
                ) {
                    let scope = inferred_remote_secret_scope(scope, &service, server_id)
                        .unwrap_or(RemoteSecretScope::Service);
                    Box::new(
                        stacker::console::commands::cli::secrets::SecretsSetCommand::new_remote(
                            input, scope, project, service, server_id, body, body_file,
                        ),
                    )
                } else {
                    Box::new(
                        stacker::console::commands::cli::secrets::SecretsSetCommand::new(
                            input, file,
                        ),
                    )
                }
            }
            SecretsCommands::Get {
                key,
                file,
                show,
                scope,
                project,
                service,
                server_id,
                json,
            } => {
                if should_use_remote_secret_metadata(scope, &project, &service, server_id, json) {
                    let scope = inferred_remote_secret_scope(scope, &service, server_id)
                        .unwrap_or(RemoteSecretScope::Service);
                    Box::new(
                        stacker::console::commands::cli::secrets::SecretsGetCommand::new_remote(
                            key, scope, project, service, server_id, json,
                        ),
                    )
                } else {
                    Box::new(
                        stacker::console::commands::cli::secrets::SecretsGetCommand::new(
                            key, file, show,
                        ),
                    )
                }
            }
            SecretsCommands::List {
                file,
                show,
                scope,
                project,
                service,
                server_id,
                json,
            } => {
                if should_use_remote_secret_metadata(scope, &project, &service, server_id, json) {
                    let scope = inferred_remote_secret_scope(scope, &service, server_id)
                        .unwrap_or(RemoteSecretScope::Service);
                    Box::new(
                        stacker::console::commands::cli::secrets::SecretsListCommand::new_remote(
                            scope, project, service, server_id, json,
                        ),
                    )
                } else {
                    Box::new(
                        stacker::console::commands::cli::secrets::SecretsListCommand::new(
                            file, show,
                        ),
                    )
                }
            }
            SecretsCommands::Apps {
                command,
                project,
                json,
            } => match command {
                Some(SecretsAppsCommands::Register {
                    service,
                    project: command_project,
                    json: command_json,
                }) => Box::new(
                    stacker::console::commands::cli::secrets::SecretsAppsCommand::register(
                        service,
                        command_project.or(project),
                        json || command_json,
                    ),
                ),
                Some(SecretsAppsCommands::Sync {
                    project: command_project,
                    json: command_json,
                }) => Box::new(
                    stacker::console::commands::cli::secrets::SecretsAppsCommand::sync(
                        command_project.or(project),
                        json || command_json,
                    ),
                ),
                None => Box::new(
                    stacker::console::commands::cli::secrets::SecretsAppsCommand::new(
                        project, json,
                    ),
                ),
            },
            SecretsCommands::Push {
                service,
                project,
                force,
                json,
                deployment,
                environment,
            } => Box::new(
                stacker::console::commands::cli::secrets::SecretsPushCommand::new(
                    project,
                    service,
                    force,
                    json,
                    deployment,
                    environment,
                ),
            ),
            SecretsCommands::Delete {
                key,
                file,
                scope,
                project,
                service,
                server_id,
            } => {
                if scope.is_some() || project.is_some() || service.is_some() || server_id.is_some()
                {
                    let scope = inferred_remote_secret_scope(scope, &service, server_id)
                        .unwrap_or(RemoteSecretScope::Service);
                    Box::new(
                        stacker::console::commands::cli::secrets::SecretsDeleteCommand::new_remote(
                            key, scope, project, service, server_id,
                        ),
                    )
                } else {
                    Box::new(
                        stacker::console::commands::cli::secrets::SecretsDeleteCommand::new(
                            key, file,
                        ),
                    )
                }
            }
            SecretsCommands::Validate { file } => Box::new(
                stacker::console::commands::cli::secrets::SecretsValidateCommand::new(file),
            ),
        },
        StackerCommands::Ci { command: ci_cmd } => match ci_cmd {
            CiCommands::Export { platform, file } => Box::new(
                stacker::console::commands::cli::ci::CiExportCommand::new(platform, file),
            ),
            CiCommands::Validate { platform } => Box::new(
                stacker::console::commands::cli::ci::CiValidateCommand::new(platform),
            ),
        },
        StackerCommands::Pipe { command: pipe_cmd } => {
            use stacker::console::commands::cli::pipe;
            match pipe_cmd {
                PipeCommands::Scan {
                    legacy_selector,
                    app,
                    containers,
                    container,
                    protocols,
                    capture_samples,
                    json,
                    deployment,
                } => {
                    let request = if let Some(app) = app {
                        pipe::PipeScanRequest::App { app, container }
                    } else if let Some(filter) = containers {
                        let filter = if filter == "*" { None } else { Some(filter) };
                        pipe::PipeScanRequest::Containers { filter }
                    } else {
                        pipe::PipeScanRequest::Legacy {
                            selector: legacy_selector,
                        }
                    };
                    Box::new(pipe::PipeScanCommand::new(
                        request,
                        protocols,
                        capture_samples,
                        json,
                        deployment,
                    ))
                }
                PipeCommands::Create {
                    source,
                    target,
                    manual,
                    ai,
                    no_ai,
                    ml,
                    json,
                    deployment,
                } => Box::new(pipe::PipeCreateCommand::new(
                    source, target, manual, ai, no_ai, ml, json, deployment,
                )),
                PipeCommands::List { json, deployment } => {
                    Box::new(pipe::PipeListCommand::new(json, deployment))
                }
                PipeCommands::Activate {
                    pipe_id,
                    trigger,
                    poll_interval,
                    json,
                    deployment,
                } => Box::new(pipe::PipeActivateCommand::new(
                    pipe_id,
                    trigger,
                    poll_interval,
                    json,
                    deployment,
                )),
                PipeCommands::Deactivate {
                    pipe_id,
                    json,
                    deployment,
                } => Box::new(pipe::PipeDeactivateCommand::new(pipe_id, json, deployment)),
                PipeCommands::Trigger {
                    pipe_id,
                    data,
                    json,
                    deployment,
                } => Box::new(pipe::PipeTriggerCommand::new(
                    pipe_id, data, json, deployment,
                )),
                PipeCommands::History {
                    instance_id,
                    limit,
                    json,
                    deployment,
                } => Box::new(pipe::PipeHistoryCommand::new(
                    instance_id,
                    limit,
                    json,
                    deployment,
                )),
                PipeCommands::Replay {
                    execution_id,
                    json,
                    deployment,
                } => Box::new(pipe::PipeReplayCommand::new(execution_id, json, deployment)),
                PipeCommands::Deploy {
                    instance_id,
                    deployment,
                    json,
                } => Box::new(pipe::PipeDeployCommand::new(instance_id, deployment, json)),
            }
        }
        StackerCommands::Agent { command: agent_cmd } => {
            use stacker::console::commands::cli::agent;
            match agent_cmd {
                AgentCommands::Health {
                    app,
                    system,
                    json,
                    deployment,
                } => Box::new(agent::AgentHealthCommand::new(
                    app, json, deployment, system,
                )),
                AgentCommands::Logs {
                    app,
                    limit,
                    json,
                    deployment,
                } => Box::new(agent::AgentLogsCommand::new(
                    app,
                    Some(limit),
                    json,
                    deployment,
                )),
                AgentCommands::Restart {
                    app,
                    force,
                    json,
                    deployment,
                } => Box::new(agent::AgentRestartCommand::new(
                    app, force, json, deployment,
                )),
                AgentCommands::DeployApp {
                    app,
                    image,
                    force,
                    runtime,
                    json,
                    deployment,
                    environment,
                    plan,
                    apply_plan,
                } => Box::new(
                    agent::AgentDeployAppCommand::new(
                        app,
                        image,
                        force,
                        runtime,
                        json,
                        deployment,
                        environment,
                    )
                    .with_plan(plan)
                    .with_apply_plan(apply_plan),
                ),
                AgentCommands::RemoveApp {
                    app,
                    volumes,
                    remove_image,
                    force,
                    json,
                    deployment,
                } => Box::new(agent::AgentRemoveAppCommand::new(
                    app,
                    volumes,
                    remove_image,
                    force,
                    json,
                    deployment,
                )),
                AgentCommands::ConfigureFirewall {
                    action,
                    list,
                    app,
                    public_ports,
                    private_ports,
                    persist,
                    force,
                    json,
                    deployment,
                } => {
                    let effective_action = if list { "list".to_string() } else { action };
                    Box::new(agent::AgentConfigureFirewallCommand::new(
                        effective_action,
                        app,
                        public_ports,
                        private_ports,
                        persist,
                        force,
                        json,
                        deployment,
                    ))
                }
                AgentCommands::ConfigureProxy {
                    app,
                    domain,
                    port,
                    ssl,
                    no_ssl,
                    action,
                    force,
                    json,
                    deployment,
                } => Box::new(agent::AgentConfigureProxyCommand::new(
                    app, domain, port, ssl, no_ssl, action, force, json, deployment,
                )),
                AgentCommands::List { command: list_cmd } => match list_cmd {
                    AgentListCommands::Apps { json, deployment } => {
                        Box::new(agent::AgentListAppsCommand::new(json, deployment))
                    }
                    AgentListCommands::Containers { json, deployment } => {
                        Box::new(agent::AgentListContainersCommand::new(json, deployment))
                    }
                },
                AgentCommands::Status { json, deployment } => {
                    Box::new(agent::AgentStatusCommand::new(json, deployment))
                }
                AgentCommands::History { json, deployment } => {
                    Box::new(agent::AgentHistoryCommand::new(json, deployment))
                }
                AgentCommands::Exec {
                    command_type,
                    params,
                    timeout,
                    json,
                    deployment,
                } => Box::new(agent::AgentExecCommand::new(
                    command_type,
                    params,
                    timeout,
                    json,
                    deployment,
                )),
                AgentCommands::Install {
                    file,
                    persist_config,
                    json,
                } => Box::new(agent::AgentInstallCommand::new(file, persist_config, json)),
            }
        }
        StackerCommands::Cloud { command } => match command {
            CloudCommands::Firewall { command } => match command {
                CloudFirewallCommands::Add {
                    server_id,
                    public_ports,
                    private_ports,
                    dry_run,
                    json,
                } => Box::new(
                    stacker::console::commands::cli::cloud_firewall::CloudFirewallCommand::new(
                        stacker::forms::CloudFirewallAction::Add,
                        server_id,
                        public_ports,
                        private_ports,
                        dry_run,
                        json,
                    ),
                ),
                CloudFirewallCommands::Remove {
                    server_id,
                    public_ports,
                    private_ports,
                    dry_run,
                    json,
                } => Box::new(
                    stacker::console::commands::cli::cloud_firewall::CloudFirewallCommand::new(
                        stacker::forms::CloudFirewallAction::Remove,
                        server_id,
                        public_ports,
                        private_ports,
                        dry_run,
                        json,
                    ),
                ),
                CloudFirewallCommands::List { server_id, json } => Box::new(
                    stacker::console::commands::cli::cloud_firewall::CloudFirewallCommand::new(
                        stacker::forms::CloudFirewallAction::List,
                        server_id,
                        vec![],
                        vec![],
                        false,
                        json,
                    ),
                ),
            },
        },
        StackerCommands::Submit {
            file,
            version,
            description,
            category,
            plan_type,
            price,
        } => Box::new(stacker::console::commands::cli::submit::SubmitCommand::new(
            file,
            version,
            description,
            category,
            plan_type,
            price,
        )),
        StackerCommands::Marketplace { command: mkt_cmd } => match mkt_cmd {
            MarketplaceCommands::Status { name, json } => Box::new(
                stacker::console::commands::cli::marketplace::MarketplaceStatusCommand::new(
                    name, json,
                ),
            ),
            MarketplaceCommands::Logs { name, json } => Box::new(
                stacker::console::commands::cli::marketplace::MarketplaceLogsCommand::new(
                    name, json,
                ),
            ),
            MarketplaceCommands::Submit {
                file,
                version,
                description,
                category,
                plan_type,
                price,
            } => Box::new(stacker::console::commands::cli::submit::SubmitCommand::new(
                file,
                version,
                description,
                category,
                plan_type,
                price,
            )),
        },
        // Completion is handled in main() before this function is called.
        StackerCommands::Completion { .. } => unreachable!(),
        // Target is handled in main() before this function is called.
        StackerCommands::Target { .. } => unreachable!(),
        // Env is handled in main() before this function is called.
        StackerCommands::Env { .. } => unreachable!(),
    };

    Ok(cmd)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn render_command_help(command: &mut clap::Command) -> String {
        let mut buffer = Vec::new();
        command
            .write_long_help(&mut buffer)
            .expect("help rendering should succeed");
        String::from_utf8(buffer).expect("help output should be valid UTF-8")
    }

    #[test]
    fn test_deploy_parses_environment_alias() {
        let cli = Cli::try_parse_from([
            "stacker",
            "deploy",
            "--target",
            "cloud",
            "--env",
            "production",
        ])
        .unwrap();

        match cli.command.unwrap() {
            StackerCommands::Deploy {
                target,
                environment,
                ..
            } => {
                assert_eq!(target.as_deref(), Some("cloud"));
                assert_eq!(environment.as_deref(), Some("production"));
            }
            _ => panic!("expected deploy command"),
        }
    }

    #[test]
    fn test_deploy_parses_environment_long_alias() {
        let cli = Cli::try_parse_from([
            "stacker",
            "deploy",
            "--target",
            "cloud",
            "--environment",
            "staging",
        ])
        .unwrap();

        match cli.command.unwrap() {
            StackerCommands::Deploy { environment, .. } => {
                assert_eq!(environment.as_deref(), Some("staging"));
            }
            _ => panic!("expected deploy command"),
        }
    }

    #[test]
    fn test_whoami_parses() {
        let cli = Cli::try_parse_from(["stacker", "whoami"]).unwrap();

        match cli.command.unwrap() {
            StackerCommands::Whoami {} => {}
            _ => panic!("expected whoami command"),
        }
    }

    #[test]
    fn test_ai_ask_parses_scenario_flags() {
        let cli = Cli::try_parse_from([
            "stacker",
            "ai",
            "ask",
            "continue",
            "--scenario",
            "website-deploy",
            "--step",
            "cloud-deploy",
        ])
        .unwrap();

        match cli.command.unwrap() {
            StackerCommands::Ai(ai_args) => {
                assert_eq!(ai_args.scenario.as_deref(), Some("website-deploy"));
                assert_eq!(ai_args.step.as_deref(), Some("cloud-deploy"));
            }
            _ => panic!("expected ai command"),
        }
    }

    #[test]
    fn test_ai_chat_parses_scenario_flags() {
        let cli = Cli::try_parse_from([
            "stacker",
            "ai",
            "--scenario",
            "website-deploy",
            "--step",
            "init-validate",
        ])
        .unwrap();

        match cli.command.unwrap() {
            StackerCommands::Ai(ai_args) => {
                assert_eq!(ai_args.scenario.as_deref(), Some("website-deploy"));
                assert_eq!(ai_args.step.as_deref(), Some("init-validate"));
            }
            _ => panic!("expected ai command"),
        }
    }

    #[test]
    fn test_pipe_scan_parses_without_selector() {
        let cli = Cli::try_parse_from(["stacker", "pipe", "scan"]).unwrap();
        match cli.command.unwrap() {
            StackerCommands::Pipe {
                command:
                    PipeCommands::Scan {
                        legacy_selector,
                        app,
                        containers,
                        container,
                        ..
                    },
            } => {
                assert!(legacy_selector.is_none());
                assert!(app.is_none());
                assert!(containers.is_none());
                assert!(container.is_none());
            }
            _ => panic!("expected pipe scan command"),
        }
    }

    #[test]
    fn test_pipe_scan_parses_containers_flag() {
        let cli =
            Cli::try_parse_from(["stacker", "pipe", "scan", "--containers", "upload"]).unwrap();
        match cli.command.unwrap() {
            StackerCommands::Pipe {
                command:
                    PipeCommands::Scan {
                        containers,
                        legacy_selector,
                        ..
                    },
            } => {
                assert_eq!(containers.as_deref(), Some("upload"));
                assert!(legacy_selector.is_none());
            }
            _ => panic!("expected pipe scan command"),
        }
    }

    #[test]
    fn test_pipe_scan_parses_app_flag() {
        let cli = Cli::try_parse_from([
            "stacker",
            "pipe",
            "scan",
            "--app",
            "website",
            "--container",
            "website-web-1",
        ])
        .unwrap();
        match cli.command.unwrap() {
            StackerCommands::Pipe {
                command: PipeCommands::Scan { app, container, .. },
            } => {
                assert_eq!(app.as_deref(), Some("website"));
                assert_eq!(container.as_deref(), Some("website-web-1"));
            }
            _ => panic!("expected pipe scan command"),
        }
    }

    #[test]
    fn test_pipe_scan_parses_legacy_selector() {
        let cli = Cli::try_parse_from(["stacker", "pipe", "scan", "website"]).unwrap();
        match cli.command.unwrap() {
            StackerCommands::Pipe {
                command:
                    PipeCommands::Scan {
                        legacy_selector,
                        app,
                        containers,
                        ..
                    },
            } => {
                assert_eq!(legacy_selector.as_deref(), Some("website"));
                assert!(app.is_none());
                assert!(containers.is_none());
            }
            _ => panic!("expected pipe scan command"),
        }
    }

    #[test]
    fn test_pipe_scan_parses_legacy_keyword_app() {
        let cli = Cli::try_parse_from(["stacker", "pipe", "scan", "app"]).unwrap();
        match cli.command.unwrap() {
            StackerCommands::Pipe {
                command:
                    PipeCommands::Scan {
                        legacy_selector,
                        app,
                        containers,
                        ..
                    },
            } => {
                assert_eq!(legacy_selector.as_deref(), Some("app"));
                assert!(app.is_none());
                assert!(containers.is_none());
            }
            _ => panic!("expected pipe scan command"),
        }
    }

    #[test]
    fn test_pipe_scan_parses_legacy_keyword_containers() {
        let cli = Cli::try_parse_from(["stacker", "pipe", "scan", "containers"]).unwrap();
        match cli.command.unwrap() {
            StackerCommands::Pipe {
                command:
                    PipeCommands::Scan {
                        legacy_selector,
                        app,
                        containers,
                        ..
                    },
            } => {
                assert_eq!(legacy_selector.as_deref(), Some("containers"));
                assert!(app.is_none());
                assert!(containers.is_none());
            }
            _ => panic!("expected pipe scan command"),
        }
    }

    #[test]
    fn test_secrets_set_still_parses_local_key_value() {
        let parsed = Cli::try_parse_from(["stacker", "secrets", "set", "DB_PASSWORD=supersecret"]);
        assert!(
            parsed.is_ok(),
            "local secrets set syntax must remain supported"
        );
    }

    #[test]
    fn test_secrets_set_parses_remote_service_flags() {
        let parsed = Cli::try_parse_from([
            "stacker",
            "secrets",
            "set",
            "S3_SECRET_KEY",
            "--project",
            "blog",
            "--service",
            "uploader",
            "--body",
            "supersecret",
        ]);

        assert!(
            parsed.is_ok(),
            "remote service secret syntax should parse successfully"
        );
    }

    #[test]
    fn test_secrets_set_still_parses_explicit_remote_service_scope() {
        let parsed = Cli::try_parse_from([
            "stacker",
            "secrets",
            "set",
            "S3_SECRET_KEY",
            "--scope",
            "service",
            "--service",
            "uploader",
            "--body",
            "supersecret",
        ]);

        assert!(
            parsed.is_ok(),
            "explicit remote service scope should remain supported"
        );
    }

    #[test]
    fn test_secrets_set_parses_remote_server_flags() {
        let parsed = Cli::try_parse_from([
            "stacker",
            "secrets",
            "set",
            "NPM_TOKEN",
            "--scope",
            "server",
            "--server-id",
            "42",
            "--body-file",
            "/tmp/npm-token.txt",
        ]);

        assert!(
            parsed.is_ok(),
            "remote server secret syntax should parse successfully"
        );
    }

    #[test]
    fn test_secrets_list_parses_remote_scope_and_json() {
        let parsed = Cli::try_parse_from([
            "stacker",
            "secrets",
            "list",
            "--project",
            "blog",
            "--service",
            "uploader",
            "--json",
        ]);

        assert!(
            parsed.is_ok(),
            "remote secrets list syntax should parse successfully"
        );
    }

    #[test]
    fn test_secrets_get_parses_service_without_scope() {
        let parsed = Cli::try_parse_from([
            "stacker",
            "secrets",
            "get",
            "S3_BUCKET",
            "--service",
            "upload",
            "--json",
        ]);

        assert!(
            parsed.is_ok(),
            "remote service get should infer service scope from --service"
        );
    }

    #[test]
    fn test_secrets_delete_parses_service_without_scope() {
        let parsed = Cli::try_parse_from([
            "stacker",
            "secrets",
            "delete",
            "S3_BUCKET",
            "--service",
            "upload",
        ]);

        assert!(
            parsed.is_ok(),
            "remote service delete should infer service scope from --service"
        );
    }

    #[test]
    fn test_secrets_apps_parses_project_lookup_flags() {
        let parsed = Cli::try_parse_from(["stacker", "secrets", "apps", "--json"]);

        assert!(
            parsed.is_ok(),
            "remote secrets apps syntax should parse successfully"
        );
    }

    #[test]
    fn test_secrets_apps_parses_register_and_sync() {
        let register = Cli::try_parse_from([
            "stacker",
            "secrets",
            "apps",
            "register",
            "upload",
            "--project",
            "blog",
            "--json",
        ]);
        let sync = Cli::try_parse_from(["stacker", "secrets", "apps", "sync", "--json"]);

        assert!(
            register.is_ok(),
            "secrets apps register should parse successfully"
        );
        assert!(sync.is_ok(), "secrets apps sync should parse successfully");
    }

    #[test]
    fn test_secrets_help_mentions_remote_modes() {
        let mut command = Cli::command();
        let secrets = command
            .find_subcommand_mut("secrets")
            .expect("secrets subcommand should exist");
        let help = render_command_help(secrets);

        assert!(help.contains("Vault-backed secrets"));
        assert!(help.contains("--scope service"));
        assert!(help.contains("--scope server"));
        assert!(help.contains("metadata-only"));
        assert!(help.contains("List valid remote deployable service/app target codes"));
    }

    #[test]
    fn test_secrets_help_describes_service_scope_as_deployable_target() {
        let mut command = Cli::command();
        let secrets = command
            .find_subcommand_mut("secrets")
            .expect("secrets subcommand should exist");
        let help = render_command_help(secrets);

        assert!(help.contains("deployable service/app target"));
        assert!(help.contains("stacker secrets apps"));
    }

    #[test]
    fn test_secrets_get_help_mentions_metadata_only_remote_reads() {
        let mut command = Cli::command();
        let secrets = command
            .find_subcommand_mut("secrets")
            .expect("secrets subcommand should exist");
        let get = secrets
            .find_subcommand_mut("get")
            .expect("get subcommand should exist");
        let help = render_command_help(get);

        assert!(help.contains("metadata-only"));
        assert!(help.contains("--scope <SCOPE>"));
        assert!(help.contains("--json"));
    }
}
