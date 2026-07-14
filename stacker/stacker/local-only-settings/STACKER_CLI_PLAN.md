# Stacker CLI — Implementation Plan

> **Approach**: Test-Driven Development — write automated tests first, then implement.
> **Principles**: Clean Code (Robert C. Martin), Rust idioms (Builder, From/Into, small functions, single responsibility).
> **Date**: 2026-02-22
> **Status**: Draft

---

## Table of Contents

- [Overview](#overview)
- [Clean Code Principles Applied](#clean-code-principles-applied)
- [Architecture & Module Design](#architecture--module-design)
- [Type System Design](#type-system-design)
- [stacker.yml Configuration Schema](#stackeryml-configuration-schema)
- [CLI Command Interface](#cli-command-interface)
- [Test-First Implementation Plan](#test-first-implementation-plan)
- [Step-by-Step Implementation](#step-by-step-implementation)
- [Verification](#verification)
- [Decisions Log](#decisions-log)

---

## Overview

Extend the existing Stacker Rust console binary (`src/console/main.rs`) with new subcommands
enabling developers to deploy simple HTML+JS+CSS apps (and more) by adding a single `stacker.yml`
configuration file to their project.

**Key capabilities:**
- Auto-detect project type, generate Dockerfile and docker-compose.yml when missing
- Deploy locally (docker compose), to cloud (via install container with Terraform/Ansible), or to existing servers (SSH)
- Auto-connect to existing nginx or Nginx Proxy Manager
- AI-assisted Dockerfile generation and troubleshooting (via LLM)
- Deploy Status Panel agent alongside app for monitoring
- Pull install container for Terraform/Ansible execution (no local install needed)
- Standalone for local deploys; optional TryDirect login for cloud/marketplace/AI

---

## Clean Code Principles Applied

### Naming: Intention-Revealing Names (Ch. 2)

Every struct, function, and variable tells its purpose. No abbreviations, no generic names:

```
Bad:  fn proc(c: &Config) -> Res
Good: fn generate_dockerfile(project: &ProjectDetection) -> Result<Dockerfile, GeneratorError>

Bad:  struct Cfg { tp: String, p: String }
Good: struct AppSource { app_type: AppType, source_path: PathBuf }
```

### Functions: Small, Do One Thing (Ch. 3)

Each function does exactly one thing at one level of abstraction. Command handlers
delegate to focused service functions:

```
deploy_command()                        → orchestration only
├── config_parser::load("stacker.yml")  → parsing only
├── detector::detect(&source_path)      → file scanning only
├── generator::dockerfile(...)          → Dockerfile text only
├── generator::compose(...)             → compose YAML only
└── runner::start_containers(...)       → docker execution only
```

### Single Responsibility Principle (SRP)

| Module | Single Responsibility |
|--------|-----------------------|
| `config_parser` | Parse and validate stacker.yml |
| `detector` | Identify project type from filesystem |
| `generator::dockerfile` | Produce Dockerfile content |
| `generator::compose` | Produce docker-compose.yml content |
| `proxy_manager` | Detect and configure reverse proxies |
| `credentials` | Store and retrieve auth tokens |
| `ai_client` | Communicate with LLM providers |
| `install_runner` | Run Terraform/Ansible via container |

### Open/Closed Principle (OCP)

New app types, cloud providers, and proxy types are added by extending enums
and implementing `From`/`Into` — not by modifying existing match arms:

```rust
// Adding a new app type only requires:
// 1. Add variant to AppType enum
// 2. Implement From<AppType> for DockerfileTemplate
// No existing code changes needed.
```

### Dependency Inversion Principle (DIP)

Commands depend on traits, not concrete implementations. This enables testing
with mocks while keeping production code clean:

```rust
// Trait (abstraction)
trait ContainerRuntime {
    fn start(&self, compose_path: &Path) -> Result<(), RuntimeError>;
    fn stop(&self, compose_path: &Path) -> Result<(), RuntimeError>;
    fn logs(&self, service: &str, follow: bool) -> Result<LogStream, RuntimeError>;
}

// Production: DockerComposeRuntime
// Tests: MockContainerRuntime
```

### Error Handling: Use Exceptions (Types), Not Return Codes (Ch. 7)

Following the existing codebase pattern — custom error enums with `Display`,
`From` conversions for error wrapping, and `anyhow` for ad-hoc contexts.
No string-based error passing.

### DRY: Don't Repeat Yourself

Shared template rendering, env var interpolation, and YAML generation are
extracted into reusable utilities — not duplicated across commands.

---

## Architecture & Module Design

```
stacker/src/
├── cli/                                  # NEW: Core CLI library modules
│   ├── mod.rs                            # Public API surface
│   ├── config_parser.rs                  # stacker.yml → StackerConfig
│   ├── detector.rs                       # Filesystem → ProjectDetection
│   ├── error.rs                          # CliError enum (single error hierarchy)
│   ├── generator/
│   │   ├── mod.rs
│   │   ├── dockerfile.rs                 # AppType → Dockerfile content
│   │   ├── compose.rs                    # StackerConfig → docker-compose.yml
│   │   └── templates.rs                  # Embedded Dockerfile templates
│   ├── proxy_manager.rs                  # Proxy detection + configuration
│   ├── ai_client.rs                      # LLM provider abstraction
│   ├── credentials.rs                    # Token storage + refresh
│   └── install_runner.rs                 # Install container orchestration
│
├── console/
│   ├── main.rs                           # Extended Commands enum
│   └── commands/
│       ├── cli/                          # NEW: CLI command implementations
│       │   ├── mod.rs
│       │   ├── login.rs                  # CallableTrait impl
│       │   ├── init.rs
│       │   ├── deploy/
│       │   │   ├── mod.rs                # DeployCommand dispatcher
│       │   │   ├── local.rs              # LocalDeployStrategy
│       │   │   ├── cloud.rs              # CloudDeployStrategy
│       │   │   └── server.rs             # ServerDeployStrategy
│       │   ├── logs.rs
│       │   ├── status.rs
│       │   ├── destroy.rs
│       │   ├── config.rs
│       │   ├── ai.rs
│       │   ├── proxy.rs
│       │   └── update.rs
│       └── ...existing commands...
```

### Dependency Graph (no cycles)

```
commands/cli/*
    └── depends on → cli/*  (library modules)
                        └── depends on → models, helpers, connectors  (existing stacker infra)
```

---

## Type System Design

### Core Types with Builder, From/Into

All types follow existing codebase conventions: `Debug` always, `Clone + Serialize + Deserialize`
on DTOs, `Default` on structs with optional fields, `Validate` on user inputs.

```rust
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// cli/config_parser.rs — The central config type
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Root configuration parsed from stacker.yml.
/// Every optional section defaults to sensible values via Default.
#[derive(Debug, Clone, Serialize, Deserialize, Default, Validate)]
pub struct StackerConfig {
    #[validate(min_length = 1)]
    #[validate(max_length = 128)]
    pub name: String,

    #[serde(default)]
    pub version: Option<String>,

    #[serde(default)]
    pub organization: Option<String>,

    pub app: AppSource,

    #[serde(default)]
    pub services: Vec<ServiceDefinition>,

    #[serde(default)]
    pub proxy: ProxyConfig,

    #[serde(default)]
    pub deploy: DeployConfig,

    #[serde(default)]
    pub ai: AiConfig,

    #[serde(default)]
    pub monitoring: MonitoringConfig,

    #[serde(default)]
    pub hooks: HookConfig,

    #[serde(default)]
    pub env_file: Option<PathBuf>,

    #[serde(default)]
    pub env: HashMap<String, String>,
}

impl StackerConfig {
    /// Load from file path, resolving env vars and validating.
    pub fn from_file(path: &Path) -> Result<Self, CliError> { ... }

    /// Validate cross-field constraints beyond serde_valid.
    pub fn validate_semantics(&self) -> Result<(), Vec<ValidationIssue>> { ... }
}
```

### Enums with Display, From, serde rename

```rust
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// AppType — Discoverable project types
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AppType {
    Static,
    Node,
    Python,
    Rust,
    Go,
    Php,
    Custom,
}

impl std::fmt::Display for AppType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Static => write!(f, "static"),
            Self::Node   => write!(f, "node"),
            Self::Python => write!(f, "python"),
            Self::Rust   => write!(f, "rust"),
            Self::Go     => write!(f, "go"),
            Self::Php    => write!(f, "php"),
            Self::Custom => write!(f, "custom"),
        }
    }
}

impl Default for AppType {
    fn default() -> Self { Self::Static }
}
```

### Builder Pattern — ConfigBuilder

Fluent builder for constructing `StackerConfig` programmatically (used by `stacker init`
and tests). Follows the `JsonResponseBuilder<T>` pattern already in the codebase:

```rust
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// ConfigBuilder — fluent stacker.yml construction
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, Default)]
pub struct ConfigBuilder {
    name: Option<String>,
    version: Option<String>,
    organization: Option<String>,
    app_type: Option<AppType>,
    app_path: Option<PathBuf>,
    services: Vec<ServiceDefinition>,
    proxy: Option<ProxyConfig>,
    deploy_target: Option<DeployTarget>,
    ai: Option<AiConfig>,
    monitoring: Option<MonitoringConfig>,
}

impl ConfigBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn name<S: Into<String>>(mut self, name: S) -> Self {
        self.name = Some(name.into());
        self
    }

    pub fn app_type(mut self, app_type: AppType) -> Self {
        self.app_type = Some(app_type);
        self
    }

    pub fn app_path<P: Into<PathBuf>>(mut self, path: P) -> Self {
        self.app_path = Some(path.into());
        self
    }

    pub fn add_service(mut self, service: ServiceDefinition) -> Self {
        self.services.push(service);
        self
    }

    pub fn proxy(mut self, proxy: ProxyConfig) -> Self {
        self.proxy = Some(proxy);
        self
    }

    pub fn deploy_target(mut self, target: DeployTarget) -> Self {
        self.deploy_target = Some(target);
        self
    }

    pub fn ai(mut self, ai: AiConfig) -> Self {
        self.ai = Some(ai);
        self
    }

    pub fn monitoring(mut self, monitoring: MonitoringConfig) -> Self {
        self.monitoring = Some(monitoring);
        self
    }

    /// Consume the builder, validate, and produce StackerConfig.
    /// Returns CliError::ConfigValidation if required fields are missing.
    pub fn build(self) -> Result<StackerConfig, CliError> {
        let name = self.name
            .ok_or(CliError::ConfigValidation("name is required".into()))?;

        Ok(StackerConfig {
            name,
            version: self.version,
            organization: self.organization,
            app: AppSource {
                app_type: self.app_type.unwrap_or_default(),
                path: self.app_path.unwrap_or_else(|| PathBuf::from(".")),
                ..Default::default()
            },
            services: self.services,
            proxy: self.proxy.unwrap_or_default(),
            deploy: DeployConfig {
                target: self.deploy_target.unwrap_or_default(),
                ..Default::default()
            },
            ai: self.ai.unwrap_or_default(),
            monitoring: self.monitoring.unwrap_or_default(),
            ..Default::default()
        })
    }
}
```

### Builder Pattern — DockerfileBuilder

```rust
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// DockerfileBuilder — construct Dockerfile content
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, Default)]
pub struct DockerfileBuilder {
    base_image: Option<String>,
    workdir: Option<String>,
    copy_instructions: Vec<(String, String)>,
    run_commands: Vec<String>,
    expose_ports: Vec<u16>,
    entrypoint: Option<Vec<String>>,
    cmd: Option<Vec<String>>,
    build_args: Vec<(String, String)>,
    stages: Vec<DockerfileStage>,
}

impl DockerfileBuilder {
    pub fn new() -> Self { Self::default() }

    pub fn base_image<S: Into<String>>(mut self, image: S) -> Self {
        self.base_image = Some(image.into());
        self
    }

    pub fn workdir<S: Into<String>>(mut self, dir: S) -> Self {
        self.workdir = Some(dir.into());
        self
    }

    pub fn copy<S: Into<String>>(mut self, src: S, dst: S) -> Self {
        self.copy_instructions.push((src.into(), dst.into()));
        self
    }

    pub fn run<S: Into<String>>(mut self, cmd: S) -> Self {
        self.run_commands.push(cmd.into());
        self
    }

    pub fn expose(mut self, port: u16) -> Self {
        self.expose_ports.push(port);
        self
    }

    pub fn cmd(mut self, cmd: Vec<String>) -> Self {
        self.cmd = Some(cmd);
        self
    }

    pub fn build_arg<S: Into<String>>(mut self, key: S, default: S) -> Self {
        self.build_args.push((key.into(), default.into()));
        self
    }

    /// Produce the Dockerfile content as a String.
    pub fn build(self) -> Result<String, CliError> {
        let base = self.base_image
            .ok_or(CliError::GeneratorError("base_image is required".into()))?;
        let mut lines = Vec::new();
        lines.push(format!("FROM {base}"));
        // ... assemble all instructions
        Ok(lines.join("\n"))
    }
}
```

### From/Into Conversions — Type-Safe Transformations

Following the heavy `From`/`TryFrom` usage in the existing codebase (see
`DeploymentIdentifier`, form↔model conversions, view mappings):

```rust
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// From<AppType> for DockerfileBuilder — auto-configure by type
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

impl From<AppType> for DockerfileBuilder {
    fn from(app_type: AppType) -> Self {
        match app_type {
            AppType::Static => DockerfileBuilder::new()
                .base_image("nginx:alpine")
                .copy(".", "/usr/share/nginx/html")
                .expose(80),

            AppType::Node => DockerfileBuilder::new()
                .base_image("node:lts-alpine")
                .workdir("/app")
                .copy("package*.json", ".")
                .run("npm ci --only=production")
                .copy(".", ".")
                .expose(3000)
                .cmd(vec!["node".into(), "server.js".into()]),

            AppType::Python => DockerfileBuilder::new()
                .base_image("python:3.12-slim")
                .workdir("/app")
                .copy("requirements.txt", ".")
                .run("pip install --no-cache-dir -r requirements.txt")
                .copy(".", ".")
                .expose(8000),

            AppType::Rust => DockerfileBuilder::new()
                .base_image("rust:1-slim-bookworm")
                .workdir("/app")
                .copy("Cargo.toml", ".")
                .copy("Cargo.lock", ".")
                .copy("src", "src")
                .run("cargo build --release")
                .expose(8080),

            AppType::Go => DockerfileBuilder::new()
                .base_image("golang:1.22-alpine")
                .workdir("/app")
                .copy("go.mod", ".")
                .copy("go.sum", ".")
                .run("go mod download")
                .copy(".", ".")
                .run("go build -o /app/main .")
                .expose(8080),

            AppType::Php => DockerfileBuilder::new()
                .base_image("php:8.3-apache")
                .copy(".", "/var/www/html")
                .expose(80),

            AppType::Custom => DockerfileBuilder::new(),
        }
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// From<ProjectDetection> for AppType — detector → type
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

impl From<&ProjectDetection> for AppType {
    fn from(detection: &ProjectDetection) -> Self {
        detection.app_type
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// From<StackerConfig> for ComposeDefinition — config → compose
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

impl TryFrom<&StackerConfig> for ComposeDefinition {
    type Error = CliError;

    fn try_from(config: &StackerConfig) -> Result<Self, Self::Error> {
        let mut services = Vec::new();

        // App service
        let app_service = ComposeService::from(&config.app);
        services.push(app_service);

        // Additional services
        for svc in &config.services {
            services.push(ComposeService::from(svc));
        }

        // Proxy service (if configured)
        if config.proxy.proxy_type != ProxyType::None {
            let proxy_service = ComposeService::try_from(&config.proxy)?;
            services.push(proxy_service);
        }

        // Status panel (if monitoring enabled)
        if config.monitoring.status_panel {
            services.push(ComposeService::status_panel());
        }

        Ok(ComposeDefinition { services, ..Default::default() })
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// From<&ServiceDefinition> for ComposeService — user service → compose
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

impl From<&ServiceDefinition> for ComposeService {
    fn from(svc: &ServiceDefinition) -> Self {
        ComposeService {
            name: svc.name.clone(),
            image: svc.image.clone(),
            ports: svc.ports.clone(),
            environment: svc.environment.clone(),
            volumes: svc.volumes.clone(),
            ..Default::default()
        }
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// From<StackerConfig> for DeployPayload — config → install service format
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

impl TryFrom<&StackerConfig> for DeployPayload {
    type Error = CliError;

    fn try_from(config: &StackerConfig) -> Result<Self, Self::Error> {
        // Transforms stacker.yml config into the Payload format
        // expected by InstallServiceClient::deploy()
        // (see forms/project/payload.rs for the target structure)
        ...
    }
}
```

### Error Hierarchy — Single Unified Type

Following the `ConnectorError` / `DeploymentValidationError` pattern in the codebase.
One `CliError` enum covers all CLI failure modes with structured variants:

```rust
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// cli/error.rs — Unified CLI error type
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug)]
pub enum CliError {
    // Config errors
    ConfigNotFound { path: PathBuf },
    ConfigParseFailed { source: serde_yaml::Error },
    ConfigValidation(String),
    EnvVarNotFound { var_name: String },

    // Detection errors
    DetectionFailed { path: PathBuf, reason: String },

    // Generator errors
    GeneratorError(String),
    DockerfileExists { path: PathBuf },

    // Deployment errors
    DeployFailed { target: DeployTarget, reason: String },
    LoginRequired { feature: String },
    CloudProviderMissing,
    ServerHostMissing,

    // Runtime errors
    ContainerRuntimeUnavailable,
    CommandFailed { command: String, exit_code: i32 },

    // Auth errors
    AuthFailed(String),
    TokenExpired,

    // AI errors
    AiNotConfigured,
    AiProviderError { provider: String, message: String },

    // Proxy errors
    ProxyConfigFailed(String),

    // IO errors
    Io(std::io::Error),
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ConfigNotFound { path } =>
                write!(f, "Configuration file not found: {}", path.display()),
            Self::ConfigParseFailed { source } =>
                write!(f, "Failed to parse stacker.yml: {source}"),
            Self::ConfigValidation(msg) =>
                write!(f, "Configuration validation error: {msg}"),
            Self::EnvVarNotFound { var_name } =>
                write!(f, "Environment variable not found: ${var_name}"),
            Self::LoginRequired { feature } =>
                write!(f, "Login required for {feature}. Run: stacker login"),
            Self::ContainerRuntimeUnavailable =>
                write!(f, "Docker is not running. Install Docker or start the Docker daemon."),
            // ... every variant has a human-readable message
            _ => write!(f, "{self:?}"),
        }
    }
}

impl std::error::Error for CliError {}

// From conversions for ergonomic error propagation with ?
impl From<std::io::Error> for CliError {
    fn from(err: std::io::Error) -> Self { Self::Io(err) }
}

impl From<serde_yaml::Error> for CliError {
    fn from(err: serde_yaml::Error) -> Self { Self::ConfigParseFailed { source: err } }
}
```

### Strategy Pattern — Deploy Targets

Each deploy target is a strategy implementing a common trait.
New targets are added by implementing `DeployStrategy` — no modification of existing code (OCP):

```rust
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Deploy strategy trait (DIP + Strategy pattern)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[async_trait]
pub trait DeployStrategy {
    /// Validate that all prerequisites are met for this target.
    fn validate(&self, config: &StackerConfig) -> Result<(), CliError>;

    /// Execute the deployment.
    async fn deploy(&self, context: &DeployContext) -> Result<DeployResult, CliError>;

    /// Tear down a deployment created by this strategy.
    async fn destroy(&self, context: &DeployContext) -> Result<(), CliError>;
}

// Concrete strategies
pub struct LocalDeploy;        // docker compose up/down
pub struct CloudDeploy;        // install container → Terraform/Ansible
pub struct ServerDeploy;       // SSH + docker compose or Ansible

// Factory: DeployTarget enum → strategy (From pattern)
impl DeployTarget {
    pub fn strategy(&self) -> Box<dyn DeployStrategy> {
        match self {
            DeployTarget::Local  => Box::new(LocalDeploy),
            DeployTarget::Cloud  => Box::new(CloudDeploy),
            DeployTarget::Server => Box::new(ServerDeploy),
        }
    }
}
```

### Trait-Based Abstractions for Testability (DIP)

Following the `UserServiceConnector` / `MockUserServiceConnector` pattern:

```rust
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Abstractions for testing — trait + mock pairs
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// Container runtime
#[async_trait]
pub trait ContainerRuntime: Send + Sync {
    async fn compose_up(&self, path: &Path, build: bool) -> Result<(), CliError>;
    async fn compose_down(&self, path: &Path, volumes: bool) -> Result<(), CliError>;
    async fn compose_logs(&self, path: &Path, service: Option<&str>,
                          follow: bool, tail: Option<u32>) -> Result<(), CliError>;
    async fn list_containers(&self) -> Result<Vec<ContainerInfo>, CliError>;
    fn is_available(&self) -> bool;
}

pub struct DockerComposeRuntime;     // Production
pub struct MockContainerRuntime;     // Tests

// Filesystem (for detector/generator testing without tempdir)
pub trait FileSystem: Send + Sync {
    fn exists(&self, path: &Path) -> bool;
    fn read_to_string(&self, path: &Path) -> Result<String, CliError>;
    fn write(&self, path: &Path, content: &str) -> Result<(), CliError>;
    fn list_dir(&self, path: &Path) -> Result<Vec<PathBuf>, CliError>;
}

pub struct RealFileSystem;           // Production
pub struct MockFileSystem;           // Tests — in-memory HashMap<PathBuf, String>

// AI provider
#[async_trait]
pub trait AiProvider: Send + Sync {
    async fn complete(&self, prompt: &str, context: &str) -> Result<String, CliError>;
}

pub struct OpenAiProvider;
pub struct OllamaProvider;
pub struct MockAiProvider;           // Tests — returns canned responses
```

### Validation — Structured Issues

```rust
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Validation results (like ValidateStackConfigTool pattern)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationIssue {
    pub severity: Severity,
    pub code: String,
    pub message: String,
    pub field: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Error,
    Warning,
    Info,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Error   => write!(f, "error"),
            Self::Warning => write!(f, "warning"),
            Self::Info    => write!(f, "info"),
        }
    }
}
```

---

## stacker.yml Configuration Schema

```yaml
# ===== Project Identity =====
name: my-landing-page             # required
version: "1.0"                    # optional
organization: acme-corp           # optional, set via `stacker login`

# ===== Application Source =====
app:
  type: static                    # static | node | python | rust | go | php | custom
  path: ./src                     # app source root (default: .)
  dockerfile: ./Dockerfile        # optional — auto-generated if missing
  image: registry.io/myapp:v1     # optional — skip build if provided
  build:
    context: .
    args:
      NODE_ENV: production
  ports:                           # optional — overrides default port from type
    - "8080:3000"
  volumes:                         # optional — volume mounts for the app
    - "./uploads:/app/uploads"
  environment:                     # optional — merged with top-level env (app wins)
    NODE_ENV: production

# ===== Services =====
services:
  - name: postgres
    image: postgres:16
    ports: ["5432:5432"]
    environment:
      POSTGRES_DB: myapp
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    volumes:
      - pgdata:/var/lib/postgresql/data
  - name: redis
    image: redis:7-alpine

# ===== Proxy / Ingress =====
proxy:
  type: nginx                     # nginx | nginx-proxy-manager | traefik | none
  auto_detect: true
  domains:
    - domain: myapp.example.com
      ssl: auto                   # auto | manual | off
      upstream: app:3000
  config: ./nginx.conf

# ===== Deployment Target =====
deploy:
  target: local                   # local | cloud | server
  compose_file: ./docker-compose.yml

  cloud:
    provider: hetzner             # hetzner | digitalocean | aws | linode | vultr
    region: fsn1
    size: cpx21
    ssh_key: ~/.ssh/id_ed25519

  server:
    host: 192.168.1.100
    user: deploy
    ssh_key: ~/.ssh/id_ed25519
    port: 22

# ===== AI Assistant =====
ai:
  enabled: true
  provider: openai                # openai | anthropic | ollama | custom
  model: gpt-4o
  api_key: ${OPENAI_API_KEY}
  endpoint: null
  tasks: [dockerfile, compose, troubleshoot, security]

# ===== Monitoring =====
monitoring:
  status_panel: true
  healthcheck:
    endpoint: /health
    interval: 30s
  metrics:
    enabled: true
    telegraf: false

# ===== Lifecycle Hooks =====
hooks:
  pre_build: ./scripts/pre-build.sh
  post_deploy: ./scripts/post-deploy.sh
  on_failure: ./scripts/on-failure.sh

# ===== Environment =====
env_file: .env
env:
  APP_PORT: "3000"
  LOG_LEVEL: info
```

### Minimal config (static HTML app)

```yaml
name: my-site
app:
  type: static
  path: ./public
```

---

## CLI Command Interface

```
stacker login      [--org <name>] [--domain <domain>] [--api-url <url>]
stacker init       [--type static|node|python|rust|go|php] [--with-proxy] [--with-ai]
stacker deploy     [--target local|cloud|server] [--file stacker.yml] [--dry-run] [--force-rebuild]
stacker logs       [--service <name>] [--follow] [--tail <n>] [--since <duration>]
stacker status     [--json] [--watch]
stacker destroy    [--volumes] [--confirm]
stacker config validate  [--file stacker.yml]
stacker config show      [--file stacker.yml]
stacker ai ask           "<question>" [--context deploy|compose|dockerfile]
stacker proxy add        <domain> [--upstream <host:port>] [--ssl auto|manual|off]
stacker proxy detect
stacker update     [--channel stable|nightly]
```

---

## Test-First Implementation Plan

### Dev-Dependencies to Add

```toml
# stacker/Cargo.toml [dev-dependencies] — additions
assert_cmd = "2.0"       # CLI binary testing
predicates = "3.0"       # Assertion helpers for assert_cmd
tempfile = "3"            # Temp dirs for project scaffolding tests
mockito = "1"             # HTTP mock server
```

### Test Phases and Files

Tests are organized in dependency order — each phase builds on types from the previous.

---

### Phase 0: Error Types + Core Enums (foundation)

**File: `src/cli/error.rs` — `#[cfg(test)] mod tests`**

```
test_cli_error_display_config_not_found
  — Create CliError::ConfigNotFound { path: "/tmp/stacker.yml".into() }
  — Assert: display contains "Configuration file not found: /tmp/stacker.yml"

test_cli_error_display_env_var_not_found
  — Create CliError::EnvVarNotFound { var_name: "DB_PASSWORD".into() }
  — Assert: display contains "DB_PASSWORD"

test_cli_error_display_login_required
  — Create CliError::LoginRequired { feature: "cloud deploy".into() }
  — Assert: display contains "stacker login"

test_cli_error_from_io_error
  — Create std::io::Error → convert via From
  — Assert: matches CliError::Io(_)

test_cli_error_from_yaml_error
  — Create serde_yaml parse error → convert via From
  — Assert: matches CliError::ConfigParseFailed { .. }

test_app_type_display
  — For each AppType variant: assert display matches serde rename
  — Static→"static", Node→"node", Python→"python" etc.

test_app_type_serde_roundtrip
  — Serialize AppType::Node → deserialize back
  — Assert: equality preserved

test_app_type_default_is_static
  — Assert: AppType::default() == AppType::Static

test_deploy_target_display
  — DeployTarget::Cloud → "cloud"
  — DeployTarget::Local → "local"
  — DeployTarget::Server → "server"

test_deploy_target_default_is_local
  — Assert: DeployTarget::default() == DeployTarget::Local

test_proxy_type_display
  — ProxyType::Nginx → "nginx"
  — ProxyType::NginxProxyManager → "nginx-proxy-manager"
  — ProxyType::None → "none"

test_severity_display
  — Severity::Error → "error"
  — Severity::Warning → "warning"

test_validation_issue_serialize
  — Create ValidationIssue with code/message/field
  — Serialize to JSON → assert expected structure
```

**13 tests** — Establishes error hierarchy and enum behavior.

---

### Phase 1: Config Parser + Builder

**File: `src/cli/config_parser.rs` — `#[cfg(test)] mod tests`**

```
test_parse_minimal_config
  — Parse: name + app.type + app.path only
  — Assert: name="my-site", app.app_type=Static, app.path="./public"
  — Assert: all optional sections are Default values

test_parse_full_config
  — Parse complete stacker.yml with every section populated
  — Assert: every field parsed correctly, services.len() correct, proxy domains correct

test_parse_env_var_interpolation
  — Set env var TEST_DB_PASS=secret123
  — Parse config with password: ${TEST_DB_PASS}
  — Assert: resolved to "secret123"

test_parse_env_var_missing_returns_error
  — Parse config with ${NONEXISTENT_VAR}
  — Assert: CliError::EnvVarNotFound { var_name: "NONEXISTENT_VAR" }

test_parse_env_file_loads_vars
  — Write .env to tempdir with KEY=value
  — Parse config with env_file: .env
  — Assert: env map contains KEY=value

test_parse_invalid_app_type_returns_error
  — Parse: app.type: cobol
  — Assert: serde error mentioning unknown variant

test_parse_missing_name_returns_error
  — Parse config without name field
  — Assert: CliError::ConfigValidation mentioning "name"

test_parse_services_array
  — Parse config with 3 services (postgres, redis, minio)
  — Assert: services.len()==3, each has correct name/image/ports

test_parse_proxy_domains
  — Parse proxy with 2 domains, different ssl settings
  — Assert: domains[0].ssl == SslMode::Auto, domains[1].upstream correct

test_parse_ai_section_with_ollama
  — Parse ai with provider=ollama, custom endpoint
  — Assert: ai.provider==AiProvider::Ollama, ai.endpoint present

test_default_deploy_target_is_local
  — Parse config without deploy section
  — Assert: config.deploy.target == DeployTarget::Local

test_default_proxy_type_is_none
  — Parse config without proxy section
  — Assert: config.proxy.proxy_type == ProxyType::None

test_config_file_not_found
  — StackerConfig::from_file(Path::new("/nonexistent/stacker.yml"))
  — Assert: CliError::ConfigNotFound { path }

test_config_invalid_yaml_syntax
  — Parse "{{invalid: yaml: :::"
  — Assert: CliError::ConfigParseFailed

test_validate_semantics_cloud_without_provider
  — Config with deploy.target=Cloud but cloud.provider=None
  — Assert: validate_semantics() returns error with "provider"

test_validate_semantics_server_without_host
  — Config with deploy.target=Server but server.host=None
  — Assert: error with "host"

test_validate_semantics_port_conflict
  — Config with two services both on port 8080
  — Assert: warning about port conflict

test_validate_semantics_no_image_no_dockerfile_custom_type
  — Config with app.type=Custom, no image, no dockerfile
  — Assert: error "need image or dockerfile"

test_validate_semantics_happy_path
  — Valid full config
  — Assert: no issues returned
```

**ConfigBuilder tests (same file):**

```
test_config_builder_minimal
  — ConfigBuilder::new().name("test").build()
  — Assert: Ok(config) with name="test", defaults everywhere

test_config_builder_fluent_chain
  — ConfigBuilder::new()
      .name("my-app")
      .app_type(AppType::Node)
      .app_path("./src")
      .add_service(postgres_service)
      .proxy(proxy_config)
      .build()
  — Assert: all fields set correctly

test_config_builder_missing_name_returns_error
  — ConfigBuilder::new().app_type(AppType::Static).build()
  — Assert: Err(CliError::ConfigValidation("name is required"))

test_config_builder_default_app_type_is_static
  — ConfigBuilder::new().name("x").build()
  — Assert: config.app.app_type == AppType::Static

test_config_builder_to_yaml_roundtrip
  — Build config via builder → serialize to YAML → parse back
  — Assert: both match

test_config_builder_multiple_services
  — Add 3 services via chained .add_service()
  — Assert: config.services.len() == 3
```

**25 tests** — Config parsing, env interpolation, validation, builder.

---

### Phase 2: Project Detector

**File: `src/cli/detector.rs` — `#[cfg(test)] mod tests`**

Uses `MockFileSystem` trait mock to avoid tempdir I/O:

```
test_detect_static_html
  — MockFileSystem with ["index.html", "style.css"]
  — Assert: detection.app_type == AppType::Static

test_detect_node_project
  — MockFileSystem with ["package.json", "src/index.js"]
  — Assert: detection.app_type == AppType::Node

test_detect_python_requirements
  — MockFileSystem with ["requirements.txt", "app.py"]
  — Assert: detection.app_type == AppType::Python

test_detect_python_pyproject
  — MockFileSystem with ["pyproject.toml"]
  — Assert: detection.app_type == AppType::Python

test_detect_rust_project
  — MockFileSystem with ["Cargo.toml", "src/main.rs"]
  — Assert: detection.app_type == AppType::Rust

test_detect_go_project
  — MockFileSystem with ["go.mod", "main.go"]
  — Assert: detection.app_type == AppType::Go

test_detect_php_composer
  — MockFileSystem with ["composer.json", "public/index.php"]
  — Assert: detection.app_type == AppType::Php

test_detect_empty_directory
  — MockFileSystem with []
  — Assert: detection.app_type == AppType::Custom (unknown fallback)

test_detect_priority_node_over_static
  — MockFileSystem with ["package.json", "index.html"]
  — Assert: detection.app_type == AppType::Node

test_detect_existing_dockerfile_flag
  — MockFileSystem with ["Dockerfile", "package.json"]
  — Assert: detection.has_dockerfile == true

test_detect_existing_compose_flag
  — MockFileSystem with ["docker-compose.yml", "index.html"]
  — Assert: detection.has_compose == true

test_detect_env_file_flag
  — MockFileSystem with [".env", "index.html"]
  — Assert: detection.has_env_file == true

test_detection_to_app_type_via_from
  — Create ProjectDetection { app_type: AppType::Node, .. }
  — let app_type: AppType = AppType::from(&detection);
  — Assert: app_type == AppType::Node
```

**13 tests** — Project detection with mock filesystem.

---

### Phase 3: Generators

**File: `src/cli/generator/dockerfile.rs` — `#[cfg(test)] mod tests`**

```
test_dockerfile_builder_static
  — DockerfileBuilder::from(AppType::Static).build()
  — Assert: contains "FROM nginx:alpine", "COPY . /usr/share/nginx/html"

test_dockerfile_builder_node
  — DockerfileBuilder::from(AppType::Node).build()
  — Assert: contains "FROM node:", "npm ci", "EXPOSE 3000"

test_dockerfile_builder_python
  — DockerfileBuilder::from(AppType::Python).build()
  — Assert: contains "FROM python:3.12-slim", "pip install"

test_dockerfile_builder_rust
  — DockerfileBuilder::from(AppType::Rust).build()
  — Assert: contains "FROM rust:", "cargo build --release"

test_dockerfile_builder_go
  — DockerfileBuilder::from(AppType::Go).build()
  — Assert: contains "FROM golang:", "go build"

test_dockerfile_builder_php
  — DockerfileBuilder::from(AppType::Php).build()
  — Assert: contains "FROM php:", "/var/www/html"

test_dockerfile_builder_custom_base_image
  — DockerfileBuilder::new().base_image("ubuntu:22.04").build()
  — Assert: starts with "FROM ubuntu:22.04"

test_dockerfile_builder_with_build_args
  — DockerfileBuilder::from(AppType::Node)
      .build_arg("NODE_ENV", "production")
      .build()
  — Assert: contains "ARG NODE_ENV"

test_dockerfile_builder_with_custom_path
  — DockerfileBuilder::new()
      .base_image("nginx:alpine")
      .copy("./dist", "/usr/share/nginx/html")
      .build()
  — Assert: contains "COPY ./dist"

test_dockerfile_builder_missing_base_image_returns_error
  — DockerfileBuilder::new().copy(".", ".").build()
  — Assert: Err(CliError::GeneratorError) mentioning "base_image"

test_dockerfile_builder_chaining_returns_self
  — Verify each method returns Self for chaining:
    DockerfileBuilder::new()
      .base_image("x").workdir("/app").copy("a","b")
      .run("cmd").expose(80).cmd(vec![]).build_arg("K","V")
      .build()
  — Assert: Ok — all methods chainable

test_generate_does_not_overwrite_existing_dockerfile
  — MockFileSystem with existing Dockerfile
  — Call generate → assert CliError::DockerfileExists
```

**12 tests** — Dockerfile builder + From<AppType> conversions.

**File: `src/cli/generator/compose.rs` — `#[cfg(test)] mod tests`**

```
test_compose_from_minimal_config
  — Config: app only, no services
  — ComposeDefinition::try_from(&config)
  — Assert: 1 service ("app"), valid YAML output

test_compose_from_config_with_services
  — Config with postgres + redis
  — Assert: 3 services total, correct images/ports

test_compose_from_config_with_nginx_proxy
  — Config with proxy.type=Nginx, 1 domain
  — Assert: nginx service present, depends_on app, port 80/443

test_compose_from_config_with_npm_proxy
  — Config with proxy.type=NginxProxyManager
  — Assert: NPM service with ports 80, 81, 443

test_compose_from_config_with_status_panel
  — Config with monitoring.status_panel=true
  — Assert: status-panel service present

test_compose_service_from_service_definition
  — ServiceDefinition { name: "pg", image: "postgres:16", ports: ["5432:5432"] }
  — ComposeService::from(&svc)
  — Assert: name, image, ports correct

test_compose_output_is_valid_yaml
  — Generate from full config → serde_yaml::from_str(&output)
  — Assert: roundtrip succeeds

test_compose_includes_named_volumes
  — Config with service using named volumes
  — Assert: top-level volumes section in output

test_compose_includes_default_network
  — Any config → compose output
  — Assert: networks section with default bridge

test_compose_env_vars_rendered
  — Config with app env vars
  — Assert: environment section in compose YAML

test_compose_port_format
  — Service with ports ["8080:80", "443:443"]
  — Assert: ports rendered as "8080:80" strings in YAML
```

**11 tests** — Compose generation via TryFrom<&StackerConfig>.

---

### Phase 4: Credentials

**File: `src/cli/credentials.rs` — `#[cfg(test)] mod tests`**

```
test_credentials_save_and_load
  — Save Credentials { token, org, domain, api_url } to tempdir
  — Load from same path → assert fields match

test_credentials_with_org_and_domain
  — Save with org="acme-corp", domain="acme.com"
  — Load → assert correct

test_credentials_missing_file_returns_none
  — Load from nonexistent path
  — Assert: Ok(None)

test_credentials_corrupted_file_returns_error
  — Write "not json" to credentials path
  — Load → assert CliError

test_credentials_is_expired_true
  — Credentials with expires_at in the past
  — Assert: is_expired() == true

test_credentials_is_expired_false
  — Credentials with expires_at in the future
  — Assert: is_expired() == false

test_credentials_refresh_token
  — Mock OAuth endpoint (mockito) returning new token
  — Call refresh() → assert new token saved

test_credentials_default_config_dir
  — Assert: default_config_dir() returns ~/.config/stacker (Linux)
    or ~/Library/Application Support/stacker (macOS)
```

**8 tests** — Token storage, expiry, refresh.

---

### Phase 5: Proxy Manager

**File: `src/cli/proxy_manager.rs` — `#[cfg(test)] mod tests`**

```
test_generate_nginx_server_block
  — Input: DomainConfig { domain: "app.example.com", upstream: "app:3000", ssl: Auto }
  — Assert: output contains server_name, proxy_pass, ssl directives

test_generate_nginx_multiple_domains
  — 2 DomainConfig entries → 2 server blocks

test_detect_proxy_nginx_from_containers
  — Mock container list with container named "nginx" on port 80
  — Assert: ProxyDetection { proxy_type: ProxyType::Nginx, ports: [80] }

test_detect_proxy_npm_from_containers
  — Mock container with ports 80, 81, 443
  — Assert: ProxyDetection { proxy_type: ProxyType::NginxProxyManager }

test_detect_no_proxy
  — Empty container list
  — Assert: ProxyDetection { proxy_type: ProxyType::None }

test_proxy_type_from_string
  — "nginx" → ProxyType::Nginx
  — "nginx-proxy-manager" → ProxyType::NginxProxyManager
  — "traefik" → ProxyType::Traefik
  — "none" → ProxyType::None
```

**6 tests** — Proxy detection and nginx config generation.

---

### Phase 6: Install Container Runner

**File: `src/cli/install_runner.rs` — `#[cfg(test)] mod tests`**

```
test_build_run_command_with_cloud_config
  — Input: provider=hetzner, region=fsn1, compose_path, ssh_key_path
  — Assert: docker run command has correct -v mounts and -e vars

test_run_command_mounts_stacker_yml
  — Assert: volume mount for stacker.yml at expected container path

test_run_command_mounts_ssh_key
  — ssh_key=~/.ssh/id_ed25519
  — Assert: -v mount for SSH key

test_run_command_plan_mode
  — dry_run=true
  — Assert: command includes "plan" not "apply"

test_run_command_apply_mode
  — dry_run=false
  — Assert: command includes "apply"

test_install_container_image_tag
  — Assert: default image is "trydirect/install-service:latest"
```

**6 tests** — Install container command construction.

---

### Phase 7: AI Client

**File: `src/cli/ai_client.rs` — `#[cfg(test)] mod tests`**

```
test_ai_provider_from_config_openai
  — AiConfig { provider: "openai", model: "gpt-4o", api_key: "sk-..." }
  — Build provider → assert correct type

test_ai_provider_from_config_ollama
  — AiConfig { provider: "ollama", endpoint: "http://localhost:11434" }
  — Build provider → assert correct type

test_mock_ai_complete
  — MockAiProvider returning "Use FROM node:lts-alpine"
  — Call complete("optimize dockerfile", context)
  — Assert: response contains expected text

test_ai_build_prompt_for_dockerfile
  — Build prompt with project_type=Node, files=["package.json"]
  — Assert: prompt mentions Node.js, asks for Dockerfile

test_ai_build_prompt_for_troubleshoot
  — Build prompt with error_log="connection refused"
  — Assert: prompt includes error log, asks for diagnosis

test_ai_not_configured_returns_error
  — AiConfig { enabled: false }
  — Call complete → CliError::AiNotConfigured
```

**6 tests** — AI provider abstraction and prompt building.

---

### Phase 8: Integration Tests — CLI Commands

**File: `tests/cli_login.rs`**

```
test_login_saves_credentials
  — Mock OAuth server (wiremock) returning token
  — Invoke LoginCommand with mock api_url
  — Assert: credentials file created

test_login_with_org_stores_org
  — Login with org="acme"
  — Assert: stored credentials.org == "acme"

test_login_with_domain_stores_domain
  — Login with domain="acme.com"
  — Assert: stored credentials.domain == "acme.com"

test_login_invalid_credentials_returns_error
  — Mock OAuth returning 401
  — Assert: CliError::AuthFailed

test_login_api_url_override
  — Login with api_url="https://custom.api"
  — Assert: stored api_url correct

test_login_refresh_existing_token
  — Pre-populate expired credentials
  — Login → assert new token, file updated not duplicated
```

**6 tests**

**File: `tests/cli_init.rs`**

```
test_init_static_project_creates_config
  — tempdir with index.html
  — Run InitCommand → assert stacker.yml exists with app.type=static

test_init_node_project_detects_correctly
  — tempdir with package.json
  — Assert: generated config has app.type=node

test_init_type_flag_overrides_detection
  — tempdir with package.json, --type python
  — Assert: app.type=python

test_init_with_proxy_flag_adds_section
  — --with-proxy → assert proxy section in generated YAML

test_init_with_ai_flag_adds_section
  — --with-ai → assert ai section with placeholder

test_init_does_not_overwrite_existing
  — tempdir with existing stacker.yml
  — Assert: error, not overwritten

test_init_output_parses_as_valid_config
  — Init → parse generated file via StackerConfig::from_file()
  — Assert: Ok

test_init_empty_dir_defaults_to_static
  — Empty tempdir → assert app.type=static
```

**8 tests**

**File: `tests/cli_deploy.rs`**

```
test_deploy_local_dry_run_generates_files
  — tempdir with index.html + minimal stacker.yml
  — DeployCommand with --dry-run
  — Assert: .stacker/Dockerfile and .stacker/docker-compose.yml created

test_deploy_local_preserves_existing_dockerfile
  — tempdir with custom Dockerfile, config referencing it
  — Deploy --dry-run → assert Dockerfile unchanged

test_deploy_local_uses_existing_compose
  — tempdir with docker-compose.yml, config with compose_file set
  — Deploy --dry-run → assert uses existing, no .stacker/ compose

test_deploy_local_with_image_skips_build
  — Config with app.image="nginx:latest"
  — Deploy --dry-run → assert no Dockerfile generated

test_deploy_cloud_requires_login
  — Config: deploy.target=cloud, no credentials
  — Assert: CliError::LoginRequired { feature: "cloud deploy" }

test_deploy_cloud_requires_provider
  — Config: deploy.target=cloud, cloud section empty
  — Assert: validation error

test_deploy_server_requires_host
  — Config: deploy.target=server, no host
  — Assert: validation error

test_deploy_missing_config_file
  — Deploy in empty dir → CliError::ConfigNotFound

test_deploy_custom_file_flag
  — --file custom.yml → assert loads custom file

test_deploy_force_rebuild
  — --force-rebuild → assert build steps included

test_deploy_runs_pre_build_hook
  — Config with hooks.pre_build → assert hook noted in --dry-run

test_deploy_target_strategy_dispatch
  — DeployTarget::Local.strategy() → assert is LocalDeploy
  — DeployTarget::Cloud.strategy() → assert is CloudDeploy
  — DeployTarget::Server.strategy() → assert is ServerDeploy

test_deploy_payload_from_config
  — Full config → DeployPayload::try_from(&config)
  — Assert: payload has correct stack_code, compose, cloud settings
```

**13 tests**

**File: `tests/cli_logs.rs`**

```
test_logs_constructs_compose_command
  — LogsCommand with defaults
  — Assert: command = "docker compose logs"

test_logs_with_service_filter
  — --service postgres
  — Assert: command includes "postgres"

test_logs_with_follow
  — --follow → assert "-f" in command

test_logs_with_tail
  — --tail 100 → assert "--tail 100"

test_logs_with_since
  — --since 1h → assert "--since 1h"

test_logs_no_deployment_returns_error
  — Clean dir, no .stacker/ → error
```

**6 tests**

**File: `tests/cli_status.rs`**

```
test_status_local_constructs_query
  — StatusCommand → assert queries Docker API

test_status_json_flag
  — --json → assert output format is JSON

test_status_no_deployment_returns_error
  — Clean dir → error

test_status_remote_queries_agent_api
  — Config with cloud deployment + mock agent API
  — Assert: queries /api/v1/agent/deployments/{hash}
```

**4 tests**

**File: `tests/cli_destroy.rs`**

```
test_destroy_constructs_down_command
  — DestroyCommand --confirm
  — Assert: "docker compose down"

test_destroy_with_volumes_flag
  — --volumes → assert "--volumes" in command

test_destroy_requires_confirmation
  — No --confirm → error in non-interactive mode

test_destroy_no_deployment_returns_error
  — Clean dir → error

test_destroy_cloud_triggers_terraform_destroy
  — Config: deploy.target=cloud, mock install runner
  — Assert: terraform destroy triggered
```

**5 tests**

**File: `tests/cli_config.rs`**

```
test_config_validate_valid_returns_success
  — Valid stacker.yml → assert success message

test_config_validate_invalid_lists_errors
  — Invalid config → assert errors displayed

test_config_validate_custom_file
  — --file custom.yml → assert validates custom file

test_config_show_resolves_env_vars
  — Set TEST_VAR=hello, config with ${TEST_VAR}
  — Assert: output shows "hello"

test_config_show_displays_defaults
  — Minimal config → show → assert defaults visible
```

**5 tests**

**File: `tests/cli_ai.rs`**

```
test_ai_ask_no_config_returns_error
  — Config without ai section → CliError::AiNotConfigured

test_ai_ask_openai_sends_correct_request
  — Mock OpenAI endpoint
  — Assert: POST with model, messages array

test_ai_ask_ollama_sends_correct_request
  — Mock Ollama endpoint
  — Assert: POST to /api/generate

test_ai_ask_with_context_includes_logs
  — --context deploy → assert deployment context in prompt

test_ai_dockerfile_generation
  — Mock LLM returning Dockerfile
  — Assert: valid result returned
```

**5 tests**

**File: `tests/cli_proxy.rs`**

```
test_proxy_detect_finds_nginx
  — Mock Docker API with nginx container
  — Assert: "nginx detected"

test_proxy_detect_finds_npm
  — Mock with NPM container
  — Assert: "Nginx Proxy Manager detected"

test_proxy_detect_nothing
  — Empty containers → "no proxy detected"

test_proxy_add_domain_updates_config
  — proxy add example.com --upstream app:3000
  — Assert: config updated

test_proxy_add_invalid_domain_returns_error
  — "not a domain" → validation error
```

**5 tests**

**File: `tests/cli_update.rs`**

```
test_update_newer_version_available
  — Mock release endpoint with v2.0.0
  — Assert: "new version available"

test_update_already_latest
  — Mock with same version
  — Assert: "already up to date"

test_update_channel_flag
  — --channel nightly → assert checks nightly feed
```

**3 tests**

---

### Test Fixtures

**File: `tests/mock_data/stacker_minimal.yml`**
```yaml
name: test-app
app:
  type: static
  path: ./public
```

**File: `tests/mock_data/stacker_full.yml`**
```yaml
name: full-test-app
version: "2.0"
organization: test-org
app:
  type: node
  path: ./src
  build:
    context: .
    args:
      NODE_ENV: production
services:
  - name: postgres
    image: postgres:16
    ports: ["5432:5432"]
    environment:
      POSTGRES_DB: testdb
      POSTGRES_PASSWORD: testpass
    volumes:
      - pgdata:/var/lib/postgresql/data
  - name: redis
    image: redis:7-alpine
    ports: ["6379:6379"]
proxy:
  type: nginx
  domains:
    - domain: test.example.com
      ssl: auto
      upstream: app:3000
deploy:
  target: local
ai:
  enabled: true
  provider: ollama
  model: llama3
  endpoint: http://localhost:11434
  tasks: [dockerfile, troubleshoot]
monitoring:
  status_panel: true
  healthcheck:
    endpoint: /health
    interval: 30s
env:
  APP_PORT: "3000"
  LOG_LEVEL: debug
```

**File: `tests/mock_data/stacker_invalid.yml`**
```yaml
# Missing required name field
app:
  type: cobol
```

**File: `tests/mock_data/stacker_cloud.yml`**
```yaml
name: cloud-test
app:
  type: static
  path: ./public
deploy:
  target: cloud
  cloud:
    provider: hetzner
    region: fsn1
    size: cpx21
    ssh_key: ~/.ssh/id_ed25519
```

---

### Test Count Summary

| Phase | Module | Tests |
|-------|--------|-------|
| 0 | error.rs + enums | 13 |
| 1 | config_parser + builder | 25 |
| 2 | detector | 13 |
| 3 | generator/dockerfile | 12 |
| 3 | generator/compose | 11 |
| 4 | credentials | 8 |
| 5 | proxy_manager | 6 |
| 6 | install_runner | 6 |
| 7 | ai_client | 6 |
| 8 | cli_login | 6 |
| 8 | cli_init | 8 |
| 8 | cli_deploy | 13 |
| 8 | cli_logs | 6 |
| 8 | cli_status | 4 |
| 8 | cli_destroy | 5 |
| 8 | cli_config | 5 |
| 8 | cli_ai | 5 |
| 8 | cli_proxy | 5 |
| 8 | cli_update | 3 |
| **Total** | | **160** |

---

## Step-by-Step Implementation

Each step: write tests → run (all fail) → implement → run (all pass) → refactor.

### Step 1: Foundation — Error Types + Enums
1. Add dev-dependencies to `Cargo.toml`
2. Create `src/cli/mod.rs`, `src/cli/error.rs`
3. Define `CliError`, `AppType`, `DeployTarget`, `ProxyType`, `Severity`, `ValidationIssue`
4. Implement `Display`, `From`, `Default` for each
5. Write Phase 0 tests (13) → implement → green

### Step 2: Config Parser + Builder
1. Create `src/cli/config_parser.rs`
2. Define `StackerConfig`, `AppSource`, `ServiceDefinition`, `ProxyConfig`,
   `DeployConfig`, `AiConfig`, `MonitoringConfig`, `HookConfig` — all with
   `Deserialize + Serialize + Default + Debug + Clone + Validate`
3. Define `ConfigBuilder` with fluent chaining
4. Implement `StackerConfig::from_file()` with env var interpolation
5. Implement `validate_semantics()`
6. Write Phase 1 tests (25) → implement → green

### Step 3: Project Detector
1. Create `src/cli/detector.rs`
2. Define `FileSystem` trait + `MockFileSystem` + `RealFileSystem`
3. Define `ProjectDetection` struct
4. Implement `From<&ProjectDetection> for AppType`
5. Write Phase 2 tests (13) → implement → green

### Step 4: Dockerfile Generator
1. Create `src/cli/generator/mod.rs`, `dockerfile.rs`, `templates.rs`
2. Define `DockerfileBuilder` with fluent builder pattern
3. Implement `From<AppType> for DockerfileBuilder`
4. Write Phase 3 dockerfile tests (12) → implement → green

### Step 5: Compose Generator
1. Create `src/cli/generator/compose.rs`
2. Define `ComposeDefinition`, `ComposeService`
3. Implement `TryFrom<&StackerConfig> for ComposeDefinition`
4. Implement `From<&ServiceDefinition> for ComposeService`
5. Write Phase 3 compose tests (11) → implement → green

### Step 6: Credentials Manager
1. Create `src/cli/credentials.rs`
2. Define `Credentials` struct with `save()`, `load()`, `is_expired()`, `refresh()`
3. Write Phase 4 tests (8) → implement → green

### Step 7: Proxy Manager
1. Create `src/cli/proxy_manager.rs`
2. Define `ProxyDetection`, nginx config generation
3. Implement `ContainerRuntime` trait dependency for detection
4. Write Phase 5 tests (6) → implement → green

### Step 8: Install Runner
1. Create `src/cli/install_runner.rs`
2. Define `InstallContainerCommand` builder
3. Write Phase 6 tests (6) → implement → green

### Step 9: AI Client
1. Create `src/cli/ai_client.rs`
2. Define `AiProvider` trait + `MockAiProvider` + `OpenAiProvider` + `OllamaProvider`
3. Implement prompt construction
4. Write Phase 7 tests (6) → implement → green

### Step 10: CLI Command Stubs
1. Extend `Commands` enum in `src/console/main.rs`
2. Create `src/console/commands/cli/` with all command modules
3. Stub `CallableTrait` implementations (return `Ok(())`)
4. Verify `cargo build --features explain`

### Step 11-21: Commands (one per step)
For each command (login, init, deploy, logs, status, destroy, config, ai, proxy, update):
1. Write integration tests from Phase 8
2. Implement `CallableTrait` using library modules from Steps 1-9
3. Green

### Step 22: Binary Target + Distribution
1. Add `[[bin]] name = "stacker"` in `Cargo.toml`
2. Create `scripts/install.sh` for curl-based install
3. Update CI for multi-platform builds

---

## Verification

### Run all tests
```bash
cd stacker

# All tests
cargo test --features explain

# By phase
cargo test --features explain -- cli::error::tests                    # Phase 0
cargo test --features explain -- cli::config_parser::tests            # Phase 1
cargo test --features explain -- cli::detector::tests                 # Phase 2
cargo test --features explain -- cli::generator::dockerfile::tests    # Phase 3
cargo test --features explain -- cli::generator::compose::tests       # Phase 3
cargo test --features explain -- cli::credentials::tests              # Phase 4
cargo test --features explain -- cli::proxy_manager::tests            # Phase 5
cargo test --features explain -- cli::install_runner::tests           # Phase 6
cargo test --features explain -- cli::ai_client::tests                # Phase 7
cargo test --features explain --test cli_login                        # Phase 8
cargo test --features explain --test cli_deploy                       # Phase 8
# ...

# Integration tests only
cargo test --features explain --test 'cli_*'
```

### Manual E2E smoke test
```bash
mkdir /tmp/test-site && echo "<h1>Hello</h1>" > /tmp/test-site/index.html
cd /tmp/test-site
stacker init
stacker config validate
stacker deploy --target local --dry-run
stacker deploy --target local
stacker status
stacker logs --follow
stacker destroy --confirm
```

---

## Decisions Log

| Decision | Chosen | Over | Reason |
|----------|--------|------|--------|
| Builder pattern | `ConfigBuilder`, `DockerfileBuilder` with fluent chaining | Direct struct construction | Clean API for `stacker init`, testable, follows `JsonResponseBuilder<T>` pattern in codebase |
| From/Into | `From<AppType> for DockerfileBuilder`, `TryFrom<&StackerConfig> for ComposeDefinition`, etc. | Manual conversion functions | Idiomatic Rust, composable, follows 20+ existing From/Into impls in codebase |
| Error type | Single `CliError` enum with structured variants + `Display` + `From` | String-based errors | Clean Code Ch.7 — structured error handling. Follows `ConnectorError` pattern. No `thiserror` (codebase doesn't use it) |
| Trait abstraction | `ContainerRuntime`, `FileSystem`, `AiProvider` traits | Concrete types only | DIP — enables `MockContainerRuntime` etc. for testing. Follows `UserServiceConnector` mock pattern |
| Strategy pattern | `DeployStrategy` trait with `LocalDeploy`, `CloudDeploy`, `ServerDeploy` | Match arm in single function | OCP — new deploy targets don't modify existing code |
| Naming | Full intention-revealing names, no abbreviations | Short names | Clean Code Ch.2 — `generate_dockerfile` not `gen_df` |
| Function size | Single-purpose functions, one level of abstraction | Large orchestration functions | Clean Code Ch.3 — do one thing |
| Validation | `Validate` derive + `validate_semantics()` returning `Vec<ValidationIssue>` | Boolean checks | Follows `serde_valid` pattern in codebase + `ValidateStackConfigTool` error/warning/info pattern |
| Test isolation | `MockFileSystem`, `MockContainerRuntime`, `MockAiProvider` | tempdir + real Docker | Fast, deterministic, no external dependencies. Integration tests use tempdir where needed |
| Config format | serde-derived structs with `#[serde(default)]` + `#[serde(rename_all)]` | Manual parsing | Follows every model/form in codebase. Declarative, auto-documented. |
