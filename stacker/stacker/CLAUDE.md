# Stacker

Core platform API service. Manages projects, stacks, cloud deployments, user access control, and marketplace. Exposes REST API consumed by the blog frontend and admin UI.

## Tech Stack
- **Language**: Rust (2021 edition)
- **Framework**: Actix-web 4.3.1
- **Database**: PostgreSQL (sqlx 0.8.2 with compile-time checked queries)
- **Auth**: Casbin RBAC (casbin 2.2.0, actix-casbin-auth)
- **Async**: Tokio (full features)
- **Message Queue**: RabbitMQ (lapin + deadpool-lapin)
- **Cache**: Redis (redis 0.27.5 with tokio-comp)
- **SSH**: russh 0.58 (remote server management)
- **Templates**: Tera 1.19.1
- **Crypto**: AES-GCM, HMAC-SHA256, Ed25519 SSH keys
- **Validation**: serde_valid 0.18.0
- **Testing**: wiremock, mockito, assert_cmd

## Project Structure
```
src/
  lib.rs                 # Library root
  main.rs                # Server binary entry
  configuration.rs       # Config loading (configuration.yaml)
  startup.rs             # Server initialization
  telemetry.rs           # Tracing/logging setup
  banner.rs              # Startup banner
  project_app/           # Core project/stack management
    upsert.rs            # Create/update projects
    mapping.rs           # Data mapping
    hydration.rs         # Data hydration from DB
    vault.rs             # Vault secrets integration
    tests.rs             # Module tests
  forms/                 # Request validation
    cloud.rs             # Cloud provider forms
    server.rs            # Server forms
  connectors/            # External service connectors
    dockerhub_service.rs # DockerHub API
    config.rs            # Connector configuration
    errors.rs            # Error types
  middleware/             # HTTP middleware
    authorization.rs     # Casbin RBAC middleware
    mod.rs               # Middleware registration
migrations/              # sqlx PostgreSQL migrations (up/down pairs)
configuration.yaml       # Runtime configuration
access_control.conf      # Casbin RBAC policy
```

## Binaries
- **server** — main API server (Actix-web)
- **console** — admin console commands
- **stacker-cli** — CLI tool for stack management

## Commands
```bash
# Build (offline mode for CI without DB)
SQLX_OFFLINE=true cargo build

# Run tests
cargo test

# Run specific test
cargo test test_name

# Run with features
cargo test --features explain

# Database migrations
sqlx migrate run
sqlx migrate revert

# Prepare offline query data
cargo sqlx prepare

# Format & lint
cargo fmt
cargo clippy -- -D warnings

# Run server
cargo run --bin server

# Run CLI
cargo run --bin stacker-cli -- <command>
```

## Critical Rules
- NEVER modify migration .up.sql/.down.sql files that have been applied to production
- ALWAYS create new migration files for schema changes: `sqlx migrate add <name>`
- ALWAYS run `cargo sqlx prepare` after changing any sqlx queries
- ALWAYS use compile-time checked queries with sqlx macros
- ALWAYS test with `cargo test` after every change
- Casbin policies in access_control.conf must be reviewed for any auth changes
- SSH key operations must handle cleanup on failure
- Vault secrets must never be logged or serialized to responses
- Use `SQLX_OFFLINE=true` for builds without database access
- Do not yet add to repo .claude CLAUDE.md .copilot related files

## Agents
- Use `planner` before any feature work or refactoring
- Use `tester` after every code change (must run cargo test)
- Use `code-reviewer` before commits — focus on security and SQL safety
- Use `migration-checker` for any database schema changes
- Use `api-reviewer` when adding or modifying REST endpoints