# Copilot Instructions

## Build, Test & Lint

```bash
# Build
cargo build

# Build (required for offline sqlx — always set this when no live DB)
SQLX_OFFLINE=true cargo build

# Run server
cargo run                          # default binary: server
cargo run --bin console            # admin console (requires --features explain)
cargo run --bin stacker-cli        # end-user stacker CLI

# Run all lib unit tests (single thread, with output)
make test
# Equivalent:
SQLX_OFFLINE=true cargo test --offline --lib -- --color=always --test-threads=1 --nocapture

# Run a single test by name
SQLX_OFFLINE=true cargo test --offline --lib -- --color=always --test-threads=1 --nocapture my_test_name

# Run integration tests (requires live Postgres — uses config from configuration.yaml)
cargo test --test health_check
cargo test --test agent_command_flow

# Lint
make lint                          # cargo clippy --all-targets --all-features -- -D warnings

# Format check
make style-check                   # cargo fmt --all -- --check
```

> **SQLX_OFFLINE=true** must be set when building/testing without a live database. Without it, sqlx macro type-checking fails on ~181 queries.

## Architecture

Stacker is an Actix-web HTTP server that manages containerized application stacks. It orchestrates deployments via SSH/agents, integrates with cloud providers, and exposes an MCP (Model Context Protocol) interface.

### Three binaries

| Binary | Entry point | Purpose |
|--------|-------------|---------|
| `server` | `src/main.rs` | Main HTTP API (default) |
| `console` | `src/console/main.rs` | Admin multi-tool CLI (requires `explain` feature) |
| `stacker-cli` | `src/bin/stacker.rs` | End-user CLI: `init`, `deploy`, `status`, `logs`, `destroy` |

### Source layout

```
src/
  routes/        # Actix-web request handlers (thin — delegate to services/db)
  models/        # Domain models with sqlx derives + validation logic
  forms/         # Request body types with serde_valid validation
  db/            # sqlx query functions per domain entity
  services/      # Business logic (agent dispatcher, deployment, project, vault, etc.)
  connectors/    # Trait-based adapters for external services (User Service, DockerHub, etc.)
  middleware/    # OAuth authentication + Casbin RBAC authorization
  helpers/       # Shared utilities: AgentPgPool, VaultClient, MqManager, SSH client, etc.
  mcp/           # Model Context Protocol server (WebSocket, tool registry, session)
  cli/           # stacker-cli command implementations
  console/       # console binary command implementations
  configuration.rs  # Settings struct, loaded from configuration.yaml
  startup.rs        # Server wiring: routes, middleware, data injection
  telemetry.rs      # tracing-bunyan-formatter subscriber setup
```

### Two database pools

`main.rs` creates two separate `PgPool` instances injected as `web::Data`:
- **`api_pool`** — 30 max connections, 5s acquire timeout. For regular API requests.
- **`agent_pool`** — 100 max connections, 15s acquire timeout, wrapped as `AgentPgPool`. For long-polling agent connections.

Always use the appropriate pool; `AgentPgPool` is a newtype wrapper around `PgPool`.

### External service connectors

All external HTTP calls go through `src/connectors/`. The pattern:
1. Define a trait in `{service}.rs` (e.g., `UserServiceConnector`)
2. Implement it as an HTTP client in the same file
3. Inject `Arc<dyn Trait>` into routes via `web::Data`
4. Use `Mock{Service}Connector` in tests — no real HTTP calls

`ConnectorError` implements Actix's `ResponseError` and maps to appropriate HTTP status codes.

### Authentication & Authorization

- **Authentication**: Middleware validates Bearer tokens against an external OAuth endpoint (`auth_url` in config). Results cached for 60 seconds (`OAuthCache`).
- **Authorization**: Casbin RBAC via `actix-casbin-auth`. Rules stored in PostgreSQL, periodically reloaded (configurable `casbin_reload_interval_secs`). The `explain` feature flag enables detailed Casbin logging.

### Configuration

Loaded from `configuration.yaml` (copy `configuration.yaml.dist` to get started). Key sections: `database`, `amqp`, `vault`, `connectors`, `deployment`. Environment variable overrides documented in `configuration.yaml.dist`.

### Migrations

sqlx migrations live in `migrations/` as paired `*.up.sql` / `*.down.sql` files. Run with `sqlx migrate run`.

## Key Conventions

### Error handling

- Use `thiserror` for typed domain errors; implement `ResponseError` to produce HTTP responses.
- `ConnectorError` is the canonical pattern — enum variants with `Display`, `ResponseError` impl mapping variants to HTTP status codes, and `From<reqwest::Error>`.
- Route handlers return `Result<impl Responder, SomeError>` where `SomeError: ResponseError`.

### Validation

Request bodies use `serde_valid` (not just `serde`). Structs in `src/forms/` derive `serde::Deserialize` + `serde_valid::Validate`. The JSON error handler in `startup.rs` serializes deserialization errors as structured JSON with `line`, `column`, and `msg`.

### Database queries

sqlx macros (`query!`, `query_as!`) with compile-time checking. All queries must be cached in `.sqlx/` for offline builds. When adding a new query, run `cargo sqlx prepare` with a live DB to update the cache.

### Regex caching

For compiled regexes used in hot paths, use `OnceLock<Regex>` (see `models/project.rs`):
```rust
static REGEX: OnceLock<Regex> = OnceLock::new();
REGEX.get_or_init(|| Regex::new(r"...").unwrap())
```

### Integration tests

Tests in `tests/` use `common::spawn_app()` which:
- Binds to a random port
- Creates a fresh database with a UUID name
- Spawns a mock OAuth auth server
- Returns `None` (skips test) if Postgres is unavailable — no panics on CI without DB

Unit tests (lib) use `--test-threads=1` (see Makefile) because many share global state.

### CLI commands

`stacker-cli` commands are implemented in `src/cli/`. `console` commands are in `src/console/commands/`. Both use `clap` with `#[derive(Parser, Subcommand)]`. Interactive prompts use `dialoguer`; progress bars use `indicatif`.

### Service deployment scope

`stacker service deploy <name>` is project-scoped by default for services declared in `stacker.yml`. Normal custom services must update `/home/trydirect/project/docker-compose.yml` and must not create `/home/trydirect/<service>/docker-compose.yml` unless the user explicitly chooses standalone mode, such as a future `--standalone` or `--scope standalone` flag.

Only platform-managed services live outside the project directory by default. Current examples are Status Panel (`/home/trydirect/statuspanel`) and Nginx Proxy Manager (`/home/trydirect/nginx_proxy_manager`). Add regression tests for any service/proxy deploy change that could duplicate a project-scoped service as a standalone compose project.

Stacker-managed compose services use stable runtime labels with the `my.stacker.*` prefix: `my.stacker.project_id`, `my.stacker.target`, `my.stacker.scope`, `my.stacker.service`, and `my.stacker.dns`. Keep logical service codes and Docker DNS names separate; for Nginx Proxy Manager use `my.stacker.service=nginx_proxy_manager` and `my.stacker.dns=nginx-proxy-manager`.
