# Stacker Codebase Analysis for Copilot Instructions

## Executive Summary

**Stacker** is a Rust-based platform for building, deploying, and managing containerized applications. It's a three-part system:
- **Stacker CLI** (`stacker-cli` binary): Developer tool for local init, deploy, monitor
- **Stacker Server** (`server` binary): REST API, Stack Builder UI, deployment orchestration, MCP tool server (48+ tools)
- **Status Panel Agent**: Deployed on target servers (separate repo), executes commands via AMQP queue

**Codebase**: ~29,453 LOC of Rust, structured with clear separation of concerns across modules.

---

## 1. BUILD/TEST/LINT COMMANDS

### All Commands (Makefile)
```bash
# Build all binaries
make build

# Run tests with offline mode (uses cached SQLx metadata)
make test                          # Run all lib tests
make test TESTS=test_name          # Run single test

# Code quality
make style-check                   # Check formatting (rustfmt)
make lint                          # Run clippy with warnings-as-errors

# Documentation
make docs                          # Generate cargo docs (with dependencies)

# Development (watch mode)
make dev                           # `cargo run` (runs 'server' binary by default)

# Cleanup
make clean                         # Remove build artifacts
```

### Running a Single Test
```bash
# Tests in src/ use #[tokio::test] async annotation
cargo test --offline --lib test_name -- --color=always --test-threads=1 --nocapture

# Integration tests in tests/ directory
cargo test --test cli_init -- --color=always
```

### CI/CD: GitHub Actions
- `.github/workflows/`: Docker CICD on push to main/testing/dev, PRs, and releases
- Key env: `SQLX_OFFLINE=true` (requires .sqlx/ cache with precompiled queries)
- Checks: cargo check → cargo test → rustfmt → clippy

---

## 2. HIGH-LEVEL ARCHITECTURE

### Project Structure

```
stacker/
├── src/
│   ├── main.rs                    # Server binary entry point
│   ├── lib.rs                     # Library root (14 main modules)
│   ├── bin/stacker.rs             # CLI binary entry point
│   ├── console/main.rs            # Console/admin tool binary (with "explain" feature)
│   ├── startup.rs                 # HTTP server setup (Actix-web)
│   ├── routes/                    # HTTP handlers (organized by domain)
│   │   ├── project/, agent/, deployment/, server/, cloud/
│   │   ├── client/, marketplace/, chat/, command/, agreement/
│   ├── db/                        # Database query layer (sqlx with compile-time checks)
│   ├── models/                    # Domain models (match DB schema)
│   ├── services/                  # Business logic layer
│   ├── connectors/                # External service integrations (plugin pattern)
│   ├── middleware/                # Request processing (auth, authz, cors)
│   ├── mcp/                       # Model Context Protocol (48+ AI tools)
│   ├── cli/                       # CLI library (shared with bin/stacker.rs)
│   ├── helpers/                   # Utility functions
│   ├── configuration.rs           # Settings struct
│   └── telemetry.rs               # Tracing/logging setup
├── tests/                         # Integration tests (10+ files)
├── migrations/                    # sqlx database migrations (50+)
├── Cargo.toml                     # 3 binaries: server, console, stacker-cli
└── Makefile                       # Development commands
```

### Three Binaries

| Binary | Entry Point | Purpose |
|--------|-------------|---------|
| `server` | `src/main.rs` | REST API + Actix-web server |
| `console` | `src/console/main.rs` | Admin/debug console (requires `explain` feature) |
| `stacker-cli` | `src/bin/stacker.rs` | User-facing CLI for init/deploy/status/logs |

### Key Services/Components

1. **HTTP Server (Actix-web)**: Port 8000 (default)
   - CORS enabled, Tracing middleware, structured logging
   - Authorization (Casbin RBAC) + Authentication (6 methods)
   - Compression via Brotli

2. **Database**: PostgreSQL with sqlx
   - Two connection pools:
     - **API pool**: 30 max (fast queries, 5s timeout)
     - **Agent pool**: 100 max (agent polling, 15s timeout)

3. **Message Queue**: RabbitMQ (AMQP)
   - Agent command delivery, async event publishing

4. **Vault**: Secret storage for agent tokens and session tokens

5. **MCP Tool Server**: 48+ tools for AI agents
   - Agent control, config, deployment, firewall, monitoring, cloud, marketplace

6. **External Connectors**: UserService, DockerHub, InstallService

---

## 3. KEY CONVENTIONS

### Error Handling

**Pattern**: Custom `Result<T, String>` (NOT standard Rust `Result`)

```rust
// All db:: functions return Result<T, String>
pub async fn fetch(pool: &PgPool, id: i32) -> Result<Option<models::Project>, String> {
    sqlx::query_as!(models::Project, r#"SELECT * FROM project WHERE id=$1"#, id)
        .fetch_one(pool)
        .await
        .map(|project| Some(project))
        .or_else(|err| match err {
            sqlx::Error::RowNotFound => Ok(None),
            e => {
                tracing::error!("Failed to fetch: {:?}", e);
                Err("Could not fetch data".to_string())
            }
        })
}

// HTTP layer: Convert Result<T, String> to JsonResponse
Err(err) => Err(helpers::JsonResponse::build().internal_server_error(err))
```

**Response Pattern**:
```rust
JsonResponse::build()
    .set_item(data)
    .ok("Success message")

// Errors:
JsonResponse::build().bad_request("Missing fields")
JsonResponse::build().not_found("Resource not found")
JsonResponse::build().forbidden("Unauthorized")
JsonResponse::build().internal_server_error("DB error")
```

### Database Queries

**Pattern**: sqlx with compile-time verification + `.sqlx/` cache

```rust
// Standard: sqlx::query_as! (compile-time type-checked)
sqlx::query_as!(
    models::Project,
    r#"SELECT * FROM project WHERE id = $1 AND user_id = $2"#,
    id,
    user_id
)
.fetch_one(pool)
.await
```

**Migration Pattern**:
- Files: `migrations/TIMESTAMP_description.{up,down}.sql`
- Compile-time via `.sqlx/` cache in CI: `SQLX_OFFLINE=true`

**Pool Selection**:
```rust
// API routes
let api_pool: web::Data<Pool<Postgres>> = api_pool_param;

// Agent routes
let agent_pool: web::Data<AgentPgPool> = agent_pool_param;
agent_pool.as_ref().fetch_one(...)  // AgentPgPool::as_ref() → &PgPool
```

### CLI Commands

**Pattern**: `clap` derive macros with subcommands

```rust
#[derive(Parser, Debug)]
#[command(name = "stacker")]
struct Cli {
    #[command(subcommand)]
    command: Option<StackerCommands>,
}

#[derive(Debug, Subcommand)]
enum StackerCommands {
    Init { #[arg(long)] app_type: Option<String>, #[arg(long)] with_ai: bool },
    Deploy { #[arg(long)] target: Option<String> },
}
```

**User-facing commands** (stacker-cli):
- `stacker login`, `stacker init`, `stacker deploy`, `stacker status`, `stacker logs`, `stacker destroy`
- `stacker ssh-key`, `stacker secrets`, `stacker ci`, `stacker agent`, `stacker proxy`

### Notable Patterns

1. **Builder Pattern** (Response Construction):
   ```rust
   JsonResponse::build().set_item(data).ok("message")
   ```

2. **Trait Implementations** (Plugin Pattern):
   ```rust
   pub trait UserServiceConnector: Send + Sync { ... }
   let user_service: web::Data<Arc<dyn UserServiceConnector>> = web::Data::new(...);
   ```

3. **Middleware Stack**:
   ```
   CORS → TracingLogger → Authorization (Casbin) → Authentication (6 methods) → Compression
   ```

4. **Authentication Extraction**:
   ```rust
   #[post("/endpoint")]
   pub async fn handler(user: web::ReqData<Arc<models::User>>) -> Result<impl Responder> {
       let user_id = &user.id;  // Auto-injected by middleware
   }
   ```

5. **Async Spans** (Tracing):
   ```rust
   #[tracing::instrument(name = "Fetch project", skip(pool))]
   pub async fn fetch(pool: &PgPool, id: i32) -> Result<...> { ... }
   ```

### Configuration/Environment Variables

**Pattern**: `config` crate with defaults + env override

```rust
#[derive(Debug, Clone, serde::Deserialize)]
pub struct Settings {
    pub database: DatabaseSettings,
    pub app_port: u16,                    // 8000 default
    pub app_host: String,                 // 127.0.0.1 default
    pub auth_url: String,                 // OAuth provider
    pub amqp: AmqpSettings,               // RabbitMQ
    pub vault: VaultSettings,
    // ... more fields
}

pub fn get_configuration() -> Result<Settings, config::ConfigError> {
    config::Config::builder()
        .add_source(config::File::with_name("configuration"))
        .add_source(config::Environment::with_prefix("APP").separator("__"))
        .build()?
        .try_deserialize()
}
```

**Environment Override Example**:
```bash
APP__DATABASE__HOST=db.example.com APP__DATABASE__PORT=5433 cargo run
```

---

## 4. DEPENDENCIES

### Core Framework
- **actix-web** 4.3.1: HTTP server
- **tokio** 1.28.1: Async runtime (all features)

### Database
- **sqlx** 0.8.2: Async SQL with compile-time checking
- Supports: runtime-tokio-rustls, postgres, uuid, chrono, json, ipnetwork, macros

### Messaging
- **lapin** 2.3.1: RabbitMQ/AMQP client
- **deadpool-lapin** 0.12.1: Connection pool

### Serialization & Config
- **serde** 1.0.195: Serialization framework
- **serde_json**, **serde_yaml**: JSON/YAML support
- **config** 0.13.4: Configuration file handling

### CLI
- **clap** 4.4.8: CLI argument parsing (derive macros)
- **dialoguer** 0.11: Interactive prompts
- **indicatif** 0.17: Progress bars

### Utilities
- **uuid** 1.3.4, **chrono** 0.4.39: ID/time generation
- **tracing** + **tracing-subscriber**: Structured logging
- **regex** 1.10.2, **rand** 0.8.5: Utilities

### Security
- **hmac**, **sha2**: Authentication
- **aes-gcm**, **base64**: Encryption/encoding
- **ssh-key**, **russh**: SSH support

### HTTP & Networking
- **reqwest** 0.11.23: HTTP client
- **futures** 0.3.29: Async utilities

### Authorization
- **casbin** 2.2.0: RBAC/ABAC
- **actix-casbin-auth** (git): Actix integration

### Dev Dependencies
- **assert_cmd**, **predicates**: CLI testing
- **wiremock**, **mockito**: HTTP mocking
- **tempfile**: Temporary files

---

## 5. EXISTING AI CONFIG FILES

**None found** at repository root. No `.cursorrules`, `CLAUDE.md`, `AGENTS.md`, `.clinerules`, or `.windsurfrules`.

**Documentation Files** (similar purpose):
- `START_HERE.md`, `QUICK_REFERENCE.md`, `CODE_SNIPPETS.md`, `IMPLEMENTATION_GUIDE.md`, `ANALYSIS_README.md`

---

## 6. TESTING PATTERNS

### Unit Tests (in `src/`)

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_fetch_project() { ... }

    #[test]
    fn test_validation() { ... }
}
```

### Integration Tests (in `tests/`)

```rust
use assert_cmd::Command;
use predicates::prelude::*;

fn stacker_cmd() -> Command {
    Command::cargo_bin("stacker-cli").expect("binary not found")
}

#[test]
fn completion_outputs_script() {
    stacker_cmd()
        .args(["completion", "bash"])
        .assert()
        .success()
        .stdout(predicate::str::contains("stacker"));
}
```

**Integration Test Files**:
- `cli_smoke.rs`, `cli_init.rs`, `cli_config.rs`, `cli_help.rs`
- `agent_command_flow.rs`, `middleware_trydirect.rs`, `middleware_client.rs`
- `agreement.rs`, `dockerhub.rs`, `model_project.rs`

### Test Command

```bash
cargo test --offline --lib -- --color=always --test-threads=1 --nocapture
cargo test --test cli_init -- --test-threads=1
```

---

## 7. SOURCE STRUCTURE IN DETAIL

### `src/` Directory Breakdown

**routes/** (18 domains)
- HTTP handlers organized by domain: agent, project, deployment, server, cloud, client, marketplace, chat, command, agreement, rating, dockerhub, test
- Each file: `#[post]`/`#[get]` macro with `#[tracing::instrument]`
- Registered in `startup.rs` with `web::scope()`

**db/** (14 modules)
- One per domain: project, agent, deployment, command, chat, client, cloud, marketplace, product, project_app, agreement, rating, server
- All functions: `async fn(pool: &PgPool, ...) -> Result<T, String>`
- Use `sqlx::query_as!` for compile-time safety

**models/** (16 structs)
- Domain models with sqlx attributes
- Validation enums (e.g., `ProjectNameError`)
- No business logic—purely data

**services/** (10 modules)
- Business logic: project, project_app_service, agent_dispatcher, config_renderer
- Higher-level operations combining DB queries and rules

**helpers/** (13 utilities)
- `db_pools.rs`: AgentPgPool wrapper
- `mq_manager.rs`: RabbitMQ pool
- `vault.rs`: Vault client
- `json.rs`: Response builder
- `agent_client.rs`: Agent HTTP client
- Subdirs: `client/`, `cloud/`, `project/`

**connectors/** (11 files + subdirs)
- Plugin pattern: define traits, provide implementations + mocks
- `user_service/`: TryDirect integration (12 files)
- `install_service/`, `admin_service/`, `dockerhub_service.rs`

**middleware/** (2 dirs)
- `authentication/`: 6 auth methods (Agent, JWT, OAuth, Cookie, HMAC, Anonymous)
- `authorization.rs`: Casbin RBAC/ABAC

**mcp/** (6 files + tools/)
- Protocol, registry, session, websocket
- `tools/`: 48+ AI-callable tools (agent_control, config, compose, deployment, firewall, etc.)

**cli/** (16 modules)
- `ai_client.rs`: LLM integration (Ollama, OpenAI, Anthropic)
- `config_parser.rs`, `detector.rs`, `generator/`, `credentials.rs`
- `stacker_client.rs`: HTTP client to server

---

## 8. EXAMPLE: Adding a New Route

1. **Create route file** (`src/routes/domain/endpoint.rs`):
   ```rust
   #[tracing::instrument(name = "Endpoint name", skip(pool))]
   #[post("/endpoint")]
   pub async fn handler(
       user: web::ReqData<Arc<models::User>>,  // Auto-extracted
       payload: web::Json<RequestBody>,
       pool: web::Data<Pool<sqlx::Postgres>>,
   ) -> Result<impl Responder> {
       let result = db::domain::fetch(pool.get_ref(), id)
           .await
           .map_err(|e| helpers::JsonResponse::build().internal_server_error(e))?;
       
       Ok(helpers::JsonResponse::build().set_item(result).ok("Success"))
   }
   ```

2. **Declare in module** (`src/routes/domain/mod.rs`):
   ```rust
   pub mod endpoint;
   pub use endpoint::handler;
   ```

3. **Register in startup** (`src/startup.rs`):
   ```rust
   .service(web::scope("/api/v1/domain").service(routes::domain::handler))
   ```

4. **Write tests** (`tests/integration_test.rs`):
   ```rust
   #[test]
   fn test_endpoint() { ... }
   ```

---

## 9. QUICK START FOR AI ASSISTANTS

| Task | Pattern | Files |
|------|---------|-------|
| Add HTTP endpoint | Handler + route registration | `src/routes/domain/`, `src/startup.rs` |
| Add DB query | `sqlx::query_as!` + error handling | `src/db/` |
| Add model | Struct with sqlx attributes | `src/models/` |
| Add CLI command | `clap` subcommand | `src/bin/stacker.rs` or `src/console/main.rs` |
| Add auth check | Middleware extraction + ownership check | `src/middleware/authentication/` |
| Add AI tool | Struct + registry | `src/mcp/tools/` |
| Add test | `#[tokio::test]` or `assert_cmd` | `src/` or `tests/` |

---

## Key Takeaways for Development

| Aspect | Pattern |
|--------|---------|
| **Errors** | `Result<T, String>` with converter in HTTP layer |
| **DB** | `sqlx::query_as!` compile-time safety, two pools (API/Agent) |
| **Auth** | Middleware injects `Arc<models::User>` (6 methods) |
| **Logging** | `#[tracing::instrument]` + structured Bunyan JSON |
| **Config** | `config` crate + env var override with `APP__*` prefix |
| **CLI** | `clap` derive macros with subcommands |
| **Tests** | Unit in `src/`, integration in `tests/`, use assert_cmd |
| **External** | Plugin traits (UserService, DockerHub, etc.) |
| **AI Tools** | 48+ tools in `mcp/tools/` via WebSocket |
| **Migration** | sqlx migrations, compile-time via `.sqlx/` cache |

---

## Recommended Reading Order

1. **This file** - Overview
2. `QUICK_REFERENCE.md` - Patterns and checklists
3. `CODE_SNIPPETS.md` - Copy-paste examples
4. `src/routes/*/` handler files - Learn by example
5. `src/db/` modules - Query patterns
6. `src/models/` - Data structure patterns
7. `tests/` - Integration test patterns

