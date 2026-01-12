# Status Panel (TryDirect Agent) - AI Coding Instructions

## Project Overview
Status Panel is a **hybrid Rust/Python** server health monitoring application transitioning from Python (Flask) to Rust. The Rust rewrite (in progress) uses Axum for HTTP, Bollard for Docker, and Tokio for async operations. Both implementations coexist during migration.

**Key Context:**
- **Primary codebase:** Rust CLI app (`src/main.rs`) with modular architecture
- **Legacy system:** Flask app (`app.py`) still functional but being replaced
- **Configuration:** `config.json` with special `apps_info` parsing (format: `"app1-v1,app2-v2"` → structured `Vec<AppInfo>`)
- **Execution modes:** Daemon (background monitoring), API server (with/without UI), Docker commands

## Architecture & Module Organization

### Core Rust Modules
- **`agent/`**: Core daemon logic, Docker integration, config parsing with `apps_info` normalization
- **`comms/`**: Axum HTTP server with dual modes (JSON API vs. HTML+Tera templates)
- **`security/`**: Session-based auth (in-memory `SessionStore`), credentials from `STATUS_PANEL_USERNAME/PASSWORD` env vars
- **`monitoring/`**: Metrics collection, WebSocket streaming (see `MetricsCollector`, `MetricsStore`)
- **`commands/`**: Command execution with timeout management (`CommandExecutor`), multi-phase timeout strategy (`TimeoutTracker`), command validation
- **`transport/`**: Dashboard communication via HTTP long polling and WebSocket, includes `Command` and `CommandResult` types
- **`utils/`**: Structured logging via `tracing` crate

### State Management Pattern
All handlers use `SharedState = Arc<AppState>`:
```rust
pub struct AppState {
    pub session_store: SessionStore,
    pub config: Arc<Config>,
    pub templates: Option<Arc<Tera>>,  // Only when --with-ui
    pub with_ui: bool,
    pub metrics_collector: Arc<MetricsCollector>,
    pub metrics_store: MetricsStore,
    pub metrics_tx: MetricsTx,
}
```
**Never** clone `AppState` directly—always wrap in `Arc` and use `State(state): State<SharedState>` extractor.

## Build & Run Workflows

### Building
```bash
cargo build --release                    # Default with docker feature
cargo build --release --no-default-features --features minimal  # Without Docker
```

### Execution Modes
```bash
# Daemon mode (default, no subcommand)
./target/release/status --config config.json

# Background daemon
./target/release/status --daemon --config config.json

# API-only mode (JSON responses)
./target/release/status serve --port 5000

# API with UI (Tera templates from templates/, static files from static/)
./target/release/status serve --port 5000 --with-ui

# Docker operations (requires default features)
./target/release/status containers
./target/release/status restart <container-name>
```

### Docker Deployment
- **Flask version:** `docker-compose.yml` runs on port 5001, mounts Docker socket and `/data/encrypted`
- **Environment:** Requires `.env` file with `STATUS_PANEL_USERNAME`, `STATUS_PANEL_PASSWORD`, `DOCKER_SOCK`, `NGINX_CONTAINER`, `AGENT_ID`
- **v2.0 Requirement:** All HTTP requests to dashboard must include `X-Agent-Id` header with value from `AGENT_ID` env var

### Testing
```bash
cargo test                    # Unit + integration tests
cargo test --test http_routes # HTTP endpoint tests only
```

## Configuration Parsing Convention

**Critical:** `apps_info` field has **dual representation**:
- **JSON:** String format `"phpMyAdmin-5,MySQL-5,PHP-7"`
- **Runtime:** Normalized to `Vec<AppInfo>` with `{name, version}` structs

Both `app.py` (Python) and `src/agent/config.rs` (Rust) perform this normalization. Always use the structured `apps_info: Option<Vec<AppInfo>>` in Rust code, not raw strings.

```rust
// From config.json "apps_info": "nginx-1.21,redis-7.0"
config.apps_info // -> Some([AppInfo{name: "nginx", version: "1.21"}, ...])
```

## UI vs. API Mode Behavior

**Flag:** `--with-ui` determines response types:
- **Without flag:** Pure JSON responses (e.g., `/login` returns `{"session_id": "..."}`)
- **With flag:** HTML templates via Tera, redirects on login success, error pages on failure

**Template Loading:**
```rust
let templates = if with_ui {
    Tera::new("templates/**/*.html")  // Fails gracefully if templates/ missing
} else { None }
```

Check `state.with_ui` in handlers to switch between `Html(...)` and `Json(...)` responses.

## Authentication Pattern

1. **Credentials:** Read from env vars via `Credentials::from_env()` (defaults to `admin:admin`)
2. **Session creation:** `state.session_store.create_session(user).await` returns UUID session ID
3. **Session retrieval:** `state.session_store.get_session(&session_id).await`
4. **Storage:** In-memory `HashMap` wrapped in `Arc<RwLock<...>>` (not persistent across restarts)

**@todo:** Cookie-based session management incomplete (see [local_api.rs](src/comms/local_api.rs#L180))

## Docker Integration (`#[cfg(feature = "docker")]`)

**API Functions:**
- `list_containers()` → Basic container info
- `list_containers_with_logs(tail)` → Includes log output
- `get_health(container_name)` → CPU/memory stats via `stats()` stream
- `restart(name)`, `stop(name)`, `pause(name)` → Container operations

**Pattern:** All functions use `Docker::connect_with_local_defaults()`, expecting `/var/run/docker.sock` mount.

## Command Execution Pattern

**Command Executor (`src/commands/executor.rs`):**
- Uses `tokio::process::Command` for async process spawning
- Integrates `TimeoutTracker` for multi-phase timeout monitoring (Normal → Warning → HardTermination → ForceKill)
- Captures stdout/stderr via `AsyncBufReadExt::lines()` for real-time streaming
- Platform-specific signal handling: Unix uses `nix::sys::signal::kill()` for SIGTERM/SIGKILL, Windows uses `start_kill()`

**Timeout Strategy System (`src/commands/timeout.rs`):**
```rust
TimeoutStrategy {
    base_timeout_secs: 300,
    soft_multiplier: 0.8,    // Warning at 80%
    hard_multiplier: 0.9,    // SIGTERM at 90%
    kill_multiplier: 1.0,    // SIGKILL at 100%
    allow_graceful_termination: true,
    stall_threshold_secs: 60,
}
```
- **Presets:** `backup_strategy()` for long ops with progress reporting, `quick_strategy()` for fast commands
- **Progress tracking:** `report_progress()` resets stall timer when output received, `is_stalled()` checks for hangs

**Usage Pattern:**
```rust
let executor = CommandExecutor::new()
    .with_progress_callback(|phase, elapsed| {
        tracing::info!("Command in {:?} phase after {}s", phase, elapsed);
    });

let result = executor.execute(&command, TimeoutStrategy::backup_strategy(300)).await?;
let command_result = result.to_command_result();  // Convert to transport::CommandResult for dashboard
```

## Incomplete Features & Development Plan

See `.ai/GOAL.md` for full technical spec. Areas marked with `@todo`:
1. **Daemon heartbeat:** [daemon.rs](src/agent/daemon.rs#L11) currently just logs every 10s
2. **Metrics webhooks:** `METRICS_WEBHOOK` env var parsed but not implemented
3. **Crypto operations:** [security/mod.rs](src/security/mod.rs#L3) placeholder for key management
4. **Session cookies:** Logout handler incomplete

## Code Style & Conventions

- **Error handling:** Use `anyhow::Result` with `.context()` for all public functions
- **Logging:** Prefer `tracing::info!`, `debug!`, `error!` macros (configured in `utils/logging::init()`)
- **Async:** All I/O uses `tokio`, no blocking operations in async contexts
- **Serialization:** Use `#[derive(Serialize, Deserialize)]` for all API types
- **Testing:** Colocate tests in `#[cfg(test)] mod tests` blocks, integration tests in `tests/`

## Common Pitfalls

1. **Don't hardcode ports:** Use CLI args or config
2. **Docker features:** Always check `#[cfg(feature = "docker")]` when adding Docker code
3. **Template paths:** Relative to workspace root (`templates/`, `static/`), not binary location
4. **Config validation:** `apps_info` parsing can fail silently—validate in tests
5. **Axum extractors:** Order matters—`State` must come before `Json`/`Form` extractors

## Legacy Python Code (`app.py`)

**Deprecated but functional.** Use for:
- Understanding Flask route equivalents when porting
- Validating `apps_info` normalization logic parity

**Key differences from Rust:**
- Uses `flask-login` for sessions (not UUID-based)
- Backup encryption features (`BACKUP_FILE_NAME`, `BackupSigner`) not yet ported
- Docker client via `docker-py`, not Bollard
