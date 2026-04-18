# Status Panel

On-server status panel agent. Runs on deployed servers to report health metrics, manage containers, handle self-updates, and provide a WebSocket interface for real-time monitoring.

## Tech Stack
- **Language**: Rust (2021 edition)
- **Framework**: Axum 0.8 (with WebSocket support)
- **Async**: Tokio (full features)
- **Docker**: Bollard 0.19 (Docker API via Unix socket, optional)
- **HTTP Client**: reqwest 0.12 (rustls-tls)
- **System Metrics**: sysinfo 0.30
- **Security**: HMAC-SHA256, ring 0.17
- **Daemonization**: daemonize 0.5
- **Testing**: assert_cmd, tokio-test, mockito, tower

## Project Structure
```
src/
  main.rs              # Binary entry point
  lib.rs               # Library root (core logic)
  test_utils.rs        # Shared test utilities
tests/
  http_routes.rs       # HTTP route integration tests
  security_integration.rs  # Security/auth integration tests
  self_update_integration.rs  # Self-update mechanism tests
examples/
  command_execution.rs # Command execution example
```

## Features
- `default = ["docker"]` — includes Docker management via Bollard
- `docker` — Docker container management (Unix socket)
- `minimal` — builds without Docker support

## Commands
```bash
# Build
cargo build

# Build minimal (without Docker)
cargo build --no-default-features --features minimal

# Run tests
cargo test

# Run tests without Docker feature
cargo test --no-default-features --features minimal

# Format & lint
cargo fmt
cargo clippy -- -D warnings

# Run
cargo run --bin status
```

## Critical Rules
- NEVER expose system commands without HMAC authentication
- NEVER trust incoming WebSocket data without signature verification
- ALWAYS validate self-update binary integrity before replacing
- Docker socket access is privileged — validate all container operations
- System metrics collection must not block the async runtime
- Test both `docker` and `minimal` feature configurations
- Test with `cargo test` after every change
- DO NOT yet add to repo .claude CLAUDE.md .copilot directories and files

## Agents
- Use `planner` before any feature work
- Use `tester` after every code change (must run cargo test)
- Use `code-reviewer` before commits — focus on security and system safety