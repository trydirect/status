<div align="center">

<img width="200" src="https://raw.githubusercontent.com/trydirect/status/testing/assets/logo/status.png">

# Status Panel

**A lightweight infrastructure agent for server and container management.**

Monitors health, collects metrics, manages Docker containers, and executes commands — all from a single statically-linked binary.

[![CI](https://github.com/trydirect/status/actions/workflows/ci.yml/badge.svg)](https://github.com/trydirect/status/actions/workflows/ci.yml)
[![Docker Pulls](https://img.shields.io/docker/pulls/trydirect/status.svg)](https://hub.docker.com/r/trydirect/status)
[![GitHub Release](https://img.shields.io/github/v/release/trydirect/status)](https://github.com/trydirect/status/releases/latest)
[![Discord](https://img.shields.io/discord/578119430391988232?label=discord&color=5865F2)](https://discord.gg/nsjje55wuu)

</div>

---

## Highlights

- **Single binary** — statically linked (musl), zero runtime dependencies
- **Docker management** — list, start, stop, restart, pause containers; health checks and log retrieval
- **System metrics** — CPU, memory, disk usage via CLI or JSON API
- **18+ remote commands** — health, logs, exec, deploy, config management, firewall, proxy, and more via Stacker integration
- **Self-update** — download, verify (SHA256), deploy, and rollback — all built in
- **Secure by default** — HMAC-SHA256 signed requests, replay protection, rate limiting, audit logging
- **Vault integration** — fetch, apply, and diff app configs from HashiCorp Vault
- **Flexible modes** — run as a CLI tool, background daemon, API server, or API+UI server

## Quick Install

```bash
curl -sSfL https://raw.githubusercontent.com/trydirect/status/master/install.sh | sh
```

Pin a specific version or choose a custom directory:

```bash
VERSION=v0.1.4 curl -sSfL https://raw.githubusercontent.com/trydirect/status/master/install.sh | sh
INSTALL_DIR=~/.local/bin curl -sSfL https://raw.githubusercontent.com/trydirect/status/master/install.sh | sh
```

Verify:

```bash
status --version
```

## CLI Commands

```
status serve [--port 5000] [--with-ui]   Start the HTTP API server
status containers                         List all Docker containers
status health [name]                      Check container or stack health
status logs <name> [-n 100]               Fetch container logs
status start <name>                       Start a stopped container
status stop <name>                        Stop a running container
status restart <name>                     Restart a container
status pause <name>                       Pause a container
status metrics [--json]                   Show CPU, memory, disk usage
status update check                       Check for new versions
status update apply [--version V]         Download and verify an update
status update rollback                    Roll back to previous version
```

## Running Modes

**CLI** — run a single command and exit:

```bash
status health
status metrics --json
status logs my-app -n 50
```

**Daemon** — background polling agent:

```bash
status --daemon --config config.json
```

**API server** — local HTTP interface:

```bash
status serve --port 5000           # JSON API only
status serve --port 5000 --with-ui # API + web dashboard
```

## Build from Source

```bash
cargo build --release
```

Minimal build (no Docker support):

```bash
cargo build --release --no-default-features --features minimal
```

## Docker

```bash
docker pull trydirect/status:latest
```

Or use Docker Compose with the included `docker-compose.yml` for a full setup with API server and background agent.

## API Reference

### Core Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Health check |
| `GET` | `/capabilities` | System capabilities |
| `GET` | `/metrics` | Current system metrics |
| `GET` | `/metrics/stream` | WebSocket metrics stream |

### Command Execution

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/commands/execute` | Execute a validated command |
| `GET` | `/api/v1/commands/wait/{hash}` | Long-poll for queued commands |
| `POST` | `/api/v1/commands/enqueue` | Enqueue a command |
| `POST` | `/api/v1/commands/report` | Report execution result |

### Self-Update

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/self/version` | Current and available versions |
| `POST` | `/api/self/update/start` | Start update job |
| `GET` | `/api/self/update/status/{id}` | Check update progress |
| `POST` | `/api/self/update/deploy` | Deploy prepared binary |
| `POST` | `/api/self/update/rollback` | Restore previous version |

### Stacker Commands (Remote)

The agent accepts signed commands from the Stacker dashboard covering the full lifecycle:

| Command | Description |
|---------|-------------|
| `health` | Container health with optional metrics |
| `logs` | Container logs with cursor pagination |
| `start` / `stop` / `restart` | Container lifecycle |
| `exec` | Run command inside a container (sandboxed) |
| `server_resources` | CPU, memory, disk, network metrics |
| `list_containers` | All containers with health and logs |
| `error_summary` | Categorized error analysis |
| `deploy_app` / `remove_app` | App deployment via docker-compose |
| `fetch_config` / `apply_config` | Vault config management |
| `config_diff` | Detect configuration drift |
| `configure_proxy` | Nginx proxy management |
| `configure_firewall` | iptables policy management |

## Security

- **HMAC-SHA256** request signing with `AGENT_TOKEN`
- **Replay protection** via `X-Request-Id` tracking
- **Rate limiting** per agent
- **Command validation** — conservative allowlist, blocked shells and metacharacters
- **Exec sandboxing** — dangerous commands (`rm -rf /`, `mkfs`, `shutdown`, etc.) are blocked
- **Audit logging** — all auth attempts and scope denials recorded
- **Vault integration** — secrets and configs stored securely, never in plaintext

## Configuration

| Environment Variable | Description |
|---------------------|-------------|
| `AGENT_ID` | Unique agent identifier |
| `AGENT_TOKEN` | Authentication token for signed requests |
| `DASHBOARD_URL` | Remote dashboard URL |
| `VAULT_ADDRESS` | HashiCorp Vault server URL |
| `UPDATE_SERVER_URL` | Remote update server for version checks |
| `COMPOSE_AGENT_ENABLED` | Enable compose-agent mode |
| `METRICS_INTERVAL_SECS` | Metrics collection interval |

## Contributing

1. Fork the repo
2. Create a feature branch from `testing`
3. Run `cargo fmt --all && cargo clippy -- -D warnings`
4. Open a PR against `testing`

## License

See [LICENSE](LICENSE) for details.

---

<div align="center">
Built with Rust. Maintained by <a href="https://github.com/trydirect">TryDirect</a>.
</div>
