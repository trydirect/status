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
VERSION=v0.1.8 curl -sSfL https://raw.githubusercontent.com/trydirect/status/master/install.sh | sh
INSTALL_DIR=~/.local/bin curl -sSfL https://raw.githubusercontent.com/trydirect/status/master/install.sh | sh
```

Verify:

```bash
status --version
```

## CLI Commands

```
status init                               Generate default config.json and .env
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

## First Run

After installing, generate the default configuration files:

```bash
status init                      # creates config.json and .env in current directory
status init --config /etc/status # custom path
```

Edit `.env` to set **required** credentials before starting:

```bash
STATUS_PANEL_USERNAME=myuser
STATUS_PANEL_PASSWORD=strong-secret
AGENT_ID=my-server-01
```

Then start the agent:

```bash
status --config config.json
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

## Command Transport Split

Status Panel uses **two different command transport paths**:

1. **Normal Status Panel commands** use the dashboard DB queue plus HTTP long-polling. The agent waits on `/api/v1/agent/commands/wait/{deployment_hash}`, executes the command locally, then reports back to `/api/v1/agent/commands/report`.
2. **Agent-executor pipe steps** are a separate path. AMQP/RabbitMQ support belongs to that executor flow, not to the normal Status Panel command queue.

This means RabbitMQ is **not** the transport for regular `health`, `logs`, `deploy_app`, or other Status Panel commands. Pipe operations such as `activate_pipe`, `deactivate_pipe`, and `trigger_pipe` run inside the agent runtime, but the normal command delivery path is still DB queue + long-polling.

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

The local `/api/v1/commands/*` endpoints are the agent's own Axum API surface. When connected to the remote dashboard, the daemon uses the `/api/v1/agent/commands/*` contract instead. AMQP-backed executor traffic is separate from both of these HTTP command paths.

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
| `activate_pipe` / `deactivate_pipe` / `trigger_pipe` | Agent-side pipe registration and runtime execution |

## Security

- **No default credentials** — `STATUS_PANEL_USERNAME` and `STATUS_PANEL_PASSWORD` must be set; login is disabled until configured
- **HMAC-SHA256** request signing with `AGENT_TOKEN`
- **Replay protection** via `X-Request-Id` tracking
- **Rate limiting** per agent
- **Session security** — HttpOnly + Secure + SameSite=Strict cookies; server-side session invalidation on logout; TTL-based cleanup
- **Command validation** — conservative allowlist, blocked shells and metacharacters
- **Injection prevention** — all shell-interpolated values (email, domains, container names) validated against metacharacters
- **Exec sandboxing** — dangerous commands (`rm -rf /`, `mkfs`, `shutdown`, etc.) are blocked
- **Localhost by default** — API server binds `127.0.0.1`; explicit `--bind 0.0.0.0` required for external access
- **HTTPS-only updates** — self-update rejects HTTP download URLs; SHA256 verification on every download
- **Audit logging** — all auth attempts and scope denials recorded
- **Vault integration** — secrets and configs stored securely, never in plaintext

## Configuration

`STATUS_PANEL_USERNAME` / `STATUS_PANEL_PASSWORD` only control the Status Panel UI. `configure_proxy`
uses a separate Nginx Proxy Manager credential resolved from Vault with `STACKER_SERVER_ID`.

| Environment Variable | Description |
|---------------------|-------------|
| `STATUS_PANEL_USERNAME` | **Required.** Login username |
| `STATUS_PANEL_PASSWORD` | **Required.** Login password |
| `AGENT_ID` | **Required.** Unique agent identifier (protects API endpoints) |
| `AGENT_TOKEN` | Authentication token for signed requests |
| `DASHBOARD_URL` | Remote dashboard URL |
| `VAULT_ADDRESS` | HashiCorp Vault server URL |
| `STACKER_SERVER_ID` | Stable server UUID used to resolve host-scoped NPM credentials in Vault |
| `STATUS_PANEL_PROXY_OWNER` | Set `true` on the single agent allowed to manage shared proxy state |
| `NPM_ALLOW_ENV_FALLBACK` | Temporary migration switch for legacy `NPM_*` env credentials |
| `UPDATE_SERVER_URL` | Remote update server for version checks |
| `UPDATE_EXPECTED_SHA256` | Expected SHA256 hash for self-update binary |
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
