# Compose Agent Sidecar Implementation

## Overview

The Compose Agent Sidecar is a separate container that handles Docker Compose operations and acts as an MCP (Model Context Protocol) Gateway, running alongside the Status Panel container. This separation improves isolation, reliability, and allows independent restart of the compose operations layer without affecting the main Status Panel daemon.

## Architecture

### Container Separation

```
┌─────────────────────┐     ┌──────────────────────┐
│   Status Panel      │     │  Compose Agent       │
│   (statuspanel)     │     │  (compose-agent)     │
├─────────────────────┤     ├──────────────────────┤
│ • API Server        │     │ • Docker Operations  │
│ • Web UI            │     │ • MCP Gateway        │
│ • Monitoring        │     │ • Command Execution  │
│ • No Docker socket  │     │ • Has Docker socket  │
└─────────────────────┘     └──────────────────────┘
        ↓                            ↓
   Port 5001                  Docker Socket
                             /var/run/docker.sock
```

### Key Features

1. **Docker Socket Isolation**: Only the compose-agent container mounts `/var/run/docker.sock`, reducing the attack surface for the Status Panel UI.

2. **Independent Restart**: The compose-agent container can restart on failure (including glibc mismatches) without affecting the Status Panel daemon.

3. **Control Plane Tracking**: All command executions are tagged with their source (`status_panel` or `compose_agent`) for observability.

4. **Dual Token Management**: Each container has its own Vault token path for independent authentication.

5. **Watchdog Monitoring**: Automatic health checks and restart logic for the compose-agent container.

## Configuration

### Docker Compose Setup

The `docker-compose.yml` file includes three services:

1. **statuspanel**: Web UI and API server (no Docker socket)
2. **agent**: Daemon mode with polling (has Docker socket for monitoring)
3. **compose-agent**: Sidecar for Docker operations (exclusive Docker socket access)

### Environment Variables

#### Status Panel Container
```bash
COMPOSE_AGENT_ENABLED=true
CONTROL_PLANE=status_panel
```

#### Compose Agent Container
```bash
COMPOSE_AGENT_ENABLED=true
CONTROL_PLANE=compose_agent
VAULT_TOKEN_KEY=compose_agent_token
```

### Config.json

Add these optional fields:
```json
{
  "compose_agent_enabled": true,
  "control_plane": "status_panel"
}
```

## Vault Token Schema

### Token Paths

The Vault integration supports dual token paths:

```
secret/agent/{deployment_hash}/status_panel_token
secret/agent/{deployment_hash}/compose_agent_token
```

### Usage

```rust
// Fetch status panel token
let vault_client = VaultClient::from_env()?;
let token = vault_client.fetch_agent_token("abc123", Some("status_panel_token")).await?;

// Fetch compose agent token
let token = vault_client.fetch_agent_token("abc123", Some("compose_agent_token")).await?;

// Store tokens
vault_client.store_agent_token("abc123", "token1", Some("status_panel_token")).await?;
vault_client.store_agent_token("abc123", "token2", Some("compose_agent_token")).await?;
```

## Watchdog Implementation

### Purpose

The watchdog monitors the compose-agent container and automatically restarts it on:
- Container crashes
- GLIBC version mismatches
- Unresponsive/unhealthy states

### Configuration

```rust
use status_panel::agent::watchdog::{WatchdogConfig, ComposeAgentWatchdog};

let config = WatchdogConfig {
    target_container: "compose-agent".to_string(),
    check_interval_secs: 30,
    max_restart_attempts: 5,
    restart_backoff_multiplier: 1.5,
};

let mut watchdog = ComposeAgentWatchdog::new(config)?;
watchdog.run().await?;
```

### Restart Strategy

- **Initial delay**: 10 seconds
- **Backoff**: Exponential with 1.5x multiplier
- **Max attempts**: 5 before giving up
- **Health checks**: Every 30 seconds

Example restart delays:
1. First attempt: 10s
2. Second attempt: 15s (10 * 1.5)
3. Third attempt: 22s (10 * 1.5²)
4. Fourth attempt: 33s (10 * 1.5³)
5. Fifth attempt: 50s (10 * 1.5⁴)

## Command Execution Metrics

### Tracking Control Plane

All command executions are tracked by their source:

```rust
use status_panel::monitoring::{ControlPlane, CommandExecutionMetrics};

let mut metrics = CommandExecutionMetrics::default();
metrics.record_execution(ControlPlane::ComposeAgent);
metrics.record_execution(ControlPlane::StatusPanel);

// Results:
// status_panel_count: 1
// compose_agent_count: 1
// total_count: 2
// last_control_plane: "status_panel"
```

### Metrics Endpoint

The metrics are exposed via the API and include:
- `status_panel_count`: Commands executed by Status Panel
- `compose_agent_count`: Commands executed by Compose Agent
- `total_count`: Total commands executed
- `last_control_plane`: Which plane executed the last command
- `last_command_timestamp_ms`: Timestamp of last execution

## Building and Deployment

### Build Compose Agent Image

```bash
docker-compose -f docker-compose-compose-agent.yml build
```

### Build All Images

```bash
docker-compose -f docker-compose-build.yml build
```

### Run Full Stack

```bash
docker-compose up -d
```

This starts:
- statuspanel (UI/API on port 5001)
- agent (daemon with monitoring)
- compose-agent (Docker operations sidecar)

## Legacy Mode

To disable the compose agent and run in legacy mode (Status Panel handles all operations):

### Option 1: Environment Variable
```bash
COMPOSE_AGENT_ENABLED=false
```

### Option 2: Config File
```json
{
  "compose_agent_enabled": false
}
```

### Behavior in Legacy Mode

- Status Panel mounts the Docker socket directly
- Warning log emitted: `"compose_agent=false - running in legacy mode"`
- `/capabilities` endpoint reports `compose_agent=false`
- All operations handled by status_panel control plane

## Testing

### Integration Tests

Run the watchdog and metrics tests:

```bash
cargo test --features docker -- watchdog
cargo test -- command_execution_metrics
```

### Manual Testing

1. Start the compose-agent:
```bash
docker-compose up -d compose-agent
```

2. Check health:
```bash
docker inspect compose-agent | jq '.[0].State'
```

3. Trigger a restart:
```bash
docker stop compose-agent
# Watchdog should restart it automatically
```

4. Check metrics:
```bash
curl http://localhost:5001/api/v1/metrics
```

## Security Considerations

1. **Socket Isolation**: Only compose-agent has Docker socket access, reducing attack surface for the web UI.

2. **Independent Tokens**: Separate Vault tokens allow fine-grained access control and rotation.

3. **Audit Trail**: All command executions are logged with their control plane source.

4. **Rate Limiting**: Both containers respect rate limits independently.

## Monitoring and Observability

### Logs

View compose-agent logs:
```bash
docker logs -f compose-agent
```

View Status Panel logs:
```bash
docker logs -f statuspanel
```

### Health Checks

The watchdog reports health status:
- `Healthy`: Container running normally
- `Unhealthy(reason)`: Container in bad state
- `GlibcMismatch`: GLIBC version error detected
- `NotFound`: Container doesn't exist

### Metrics

Command execution metrics include:
- Breakdown by control plane
- Last execution timestamp
- Total execution count
- Success/failure rates (if instrumented)

## Troubleshooting

### Compose Agent Won't Start

1. Check Docker socket permissions:
```bash
ls -la /var/run/docker.sock
```

2. Verify environment variables:
```bash
docker-compose config
```

3. Check logs for errors:
```bash
docker logs compose-agent
```

### GLIBC Errors

The watchdog automatically detects and attempts to restart on GLIBC mismatches. If persistent:

1. Rebuild with musl target (Dockerfile.compose-agent already uses musl)
2. Check base image compatibility
3. Review linker errors in logs

### Token Fetch Failures

1. Verify Vault environment variables:
```bash
echo $VAULT_ADDRESS
echo $VAULT_TOKEN
echo $VAULT_AGENT_PATH_PREFIX
```

2. Test Vault connectivity:
```bash
curl -H "X-Vault-Token: $VAULT_TOKEN" \
  $VAULT_ADDRESS/v1/$VAULT_AGENT_PATH_PREFIX/$DEPLOYMENT_HASH/compose_agent_token
```

3. Check token permissions in Vault policies

## Future Enhancements

1. **MCP Gateway**: Full implementation of Model Context Protocol for AI agent interactions
2. **Health Dashboard**: Real-time visualization of both control planes
3. **Auto-scaling**: Dynamic adjustment of compose-agent replicas based on load
4. **Cross-container Communication**: Direct IPC for reduced latency
5. **Rollback Logic**: Automatic rollback to legacy mode on persistent failures

## Related Documentation

- [AGENT_REGISTRATION_SPEC.md](AGENT_REGISTRATION_SPEC.md)
- [LONG_POLLING_IMPLEMENTATION.md](LONG_POLLING_IMPLEMENTATION.md)
- [VAULT_INTEGRATION.md](VAULT_INTEGRATION.md)
- [SECURITY_ENHANCEMENT.md](SECURITY_ENHANCEMENT.md)
