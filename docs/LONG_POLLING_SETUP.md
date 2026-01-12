# Long-Polling Command Execution Setup

## Overview

The Status Panel agent now supports **continuous long-polling** for receiving and executing commands from the dashboard. Instead of waiting for manual HTTP requests, the agent automatically starts polling the dashboard on startup and continuously listens for incoming commands.

## How It Works

1. **Daemon startup** → Agent initializes long-polling loop
2. **Continuous polling** → Agent waits up to `POLLING_TIMEOUT_SECS` for commands
3. **Command received** → Agent executes the command immediately
4. **Result reporting** → Agent sends execution results back to dashboard
5. **Loop continues** → Agent polls again for next command

### Key Difference from Periodic Polling

- **Long polling** (implemented): Waits up to 30s per request; server wakes client instantly when command arrives
- **Periodic polling** (not used): Would check every N seconds regardless of activity

## Configuration

Add these environment variables to your `.env` file:

```bash
# Dashboard server URL (where commands are enqueued)
DASHBOARD_URL=http://localhost:5000

# Agent identifier (must match X-Agent-Id header in dashboard requests)
AGENT_ID=my-agent-01

# Deployment hash (used to identify deployment context)
DEPLOYMENT_HASH=deploy-abc123

# Long-polling timeout (seconds) - how long to wait for command before retrying
POLLING_TIMEOUT_SECS=30

# Backoff delay after network errors (seconds) - prevents hammering on failure
POLLING_BACKOFF_SECS=5

# Command execution timeout (seconds) - max time to run a single command
COMMAND_TIMEOUT_SECS=300
```

### Default Values

| Variable | Default | Notes |
|----------|---------|-------|
| `DASHBOARD_URL` | `http://localhost:5000` | Must be reachable from agent |
| `POLLING_TIMEOUT_SECS` | `30` | Max wait per poll request |
| `POLLING_BACKOFF_SECS` | `5` | Delay on network error before retry |
| `COMMAND_TIMEOUT_SECS` | `300` | 5 minutes for command execution |

## Running the Agent with Long-Polling

### Start the daemon (background service):
```bash
./status --daemon --config config.json
```

### Start the daemon (foreground, for testing):
```bash
./status --config config.json
```

Both modes activate long-polling automatically.

### With custom environment:
```bash
DASHBOARD_URL=https://dashboard.example.com \
AGENT_ID=prod-agent-01 \
POLLING_TIMEOUT_SECS=45 \
./status --config config.json
```

## How the Polling Loop Works

```
┌─────────────────────────────────────────────────────────┐
│ Agent starts daemon                                     │
└────────────────┬────────────────────────────────────────┘
                 │
                 ▼
        ┌────────────────┐
        │ Load config    │
        │ & env vars     │
        └────────┬───────┘
                 │
                 ▼
    ┌─────────────────────────┐
    │ Start metrics heartbeat  │
    │ (separate loop)          │
    └────────┬────────────────┘
             │
             ▼
    ┌────────────────────────────────┐
    │ Start polling loop              │
    │ (waits for commands)            │
    └────┬───────────────────────────┘
         │
         ▼
    ┌─────────────────────────────────────┐
    │ Wait for command from dashboard     │
    │ (timeout: POLLING_TIMEOUT_SECS)     │
    └────┬──────────────┬─────────────────┘
         │              │
      ✓  │              │  ✗ (network error)
         │              │
    ┌────▼─────┐    ┌───▼────────────────┐
    │ Command   │    │ Apply backoff      │
    │ received  │    │ (POLLING_BACKOFF)  │
    │           │    │ & retry            │
    └────┬──────┘    └─────┬──────────────┘
         │                 │
         ▼                 │
    ┌──────────────────┐   │
    │ Execute command  │   │
    │ (timeout:        │   │
    │  COMMAND_TIMEOUT)│   │
    └──────┬───────────┘   │
           │                │
           ▼                │
    ┌─────────────────┐     │
    │ Report result   │     │
    │ to dashboard    │     │
    └──────┬──────────┘     │
           │                │
           ▼                ▼
    ┌──────────────────────────┐
    │ Loop back to poll again  │
    └──────────────────────────┘
```

## Execution Flow for a Command

When a command is enqueued on the dashboard:

1. **Dashboard enqueues** → POST to `/api/v1/agent/commands/enqueue`
2. **Agent polling** → GET to `/api/v1/agent/commands/wait/{hash}` (waiting)
3. **Server wakes agent** → via `tokio::sync::Notify`
4. **Agent receives command** → HTTP 200 + JSON command
5. **Agent executes** → Spawns process, captures output
6. **Agent reports** → POST to `/api/v1/agent/commands/report` with result

## Error Handling

### Network Errors
- Agent applies `POLLING_BACKOFF_SECS` delay
- Prevents hammering the dashboard on connection issues
- Automatically retries

### Command Execution Timeout
- Monitored via `TimeoutTracker`
- Soft kill at 80% (warning phase)
- Hard SIGTERM at 90%
- Force SIGKILL at 100%
- Result reported with timeout status

### Rate Limiting
- Dashboard enforces rate limits per `AGENT_ID`
- Agent respects 429 responses
- Check dashboard logs if consistently rate-limited

## Monitoring

### View daemon logs:
```bash
# If running in background
tail -f status.pid  # Check if running

# Check system logs
journalctl -u status-panel -f  # if installed as systemd service
```

### Key log entries to look for:
```
Agent daemon starting
long-polling configuration initialized
long-poll: polling loop started
command received from dashboard
command execution and reporting completed
```

## Example: End-to-End Command Flow

### Terminal 1: Start the agent
```bash
DASHBOARD_URL=http://localhost:5000 \
AGENT_ID=test-agent \
DEPLOYMENT_HASH=test-deploy \
./status --config config.json
```

Output:
```
2025-01-12T10:00:00Z INFO Agent daemon starting
2025-01-12T10:00:00Z INFO metrics heartbeat started
2025-01-12T10:00:00Z INFO long-polling configuration initialized
```

### Terminal 2: Enqueue a command
```bash
curl -X POST http://localhost:5000/api/v1/agent/commands/enqueue \
  -H 'Content-Type: application/json' \
  -H 'X-Agent-Id: test-agent' \
  -d '{
    "id": "cmd-001",
    "name": "echo Hello from dashboard",
    "params": {}
  }'
```

### Terminal 1: Agent logs
```
2025-01-12T10:00:05Z INFO command received from dashboard command_id=cmd-001 command_name="echo Hello from dashboard"
2025-01-12T10:00:05Z INFO Executing command: echo Hello from dashboard (id: cmd-001)
2025-01-12T10:00:05Z INFO command execution and reporting completed
```

## Troubleshooting

### Agent not receiving commands
- ✓ Verify `DASHBOARD_URL` is correct and reachable
- ✓ Verify `AGENT_ID` matches dashboard's configured agent ID
- ✓ Check agent logs for errors
- ✓ Ensure `POLLING_TIMEOUT_SECS` is reasonable (>0)

### Commands timing out
- Increase `COMMAND_TIMEOUT_SECS` if commands legitimately take longer
- Check command logs for issues
- Verify process isn't hanging/stuck

### Agent crashes on startup
- ✓ Verify all required env vars are set
- ✓ Check that config.json is valid
- ✓ Ensure dashboard is running (if using non-localhost URL)

### High CPU usage
- This shouldn't happen—agent sleeps while waiting
- Check if commands themselves are CPU-intensive
- Verify `POLLING_TIMEOUT_SECS` > 0

## Advanced Configuration

### Tuning for slow networks
If polling over unreliable network:
```bash
POLLING_TIMEOUT_SECS=60      # Longer wait per request
POLLING_BACKOFF_SECS=10      # More generous backoff
```

### Tuning for fast commands
If mostly running quick commands:
```bash
COMMAND_TIMEOUT_SECS=30      # Shorter timeout
POLLING_TIMEOUT_SECS=20      # Shorter poll wait
```

### High-frequency command processing
If expecting many commands in quick succession:
```bash
POLLING_TIMEOUT_SECS=10      # Quick retry on no command
COMMAND_TIMEOUT_SECS=60      # Still give commands time
```

## Security Considerations

- **X-Agent-Id validation**: Ensure `AGENT_ID` env var matches dashboard configuration
- **HTTPS in production**: Set `DASHBOARD_URL=https://...` for encrypted polling
- **Rate limiting**: Dashboard enforces per-agent rate limits
- **Signature verification**: Optional via `WAIT_REQUIRE_SIGNATURE=true` on dashboard

## See Also

- [API_SPEC.md](API_SPEC.md) - Full `/api/v1/agent/commands/*` endpoint specification
- [SECURITY_ENHANCEMENT.md](SECURITY_ENHANCEMENT.md) - Authentication & authorization
- [examples/long_poll_demo.sh](../examples/long_poll_demo.sh) - Working example script
