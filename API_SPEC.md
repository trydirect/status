# Status Panel Agent - API Specification

**Version:** 2.0  
**Last Updated:** December 25, 2025

## Overview

The Status Panel Agent exposes a REST API for remote command execution and system monitoring. This specification describes the endpoints available for dashboard developers to queue commands, receive execution results, and monitor agent status.

## Base URL

```
http://<agent-host>:<port>
```

Default port: `8080`

## Authentication & Signing

For all POST endpoints, requests must include identity, freshness, uniqueness, and an HMAC signature over the raw body. Required headers:

- `X-Agent-Id: <AGENT_ID>`
- `X-Timestamp: <unix_seconds>`
- `X-Request-Id: <uuid_v4>`
- `X-Agent-Signature: <base64 HMAC-SHA256(body, AGENT_TOKEN)>`

Notes:
- Signature is over the exact HTTP request body bytes, using the agent's `AGENT_TOKEN`.
- Default freshness window: 300s. Default replay TTL: 600s.
- Per-agent rate limits apply (default 120/min).

Optional: `GET /api/v1/commands/wait/{hash}` can also require signing if `WAIT_REQUIRE_SIGNATURE=true` (see below). Otherwise, it only enforces `X-Agent-Id` and rate limits.

---

## Endpoints

### 1. Health Check

**Endpoint:** `GET /health`  
**Authentication:** None  
**Description:** Returns agent health status including token rotation metrics (if Vault is configured)

**Response (200 OK):**
```json
{
  "status": "ok",
  "token_age_seconds": 120,
  "last_refresh_ok": true
}
```

**Fields:**
- `status`: Always "ok" if agent is running
- `token_age_seconds`: Seconds since last successful token rotation from Vault (0 if Vault not configured)
- `last_refresh_ok`: null if Vault not configured, true/false based on last fetch success

**Note on Vault Integration:**
When Vault is enabled via `VAULT_ADDRESS` environment variable, the agent automatically refreshes its authentication token every 60s (+ jitter) from the KV store. Monitor `token_age_seconds` > 600 as a potential warning that Vault fetch has stalled. See [VAULT_INTEGRATION.md](VAULT_INTEGRATION.md) for configuration details.

---

### 2. Metrics (Snapshot)

**Endpoint:** `GET /metrics`  
**Authentication:** None  
**Description:** Returns current system metrics snapshot

**Response (200 OK):**
```json
{
  "timestamp_ms": 1703512345678,
  "cpu_usage_pct": 15.2,
  "memory_total_bytes": 17592186044416,
  "memory_used_bytes": 8796093022208,
  "memory_used_pct": 50.0,
  "disk_total_bytes": 2000828440576,
  "disk_used_bytes": 1000414220288,
  "disk_used_pct": 50.0
}
```

---

### 3. Metrics (WebSocket Stream)

**Endpoint:** `GET /metrics/stream` (WebSocket)  
**Authentication:** None  
**Description:** Real-time metrics via WebSocket; pushes `MetricsSnapshot` JSON every 30s (configurable via `METRICS_INTERVAL_SECS`)

**Message Format:**
```json
{
  "timestamp_ms": 1703512345678,
  "cpu_usage_pct": 12.5,
  "memory_used_bytes": 8796093022208,
  "memory_total_bytes": 17592186044416,
  "memory_used_pct": 50.0,
  "disk_used_bytes": 1000414220288,
  "disk_total_bytes": 2000828440576,
  "disk_used_pct": 50.0
}
```

---

### 4. Enqueue Command

**Endpoint:** `POST /api/v1/commands/enqueue`  
**Authentication:** HMAC-signed headers required  
**Scopes:** `commands:enqueue`  
**Description:** Add a command to the agent's execution queue. Used by dashboards to schedule commands for execution.

**Request Body:**
```json
{
  "id": "cmd-12345",
  "name": "tar -czf /tmp/backup.tar.gz /data",
  "params": {
    "timeout_secs": 300,
    "priority": "normal",
    "metadata": {
      "user": "admin",
      "reason": "scheduled backup"
    }
  }
}
```

**Fields:**
- `id` (string, required): Unique command identifier
- `name` (string, required): Full command line to execute
- `params` (object, optional): Additional parameters
  - `timeout_secs` (number): Override default timeout (60s)
  - `priority` (string): Command priority (reserved for future use)
  - `metadata` (object): Arbitrary metadata for tracking

**Response (202 Accepted):**
```json
{
  "queued": true
}
```

**Validation Notes:**
- Commands are validated against a security allowlist before execution
- By default, only safe programs are allowed: `echo`, `sleep`, `ls`, `tar`, `gzip`, `uname`, `date`, `df`, `du`
- Shell invocation (`sh`, `bash`, `zsh`) is disabled by default
- Metacharacters (`; | & > < $ ` `) are blocked
- Absolute paths must match allowed prefixes (`/tmp`, `/var/tmp`)

---

### 5. Long-Poll for Commands

**Endpoint:** `GET /api/v1/commands/wait/{hash}`  
**Authentication:** `X-Agent-Id` required; optional HMAC signing if `WAIT_REQUIRE_SIGNATURE=true`  
**Scopes:** `commands:wait` (only when `WAIT_REQUIRE_SIGNATURE=true`)  
**Description:** Long-poll for the next queued command. Blocks until a command is available or timeout is reached.

**Path Parameters:**
- `hash` (string): Deployment/session hash (currently unused, reserved for multi-tenant scenarios)

**Query Parameters:**
- `timeout` (number, optional): Maximum wait time in seconds (default: 30)
- `priority` (string, optional): Filter by priority (reserved for future use)

**Example Request:**
```bash
curl -H 'X-Agent-Id: agent-001' \
  'http://agent:8080/api/v1/commands/wait/session-hash?timeout=60'
```

**Response (200 OK) - Command Available:**
```json
{
  "id": "cmd-12345",
  "name": "tar -czf /tmp/backup.tar.gz /data",
  "params": {
    "timeout_secs": 300,
    "metadata": {
      "user": "admin",
      "reason": "scheduled backup"
    }
  }
}
```

**Response (204 No Content) - No Commands:**
Returns empty body when timeout expires with no commands queued.

**Response (401 Unauthorized) - Invalid Agent ID:**
```json
{
  "error": "Invalid or missing X-Agent-Id"
}
```

---

### 6. Execute Command Directly

**Endpoint:** `POST /api/v1/commands/execute`  
**Authentication:** HMAC-signed headers required  
**Scopes:** `commands:execute` and, for Docker ops, one of `docker:restart|stop|pause|logs|inspect`  
**Description:** Execute a command immediately without queuing. Synchronous execution with timeout management.

**Request Body:**
```json
{
  "id": "cmd-67890",
  "name": "df -h",
  "params": {
    "timeout_secs": 10
  }
}
```

**Response (200 OK) - Success:**
```json
{
  "command_id": "cmd-67890",
  "status": "success",
  "result": {
    "exit_code": 0,
    "duration_secs": 1,
    "stdout": "Filesystem      Size  Used Avail Use% Mounted on\n/dev/sda1       100G   50G   50G  50% /\n"
  },
  "error": null
}
```

**Response (200 OK) - Timeout:**
```json
{
  "command_id": "cmd-67890",
  "status": "timeout",
  "result": {
    "exit_code": null,
    "duration_secs": 60,
    "stdout": "partial output...",
    "stderr": ""
  },
  "error": "Command exceeded timeout"
}
```

**Response (400 Bad Request) - Validation Failed:**
```json
{
  "error": "invalid command: program 'rm' is not allowed"
}
```

**Response (500 Internal Server Error) - Execution Failed:**
```json
{
  "error": "failed to spawn command: No such file or directory"
}
```

**Docker Commands:**
For Docker operations, use the special `docker:operation:container_name` format:

```bash
# Restart a container
curl -X POST http://agent:8080/api/v1/commands/execute \
  -H 'Content-Type: application/json' \
  -d '{
    "id": "restart-nginx",
    "name": "docker:restart:nginx",
    "params": {}
  }'
```

**Docker Operations:**
- `docker:restart:container_name` - Restart a container
- `docker:stop:container_name` - Stop a container
- `docker:logs:container_name` - View container logs (tail 100 lines)
- `docker:logs:container_name:50` - View container logs with custom tail count
- `docker:inspect:container_name` - Get detailed container information
- `docker:pause:container_name` - Pause a container

**Response (200 OK) - Docker Operation Success:**
```json
{
  "command_id": "restart-nginx",
  "status": "success",
  "result": {
    "exit_code": 0,
    "duration_secs": 2,
    "operation": "restart",
    "container": "nginx",
    "stdout": "Container 'nginx' restarted successfully"
  },
  "error": null
}
```

---

### 7. Report Command Result

**Endpoint:** `POST /api/v1/commands/report`  
**Authentication:** HMAC-signed headers required  
**Scopes:** `commands:report`  
**Description:** Report the result of a command execution back to the dashboard. Used by agents after executing commands received via long-poll.
### 8. Rotate Agent Token

**Endpoint:** `POST /api/v1/auth/rotate-token`  
**Authentication:** HMAC-signed headers required (signed with current token)  
**Scopes:** `auth:rotate`  
**Description:** Rotate the agent's signing token in-memory without restart.

**Request Body:**
```json
{ "new_token": "<NEW_TOKEN>" }
```

**Response (200 OK):**
```json
{ "rotated": true }
```

Errors: 400 malformed; 401 invalid signature; 403 insufficient scope; 409 replay; 429 rate limited.

**Request Body:**
```json
{
  "command_id": "cmd-12345",
  "status": "success",
  "result": {
    "exit_code": 0,
    "duration_secs": 45,
    "stdout": "backup completed successfully\n",
    "stderr": ""
  },
  "error": null
}
```

**Fields:**
- `command_id` (string, required): Matches the `id` from the original command
- `status` (string, required): One of: `success`, `failed`, `timeout`, `killed`
- `result` (object, optional): Execution details
  - `exit_code` (number): Process exit code
  - `duration_secs` (number): Execution time in seconds
  - `stdout` (string): Standard output (may be truncated for large outputs)
  - `stderr` (string): Standard error
- `error` (string, optional): Error message for failed executions

**Response (200 OK):**
```json
{
  "accepted": true
}
```

---

## Command Execution Flow

### Dashboard-Driven Workflow

```
┌──────────┐                    ┌───────┐                    ┌─────────────┐
│Dashboard │                    │ Agent │                    │ Agent Queue │
└────┬─────┘                    └───┬───┘                    └──────┬──────┘
     │                              │                               │
     │ POST /commands/enqueue       │                               │
     ├─────────────────────────────>│  Add to queue                 │
     │                              ├──────────────────────────────>│
     │ 202 Accepted                 │                               │
     │<─────────────────────────────┤                               │
     │                              │                               │
     │                              │ GET /commands/wait (long-poll)│
     │                              │<──────────────────────────────┤
     │                              │                               │
     │                              │ 200 OK (command)              │
     │                              ├──────────────────────────────>│
     │                              │                               │
     │                              │  [Execute command]            │
     │                              │                               │
     │ POST /commands/report        │                               │
     │<─────────────────────────────┤                               │
     │                              │                               │
     │ 200 OK                       │                               │
     ├─────────────────────────────>│                               │
     │                              │                               │
```

### Direct Execution Workflow

```
┌──────────┐                    ┌───────┐
│Dashboard │                    │ Agent │
└────┬─────┘                    └───┬───┘
     │                              │
     │ POST /commands/execute       │
     ├─────────────────────────────>│
     │                              │
     │                              │ [Execute & wait]
     │                              │
     │ 200 OK (result)              │
     │<─────────────────────────────┤
     │                              │
```

---

## Environment Variables

Agents read the following environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `AGENT_ID` | Unique agent identifier for header validation | none |
| `METRICS_WEBHOOK` | URL to push metrics snapshots (optional) | none |
| `METRICS_INTERVAL_SECS` | Metrics collection interval | 30 (server), 10 (daemon) |
| `STATUS_PANEL_USERNAME` | UI login username | `admin` |
| `STATUS_PANEL_PASSWORD` | UI login password | `admin` |

---

## Command Validation Rules

The agent applies the following security rules to all commands:

### Allowed Programs (Default)
- `echo`, `sleep`, `ls`, `tar`, `gzip`, `uname`, `date`, `df`, `du`

### Docker Operations (Whitelist)
Instead of allowing arbitrary Docker CLI commands, the agent provides a restricted set of Docker operations via the `docker:operation:container_name` syntax:

**Allowed Operations:**
- `docker:restart:nginx` - Restart a container
- `docker:stop:nginx` - Stop a container
- `docker:pause:nginx` - Pause a container
- `docker:unpause:nginx` - Unpause a container
- `docker:logs:nginx` - View container logs
- `docker:logs:nginx:50` - View container logs with custom tail count
- `docker:inspect:nginx` - Get container details

**Security Benefits:**
- No arbitrary Docker commands (no `docker run -v /etc:/host alpine cat /host/shadow`)
- Container names validated: alphanumeric, dash, underscore, max 63 chars
- Operations executed via Bollard API, not shell spawning
- Each operation goes through secure Bollard client, not CLI parsing

**Example Safe Requests:**
```bash
# ✅ Safe: Restart nginx container
docker:restart:nginx

# ✅ Safe: Get logs for redis
docker:logs:redis

# ❌ Blocked: Arbitrary docker CLI
docker ps -a

# ❌ Blocked: Malicious container names
docker:restart:nginx; rm -rf /
```

### Blocked Patterns
- Shell invocations: `sh`, `bash`, `zsh` (unless explicitly enabled)
- Metacharacters: `; | & > < $ ` ` ` (backticks)
- Path traversal: `../`, `/../`
- Environment hijacking: `VAR=value command`


Docker commands are allowed if `docker` is in the allowlist:

# Restart a container
curl -H 'X-Agent-Id: test-agent' \
  -d '{"id":"restart-1","name":"docker restart nginx"}' \
  http://agent:8080/api/v1/commands/enqueue

# Stop a container
curl -H 'X-Agent-Id: test-agent' \
  -d '{"id":"stop-1","name":"docker stop redis"}' \
  http://agent:8080/api/v1/commands/enqueue

# View container logs
curl -H 'X-Agent-Id: test-agent' \
  -d '{"id":"logs-1","name":"docker logs nginx --tail 50"}' \
  http://agent:8080/api/v1/commands/enqueue



### Path Restrictions
- Absolute paths must start with allowed prefixes: `/tmp`, `/var/tmp`
- Other paths are rejected by default

### Argument Limits
- Maximum arguments: 16
- Maximum argument length: 4096 characters

**Override:** To customize validation, modify `ValidatorConfig` in `src/commands/validator.rs` and rebuild the agent.

---

## Timeout Strategy

Commands execute with a multi-phase timeout system:

1. **Normal Phase (0-80% of timeout):** Normal execution, output streaming
2. **Warning Phase (80-90%):** Log warning, continue execution
3. **Hard Termination (90-100%):** Send SIGTERM (Unix) or terminate signal
4. **Force Kill (100%+):** Send SIGKILL (Unix) or force kill

**Progress Tracking:** The executor resets a "stall timer" when output is received. If no output for `stall_threshold_secs` (default: 60s), the command is considered stalled and logged.

---

## Error Codes

| HTTP Status | Meaning |
|-------------|---------|
| 200 | Success - Command executed or result reported |
| 202 | Accepted - Command queued |
| 204 | No Content - No commands available (long-poll timeout) |
| 400 | Bad Request - Invalid command or validation failed |
| 401 | Unauthorized - Missing or invalid `X-Agent-Id` or invalid signature |
| 403 | Forbidden - Insufficient scope or IP restriction (backup endpoints) |
| 409 | Conflict - Replay detected (duplicate `X-Request-Id`) |
| 429 | Too Many Requests - Rate limit exceeded |
| 403 | Forbidden - IP restriction (backup endpoints only) |
| 404 | Not Found - Resource not found |
| 500 | Internal Server Error - Agent execution error |

---

## Integration Examples

### Python Dashboard Integration

```python
import requests
import time

AGENT_URL = "http://agent-host:8080"
AGENT_ID = "agent-001"

def enqueue_command(cmd_id, command, timeout=60):
    """Queue a command for execution."""
    response = requests.post(
        f"{AGENT_URL}/api/v1/commands/enqueue",
        json={
            "id": cmd_id,
            "name": command,
            "params": {"timeout_secs": timeout}
        }
    )
    return response.json()

def wait_for_result(cmd_id, timeout=300):
    """Poll for command result."""
    start = time.time()
    while time.time() - start < timeout:
        response = requests.get(
            f"{AGENT_URL}/api/v1/commands/wait/session",
            headers={"X-Agent-Id": AGENT_ID},
            params={"timeout": 30}
        )
        
        if response.status_code == 200:
            command = response.json()
            if command["id"] == cmd_id:
                return command
        
        time.sleep(1)
    
    return None

# Example usage
enqueue_command("backup-001", "tar -czf /tmp/backup.tar.gz /data", timeout=300)
result = wait_for_result("backup-001")
print(f"Command result: {result}")
```

### Node.js Dashboard Integration

```javascript
const axios = require('axios');

const AGENT_URL = 'http://agent-host:8080';
const AGENT_ID = 'agent-001';

async function enqueueCommand(cmdId, command, timeoutSecs = 60) {
  const response = await axios.post(`${AGENT_URL}/api/v1/commands/enqueue`, {
    id: cmdId,
    name: command,
    params: { timeout_secs: timeoutSecs }
  });
  return response.data;
}

async function longPollCommand(timeoutSecs = 30) {
  try {
    const response = await axios.get(
      `${AGENT_URL}/api/v1/commands/wait/session`,
      {
        headers: { 'X-Agent-Id': AGENT_ID },
        params: { timeout: timeoutSecs },
        timeout: (timeoutSecs + 5) * 1000
      }
    );
    return response.data;
  } catch (error) {
    if (error.response?.status === 204) {
      return null; // No commands
    }
    throw error;
  }
}

async function reportResult(result) {
  const response = await axios.post(
    `${AGENT_URL}/api/v1/commands/report`,
    result,
    { headers: { 'X-Agent-Id': AGENT_ID } }
  );
  return response.data;
}

// Example: continuous polling
(async () => {
  while (true) {
    const command = await longPollCommand(60);
    if (command) {
      console.log('Received command:', command.id);
      // Execute and report...
    }
  }
})();
```

---

## WebSocket Integration

For real-time metrics monitoring, connect to the WebSocket endpoint:

```javascript
const ws = new WebSocket('ws://agent-host:8080/metrics/stream');

ws.onmessage = (event) => {
  const metrics = JSON.parse(event.data);
  console.log('CPU:', metrics.cpu_usage_pct);
  console.log('Memory:', metrics.memory_used_pct);
  console.log('Disk:', metrics.disk_used_pct);
};

ws.onerror = (error) => {
  console.error('WebSocket error:', error);
};
```

---

## Rate Limits and Best Practices

### Recommendations

1. **Long-Poll Timeout:** Use 30-60 second timeouts for `/commands/wait`
2. **Command Queue Depth:** Agents hold commands in-memory; avoid queuing >100 commands
3. **Result Reporting:** Always report command results to prevent orphaned executions
4. **Retries:** Implement exponential backoff for 5xx errors (start at 1s, max 60s)
5. **Metrics Polling:** Use WebSocket for real-time metrics; avoid polling `/metrics` more than once per 10s

### Limits

- **Command Queue:** No hard limit (in-memory, cleared on restart)
- **Command Name Length:** 4096 characters
- **Result Size:** Stdout/stderr truncated at ~64KB per stream
- **Concurrent Executions:** 1 (commands execute sequentially)

---

## Security Considerations

1. **HMAC Signing:** POST requests must include required headers; see `STACKER_INTEGRATION_REQUIREMENTS.md` for details and examples.
2. **Scopes:** Configure allowed scopes via `AGENT_SCOPES` to enforce least privilege.
3. **X-Agent-Id Validation:** Always set `AGENT_ID` in production to prevent unauthorized access.
4. **Network Security:** Run agents behind a firewall; expose only to trusted Stacker IPs.
5. **TLS/HTTPS:** Use a reverse proxy (nginx/traefik) with TLS for production deployments.
6. **Audit Logs:** Authentication attempts, replays, rate limits, and command executions are logged via `tracing` target `audit`.

---

## Changelog

### Version 2.0 (2025-12-25)
- Added long-poll command queue (`/commands/wait`, `/commands/report`, `/commands/enqueue`)
- Implemented HMAC request signing with `AGENT_TOKEN` for POST endpoints
- Added scope-based authorization and per-agent rate limiting
- Added token rotation endpoint (`/api/v1/auth/rotate-token`)
- Optional signing for GET `/commands/wait` behind `WAIT_REQUIRE_SIGNATURE`
- Added direct command execution (`/commands/execute`)
- Multi-phase timeout strategy with progress tracking
- WebSocket metrics streaming

### Version 1.0 (Legacy)
- Flask-based Python implementation (deprecated)
- Basic container management endpoints
- Session-based authentication

---

## Support

For issues or questions, refer to:
- **Source Code:** `src/comms/local_api.rs` (API routes)
- **Command Executor:** `src/commands/executor.rs` (execution logic)
- **Validator:** `src/commands/validator.rs` (security rules)
- **Transport Types:** `src/transport/mod.rs` (data structures)

**License:** See `LICENSE` file in repository root.
