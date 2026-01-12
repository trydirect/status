# Long-Polling Quick Start

## 1️⃣ Set Environment Variables

Add to `.env`:
```bash
DASHBOARD_URL=http://localhost:5000
AGENT_ID=my-agent
DEPLOYMENT_HASH=my-deployment
POLLING_TIMEOUT_SECS=30
POLLING_BACKOFF_SECS=5
COMMAND_TIMEOUT_SECS=300
```

## 2️⃣ Start the Agent

```bash
./status --config config.json
```

Expected output:
```
Agent daemon starting
metrics heartbeat started
long-polling configuration initialized
```

## 3️⃣ Enqueue a Command (from dashboard or curl)

```bash
curl -X POST http://localhost:5000/api/v1/commands/enqueue \
  -H 'Content-Type: application/json' \
  -H 'X-Agent-Id: my-agent' \
  -d '{
    "id": "cmd-001",
    "name": "echo Hello",
    "params": {}
  }'
```

## 4️⃣ Agent Executes & Reports Automatically

Agent logs:
```
command received from dashboard command_id=cmd-001 command_name="echo Hello"
Executing command: echo Hello (id: cmd-001)
command execution and reporting completed
```

## Environment Variables Reference

| Variable | Default | Recommended Range | Notes |
|----------|---------|-------------------|-------|
| `DASHBOARD_URL` | `http://localhost:5000` | N/A | Must be reachable |
| `POLLING_TIMEOUT_SECS` | `30` | 10-60s | How long to wait per poll |
| `POLLING_BACKOFF_SECS` | `5` | 1-30s | Delay after error |
| `COMMAND_TIMEOUT_SECS` | `300` | 30-3600s | Max per command |

## Typical Flow

```
┌────────────────────────────────────┐
│ Agent starts & polls dashboard     │
└───────────────┬────────────────────┘
                │ (waiting for command)
         ┌──────┴───────┐
         │ (30s timeout)│
         ▼              │
    ┌─────────┐    ┌────▼───────┐
    │Command  │    │  Timeout   │
    │arrives! │    │  (retry)   │
    └────┬────┘    └────┬───────┘
         │             │
         ▼             │
    ┌─────────────────────┐
    │ Execute & report    │
    └────┬────────────────┘
         │
         ▼
    ┌─────────────────────┐
    │ Loop (poll again)   │
    └─────────────────────┘
```

## Troubleshooting

| Problem | Check |
|---------|-------|
| Agent not receiving commands | ✓ `DASHBOARD_URL` correct & reachable<br/>✓ `AGENT_ID` matches dashboard config<br/>✓ Agent logs show polling started |
| Commands timeout | Increase `COMMAND_TIMEOUT_SECS` |
| Agent crashes | Verify `.env` variables are valid |
| High CPU usage | Shouldn't happen—check if commands are CPU-intensive |

## Complete Example

Start terminal 1 (server):
```bash
./status serve --port 5000
```

Start terminal 2 (agent):
```bash
DASHBOARD_URL=http://localhost:5000 \
AGENT_ID=test-agent \
./status --config config.json
```

Start terminal 3 (enqueue command):
```bash
curl -X POST http://localhost:5000/api/v1/commands/enqueue \
  -H 'Content-Type: application/json' \
  -H 'X-Agent-Id: test-agent' \
  -d '{
    "id": "test-1",
    "name": "date",
    "params": {}
  }'
```

Terminal 2 shows:
```
command received from dashboard
Executing command: date
command execution and reporting completed
```

## Advanced Tuning

### Slow network?
```bash
POLLING_TIMEOUT_SECS=60
POLLING_BACKOFF_SECS=10
```

### Quick commands?
```bash
COMMAND_TIMEOUT_SECS=30
```

### Many commands?
```bash
POLLING_TIMEOUT_SECS=10
```

---

**For full documentation, see [docs/LONG_POLLING_SETUP.md](docs/LONG_POLLING_SETUP.md)**
