# Status Panel (Beacon)

Server stack health application with UI.


## Build

```bash
cargo build --release
```

## Run

Foreground daemon (default without subcommands):

```bash
./target/release/status --config config.json
```

Daemon mode (background):

```bash
./target/release/status --daemon --config config.json
```

Local API server (API-only mode):

```bash
./target/release/status serve --port 8080
```

Local API server with UI (serves HTML templates):

```bash
./target/release/status serve --port 8080 --with-ui
```

Then open your browser to `http://localhost:8080/login` to access the web interface.

Docker operations (requires `--features docker`):

```bash
cargo run --features docker --bin status -- containers
cargo run --features docker --bin status -- restart status
```

## Features

- **API-only mode**: Returns JSON responses for programmatic access
- **UI mode** (`--with-ui`): Serves HTML templates from `templates/` directory with static files from `static/`
- Docker container management (list, restart, stop, pause)
- Session-based authentication
- Health check endpoint

## Command Execution (API)

Execute validated shell commands via the local API. The endpoint accepts a `transport::Command` payload and returns a `transport::CommandResult`.

- Endpoint: `POST /api/v1/commands/execute`
- Required fields: `id` (string), `name` (full command line)
- Optional: `params.timeout_secs` (number) to override the default 60s timeout

Example: run a simple echo

```bash
curl -s \
	-H 'Content-Type: application/json' \
	-X POST http://localhost:8080/api/v1/commands/execute \
	-d '{
		"id": "cmd-001",
		"name": "echo hello from agent",
		"params": { "timeout_secs": 10 }
	}' | jq .
```

Example: run a short sleep

```bash
curl -s \
	-H 'Content-Type: application/json' \
	-X POST http://localhost:8080/api/v1/commands/execute \
	-d '{
		"id": "cmd-002",
		"name": "sleep 2",
		"params": { "timeout_secs": 5 }
	}' | jq .
```

Notes:
- Commands are validated by a conservative allowlist and safety checks; see `src/commands/validator.rs`.
- Disallowed by default: shells (`sh`, `bash`, `zsh`) and metacharacters like `; | & > <`.
- Absolute paths must match allowed prefixes (defaults: `/tmp`, `/var/tmp`).
- Output (`stdout`/`stderr`) and `exit_code` are included when available, along with a `status` of `success`, `failed`, `timeout`, or `killed`.

## Long-Poll Command Queue

The agent supports an in-memory command queue for dashboard-driven execution via long-polling. Commands are queued and agents poll for them with configurable timeouts.

### Endpoints

- `GET /api/v1/commands/wait/{hash}?timeout=N` - Long-poll for next queued command (default 30s timeout)
- `POST /api/v1/commands/report` - Report command execution result
- `POST /api/v1/commands/enqueue` - Enqueue a command (for testing/local use)

All endpoints require `X-Agent-Id` header matching the `AGENT_ID` environment variable.

### Manual Testing

Start the server with agent ID:

```bash
export AGENT_ID=test-agent
cargo r -- serve --port 8080
```

**Terminal 1: Long-poll for commands**

```bash
curl -H 'X-Agent-Id: test-agent' \
  'http://localhost:8080/api/v1/commands/wait/demo?timeout=10'
```

**Terminal 2: Enqueue a command**

```bash
curl -s \
  -H 'Content-Type: application/json' \
  -X POST http://localhost:8080/api/v1/commands/enqueue \
  -d '{
    "id": "cmd-001",
    "name": "echo hello from queue",
    "params": {}
  }' | jq .
```

The long-poll in Terminal 1 will immediately return the queued command.

**Report command result**

```bash
curl -s \
  -H 'Content-Type: application/json' \
  -H 'X-Agent-Id: test-agent' \
  -X POST http://localhost:8080/api/v1/commands/report \
  -d '{
    "command_id": "cmd-001",
    "status": "success",
    "result": {"exit_code": 0, "stdout": "hello from queue\n"},
    "error": null
  }' | jq .
```

### Demo Script

Run the automated demo:

```bash
export AGENT_ID=test-agent
./examples/long_poll_demo.sh
```

This script starts a background poller, enqueues a command, and demonstrates the long-poll notification mechanism.

## Templates

The UI uses Tera templating engine (similar to Jinja2). Templates are located in:
- `templates/` - HTML templates (login.html, index.html, error.html)
- `static/` - CSS, JavaScript, and other static assets

## Notes

- Reads `config.json` and normalizes `apps_info` to structured items.
- Subsystems marked with `@todo` will be implemented per `.ai/GOAL.md`.
