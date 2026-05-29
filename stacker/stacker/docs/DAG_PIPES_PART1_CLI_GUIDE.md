# DAG Pipes — Part 1: CLI Guide

Build and run data pipelines using `stacker pipe` commands. No code, no curl — just the CLI.

> **Other guides:**
> [Part 2: Visual Editor (Web UI)](./DAG_PIPES_PART2_WEB_EDITOR.md) ·
> [Part 3: REST API Deep Dive](./DAG_PIPES_PART3_API_DEEP_DIVE.md)

---

## What is a Pipe?

A pipe connects services in your deployment. Data flows from a **source** (where data comes from) through optional **transforms** and **conditions**, to one or more **targets** (where data goes).

```
[Source] → [Transform] → [Target]
```

That's it. Stacker handles the wiring, execution, retries, and history.

---

## Getting Started

```bash
# 1. Login
stacker login

# 2. Make sure you have a deployment running
stacker status
```

> **💡 No cloud deployment yet?** You can experiment locally first — see [Local Mode](#local-mode-experimental) below.

---

## Example 1: Contact Form → Telegram + Slack

**Goal**: When someone submits a contact form, notify your team on both Telegram and Slack.

### Step 1 — Scan your services

```bash
# Remote deployment: probe app endpoints
stacker pipe scan --app website

# See what APIs are available with sample data
stacker pipe scan --app website --capture-samples
```

Output:
```
App: website
Protocols detected: rest

[rest] http://website:3000
     POST /api/contact  -- Submit contact form
          fields: [name, email, message]
          sample: {"name":"Alice","email":"alice@example.com","message":"Hello"}
```

### Step 2 — Create the pipe

```bash
# Interactive wizard walks you through it
stacker pipe create website telegram
```

The wizard will:
1. Scan both apps/containers for endpoints
2. Let you pick source endpoint (POST /api/contact)
3. Let you pick target endpoint (sendMessage)
4. Auto-match fields (`name` → text, `email` → text)
5. Ask for a pipe name

Repeat for Slack:
```bash
stacker pipe create website slack
```

### Step 3 — Activate

```bash
# List your pipes to get the IDs
stacker pipe list

# Activate both — webhook mode triggers on each form submission
stacker pipe activate <telegram-pipe-id>
stacker pipe activate <slack-pipe-id>
```

### Step 4 — Test it

```bash
# Manual trigger with test data
stacker pipe trigger <telegram-pipe-id> \
  --data '{"name":"Alice","email":"alice@example.com","message":"Hello!"}'
```

### Step 5 — Check history

```bash
stacker pipe history <telegram-pipe-id>
```

```
EXECUTION ID                 TRIGGER  STATUS   DURATION  STARTED
─────────────────────────────────────────────────────────────────
a1b2c3d4-e5f6-...            manual   success     342ms  2026-04-16T13:00:00Z

1 execution(s) shown.
```

---

## Example 2: Contact Form → PostgreSQL CDC → Telegram

**Goal**: Your website saves contact forms to PostgreSQL normally. The pipe watches for new rows and sends a Telegram notification — no changes to your website code needed.

```
Website → writes to PostgreSQL (as usual)
                ↓ CDC detects new row
         [cdc_source] → [transform] → [target: telegram]
```

### Step 1 — Scan PostgreSQL for CDC

```bash
stacker pipe scan postgresql --protocols cdc
```

Output:
```
App: postgresql
Protocols detected: cdc

[cdc] postgresql://postgres:5432
     TABLE public.contacts  -- Contact form submissions
           fields: [id, name, email, message, created_at]
     TABLE public.users     -- User accounts
           fields: [id, email, password_hash, created_at]
```

### Step 2 — Create the pipe

```bash
stacker pipe create postgresql telegram
# Select: TABLE public.contacts → POST sendMessage
# The wizard maps: name, email, message → text field
```

### Step 3 — Activate with webhook trigger

```bash
stacker pipe activate <pipe-id> --trigger webhook
```

Now every INSERT into the `contacts` table automatically sends a Telegram message. No polling, no cron jobs.

### Step 4 — Verify

```bash
# Insert a test row into PostgreSQL (from your app or directly)
# Then check pipe history:
stacker pipe history <pipe-id>
```

---

## Example 3: Contact Form → Email + Slack

**Goal**: Send a confirmation email to the user AND post to your team's Slack channel.

### Step 1 — Create both pipes

```bash
# Pipe 1: website → email service
stacker pipe create website email-service

# Pipe 2: website → slack
stacker pipe create website slack
```

### Step 2 — Activate both

```bash
stacker pipe activate <email-pipe-id> --trigger webhook
stacker pipe activate <slack-pipe-id> --trigger webhook
```

### Step 3 — Test

```bash
# Trigger both with the same data
stacker pipe trigger <email-pipe-id> \
  --data '{"name":"Carol","email":"carol@example.com","message":"Demo please"}'

stacker pipe trigger <slack-pipe-id> \
  --data '{"name":"Carol","email":"carol@example.com","message":"Demo please"}'
```

---

## Command Reference

| Command | What it does |
|---------|-------------|
| `stacker pipe scan` | Discover local Docker containers |
| `stacker pipe scan --containers [filter]` | Discover local containers by name |
| `stacker pipe scan --app <app>` | Discover what APIs a remote app exposes |
| `stacker pipe create <source> <target>` | Create a pipe (interactive wizard) |
| `stacker pipe list` | Show all pipes for your deployment |
| `stacker pipe activate <id>` | Start the pipe (begin listening) |
| `stacker pipe deactivate <id>` | Stop the pipe |
| `stacker pipe trigger <id>` | Run the pipe once manually |
| `stacker pipe history <id>` | View past executions |
| `stacker pipe replay <exec-id>` | Re-run a past execution |
| `stacker pipe deploy <id> --deployment <hash>` | Promote local pipe to remote |
| `stacker target [local\|cloud\|server]` | Switch deployment target mode |

### Useful flags

| Flag | Used with | What it does |
|------|-----------|-------------|
| `--json` | Any command | Output as JSON (for scripting) |
| `--trigger webhook` | `activate` | Listen for events in real-time (default) |
| `--trigger poll` | `activate` | Check for changes periodically |
| `--poll-interval 60` | `activate` | Poll every N seconds |
| `--trigger manual` | `activate` | Only run when you call `trigger` |
| `--data '{...}'` | `trigger` | Pass custom input data |
| `--capture-samples` | `scan` | Show real response examples |
| `--ai` | `create` | Use AI for smart field matching |
| `--no-ai` | `create` | Use deterministic matching only |
| `--manual` | `create` | Skip auto-matching entirely |
| `--limit 50` | `history` | Show more results |

---

## Trigger Types Explained

| Type | How it works | Best for |
|------|-------------|----------|
| **webhook** | Fires instantly when data arrives | Real-time notifications |
| **poll** | Checks for new data every N seconds | Periodic syncs, batch jobs |
| **manual** | Only runs when you say `pipe trigger` | Testing, one-off transfers |

---

## Debugging

```bash
# See what went wrong
stacker pipe history <id> --json | jq '.[0]'

# Replay a failed execution (retries with same input)
stacker pipe replay <execution-id>

# Trigger with custom test data
stacker pipe trigger <id> --data '{"name":"test","email":"test@test.com","message":"debug"}'
```

---

## Local Mode (Experimental)

Local mode lets you design, test, and iterate on pipes **without a cloud deployment**. Pipes run against your local Docker containers.

### Setting Up Local Mode

```bash
# Switch to local mode
stacker target local

# Verify active target
stacker target
# Output: Active target: local

# All pipe commands now show [local] prefix
stacker pipe scan
# [local] ✓ 3 containers discovered
# [local] ✓ 7 endpoints/resources discovered
```

### Local Workflow

```bash
# 1. Discover local endpoints/resources from running containers
stacker pipe scan

# Optional: narrow to matching container names
stacker pipe scan --containers website

# 2. Create a pipe — no deployment hash needed
stacker pipe create website telegram
# [local] ✓ Pipe instance created (id: abc-123)

# 3. Trigger locally (executes via docker exec)
stacker pipe trigger abc-123 --data '{"name":"test","email":"test@test.com"}'

# 4. Check history
stacker pipe history abc-123

# 5. When ready — promote to a remote deployment
stacker pipe deploy abc-123 --deployment <your-deployment-hash>
# ✓ Local pipe promoted to remote deployment
# Remote instance ID: def-456
# Use 'stacker pipe activate def-456' to start the remote pipe.
```

### Switching Targets

```bash
stacker target local   # local Docker containers
stacker target cloud   # cloud deployment (from prior deploy)
stacker target server  # dedicated server deployment
stacker target         # show current
```

### What Works Locally

| Command | Local Behavior |
|---------|---------------|
| `pipe scan` | Discovers local endpoints/resources from running containers |
| `pipe scan --containers [filter]` | Filters matching containers, then probes their endpoints/resources |
| `pipe scan --app <app>` | Not used locally — use container discovery instead |
| `pipe create` | Creates pipe with `is_local=true`, no deployment hash |
| `pipe list` | Shows your local pipes only |
| `pipe trigger` | Executes via `docker exec` / HTTP |
| `pipe history` | Shows execution history |
| `pipe deploy` | Promotes local pipe → remote deployment |
| `pipe activate/deactivate` | Remote only (use after deploy) |
| `pipe replay` | Remote only |

### Scan Semantics

- **Local target** → scan works with **containers**
- **Remote target** → scan works with **apps**, optionally narrowed by `--container`

```bash
# Local
stacker pipe scan
stacker pipe scan --containers upload

# Remote
stacker pipe scan --app website
stacker pipe scan --app website --container website-web-1
```

Legacy `stacker pipe scan <ARG>` still works during the transition:

- in **local mode** it is treated as a container name filter
- in **remote mode** it is treated as an app code

When local scan succeeds, expect output like:

```text
[local] ✓ 1 container(s) discovered

  Containers matched: 1
    local-device-api-1  [app-network] example/device-api:local
      addresses: 172.18.0.20:5050

  App: device-api
  Protocols detected: openapi, postgres

  [openapi] http://172.18.0.20:5050/openapi.json
       GET /devices
           fields: [id, name]

  Resources:
    [postgres] postgres://172.18.0.10:5432/app (local-postgres-1)
      table public.devices  -- CDC candidate
```

---

## What's Next?

- **[Part 2: Visual Editor](./DAG_PIPES_PART2_WEB_EDITOR.md)** — Build pipes with drag-and-drop in your browser
- **[Part 3: REST API Deep Dive](./DAG_PIPES_PART3_API_DEEP_DIVE.md)** — Full API reference, curl scripts, gRPC streaming, advanced DAG features
