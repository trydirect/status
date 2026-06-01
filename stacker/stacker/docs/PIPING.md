# Stacker Piping Guide

Data piping connects containerized apps in a deployment, routing data from one service's API to another with automatic field mapping.

## Architecture

```
+------------------+       +------------------+       +------------------+
|   stacker CLI    |       |  Stacker Server  |       |   Status Agent   |
|                  |       |                  |       |  (on deployment) |
|  pipe scan       | ----> |  enqueue command  | ----> |  probe container |
|  pipe create     |       |  validate params  |       |  curl endpoints  |
|  pipe trigger    |       |  store results    |       |  capture samples |
|  pipe history    |       |  persist history  |       |  execute pipes   |
|  pipe deploy     |       |  promote local→   |       |                  |
+------------------+       +------------------+       +------------------+
        |
        | (local mode — no agent needed)
        v
+------------------+
|  Local Docker    |
|  docker ps       |
|  docker exec     |
+------------------+
```

**Three components work together:**

1. **CLI** (`stacker pipe`) - user-facing commands
2. **Server** (`/api/v1/pipes`) - REST API, validation, persistence
3. **Agent** (status-panel) - runs on the deployment, probes app/container endpoints, executes pipe triggers

> **Local mode**: When `stacker target local` is active, scan starts with Docker discovery (`docker ps` + `docker inspect`) and then probes matched containers for endpoints/resources locally — no remote agent required. Pipes are stored with `is_local=true` and no `deployment_hash`.

> **Scan semantics**: local scan is **container-first**; remote scan is **app-first** with optional `--container` narrowing.

## Quick Start

### 1. Scan for connectable endpoints

```bash
# Local target: discover endpoints/resources from running containers
stacker pipe scan

# Filter local containers by name, then probe them
stacker pipe scan --containers wordpress

# Remote target: probe a deployed app for endpoints
stacker pipe scan --app wordpress --capture-samples

# Scan specific protocols
stacker pipe scan --app wordpress --protocols openapi,html_forms,rest
```

Output:
```
  Containers matched: 1
    local-wordpress-1 [blog] wordpress:latest
      addresses: 172.18.0.8:80

  App: wordpress
  Protocols detected: openapi

  [openapi] http://wordpress:80/wp-json
       GET /wp/v2/posts  -- List posts
           fields: [id, title, content, author, date]
           sample: [{"id":1,"title":{"rendered":"Hello World"},"author":42}]
      POST /wp/v2/posts  -- Create post
           fields: [title, content, status, author]
       GET /wp/v2/users  -- List users
           fields: [id, name, email, slug]
```

### 2. Create a pipe between two apps

```bash
# Interactive wizard: scans both apps, presents endpoint picker
stacker pipe create wordpress mailchimp

# Skip auto-matching, manual selection only
stacker pipe create wordpress mailchimp --manual
```

The wizard:
1. Scans both apps for endpoints (with sample capture)
2. Presents source endpoint selector
3. Presents target endpoint selector
4. Auto-matches fields using 4-layer smart matching
5. Asks for a pipe name
6. Creates a template + instance

### 3. Activate the pipe

```bash
# Webhook mode (default): triggers on incoming data
stacker pipe activate <pipe-id>

# Poll mode: checks source every N seconds
stacker pipe activate <pipe-id> --trigger poll --poll-interval 60

# Manual mode: only triggers when you run `pipe trigger`
stacker pipe activate <pipe-id> --trigger manual
```

### 4. Trigger manually

```bash
# One-shot execution
stacker pipe trigger <pipe-id>

# With custom input data (overrides source fetch)
stacker pipe trigger <pipe-id> --data '{"email":"test@example.com","name":"Alice"}'
```

### 5. View execution history

```bash
# Show last 20 executions
stacker pipe history <pipe-id>

# Show more
stacker pipe history <pipe-id> --limit 50

# JSON output for scripting
stacker pipe history <pipe-id> --json
```

Output:
```
EXECUTION ID                           TRIGGER    STATUS       DURATION STARTED                ERROR
--------------------------------------------------------------------------------------------------------------
a1b2c3d4-e5f6-...                      manual     success         342ms 2026-04-10T12:00:00Z
b2c3d4e5-f6a7-...                      webhook    success         215ms 2026-04-10T11:45:00Z
c3d4e5f6-a7b8-...                      poll       failed          102ms 2026-04-10T11:30:00Z   Connection refused

3 execution(s) shown.
```

### 6. Replay a previous execution

```bash
# Re-run using the exact same input data
stacker pipe replay <execution-id>
```

### 7. List and manage pipes

```bash
# List all pipes for the deployment
stacker pipe list

# Deactivate a pipe
stacker pipe deactivate <pipe-id>
```

## Concepts

### Templates vs Instances

- **Template** - reusable pipe definition: source app type, target app type, endpoint paths, field mapping. Can be shared publicly.
- **Instance** - activation of a template tied to a deployment or local context:
  - **Remote instance** — bound to a `deployment_hash`, executed via the status agent on the cloud server.
  - **Local instance** — no `deployment_hash`, `is_local=true`, executed via `docker exec` against local containers. Created when `stacker target local` is active.

### Field Mapping

Field mapping uses JSONPath expressions to transform source data into target format:

```json
{
  "email": "$.user_email",
  "first_name": "$.display_name",
  "list_id": "$.config.mailchimp_list"
}
```

The `pipe create` wizard uses 4-layer smart matching:

1. **Exact name** - `email` matches `email`
2. **Case-insensitive** - `Email` matches `email`
3. **Semantic aliases** - `user_email` matches `email`, `display_name` matches `name`
4. **Type-aware suffix** - when sample data is available, `author_id` can match `user_id` (same `_id` suffix + same JSON type)

### Trigger Types

| Type | How it works | Use case |
|------|-------------|----------|
| `webhook` | Agent listens for HTTP events on source endpoint | Real-time sync |
| `poll` | Agent checks source endpoint every N seconds | Periodic data pull |
| `manual` | Only runs when you call `pipe trigger` | Testing, one-off transfers |
| `replay` | Re-runs a previous execution with its original input | Debugging, retry |

### Execution History

Every pipe trigger (manual, webhook, poll, replay) is recorded in `pipe_executions` with:

- Full source data (what was read from source)
- Mapped data (after field transformation)
- Target response (what the target returned)
- Duration, status, error message
- Replay linkage (which execution was replayed)

### Sample Capture

When `--capture-samples` is enabled during scanning, the agent:

1. **OpenAPI specs**: extracts `example` fields from response schemas (no extra HTTP calls)
2. **REST heuristic**: makes a real GET request and captures the JSON response
3. Returns sample data alongside the schema for smarter field matching

## Examples

### WordPress to Mailchimp (new subscriber on registration)

```bash
# 1. Scan both services
stacker pipe scan --app wordpress --capture-samples
stacker pipe scan --app mailchimp --capture-samples

# 2. Create the pipe
stacker pipe create wordpress mailchimp
# Select: POST /wp/v2/users -> POST /3.0/lists/{list_id}/members
# Auto-mapping: email -> $.user_email, name -> $.display_name

# 3. Activate with webhook trigger
stacker pipe activate <pipe-id> --trigger webhook

# 4. Check it's working
stacker pipe history <pipe-id>
```

### CRM to Slack (notify on new contact)

```bash
stacker pipe create crm slack
# Select: POST /api/contacts -> POST /api/chat.postMessage
# Mapping: text -> "New contact: $.name ($.email)"

stacker pipe activate <pipe-id> --trigger webhook
```

### Periodic data sync (poll mode)

```bash
stacker pipe create analytics dashboard
# Select: GET /api/metrics -> POST /api/widgets/update

# Poll every 5 minutes
stacker pipe activate <pipe-id> --trigger poll --poll-interval 300
```

### Debugging a failed pipe

```bash
# See what happened
stacker pipe history <pipe-id> --json | jq '.[0]'

# Replay the failed execution to retry
stacker pipe replay <execution-id>

# Or trigger with custom test data
stacker pipe trigger <pipe-id> --data '{"email":"debug@test.com"}'
```

## REST API Reference

All endpoints require authentication. Pipe instance access is verified through deployment ownership.

### Templates

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/pipes/templates` | Create template |
| GET | `/api/v1/pipes/templates` | List templates (own + public) |
| GET | `/api/v1/pipes/templates/{id}` | Get template |
| DELETE | `/api/v1/pipes/templates/{id}` | Delete template |

### Instances

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/pipes/instances` | Create instance (`deployment_hash` optional for local) |
| GET | `/api/v1/pipes/instances/{deployment_hash}` | List instances for deployment |
| GET | `/api/v1/pipes/instances/local` | List local instances for current user |
| GET | `/api/v1/pipes/instances/detail/{id}` | Get instance |
| PUT | `/api/v1/pipes/instances/{id}/status` | Update status (draft/active/paused/error) |
| POST | `/api/v1/pipes/instances/{id}/deploy` | Promote local instance to remote deployment |
| DELETE | `/api/v1/pipes/instances/{id}` | Delete instance |

### Executions

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/pipes/instances/{id}/executions?limit=20&offset=0` | List executions (paginated) |
| GET | `/api/v1/pipes/executions/{id}` | Get single execution |
| POST | `/api/v1/pipes/executions/{id}/replay` | Replay execution |

### Agent Commands

| Command | Direction | Description |
|---------|-----------|-------------|
| `probe_endpoints` | Server -> Agent | Discover API endpoints for an app, optionally narrowed to a container |
| `activate_pipe` | Server -> Agent | Start webhook listener or poll scheduler |
| `deactivate_pipe` | Server -> Agent | Stop listener/scheduler |
| `trigger_pipe` | Server -> Agent | One-shot pipe execution |

## Data Flow

```
[pipe trigger]
     |
     v
Server enqueues "trigger_pipe" command
     |
     v
Agent picks up command from queue
     |
     v
Agent fetches source data (GET source_endpoint)
     |
     v
Agent applies field_mapping (JSONPath transform)
     |
     v
Agent sends mapped data to target (POST target_endpoint)
     |
     v
Agent reports result: {success, source_data, mapped_data, target_response}
     |
     v
Server persists result in pipe_executions table
Server increments trigger_count (and error_count if failed)
```

## AI-Assisted Matching

Stacker supports two field matching modes when creating pipes:

### Deterministic Mode (default)
The original 4-layer matching algorithm:
1. **Exact match** — identical field names
2. **Case-insensitive** — `Email` matches `email`
3. **Semantic aliases** — `mail` matches `email` (from built-in alias groups)
4. **Type-aware suffix** — `user_email` matches `email` (strips common prefixes)

Always available, works offline, returns confidence=1.0 for all matches.

### AI Mode
Uses the configured LLM provider (OpenAI, Anthropic, or Ollama) for semantic matching:
- Understands field semantics beyond string patterns (e.g., `wp_author_contact` → `subscriber_email`)
- Returns per-field confidence scores (0.0–1.0)
- Suggests field transformations (e.g., `concat($.first_name, ' ', $.last_name)` → `full_name`)
- Proposes which pipe connections make sense between two apps
- Falls back to deterministic matching if AI call fails

### Mode Selection

| Condition | Mode Used |
|-----------|-----------|
| `--no-ai` flag | Deterministic |
| `--ai` flag | AI (error if not configured) |
| `ai.enabled=true` in `stacker.yml` | AI |
| No AI config | Deterministic |
| `--manual` flag | No auto-matching (manual selection only) |

### CLI Flags

```bash
# Use AI matching (requires ai: section in stacker.yml)
stacker pipe create wordpress slack --ai

# Force deterministic matching even if AI is configured
stacker pipe create wordpress slack --no-ai

# Skip auto-matching entirely
stacker pipe create wordpress slack --manual
```

### Configuration

AI matching uses the same `ai:` section in `stacker.yml` as other AI features:

```yaml
ai:
  enabled: true
  provider: openai    # openai | anthropic | ollama
  model: gpt-4o
  api_key: sk-...
  # endpoint: http://localhost:11434  # for Ollama
```

When AI mode is active during pipe creation:
1. Both apps are scanned for endpoints (unchanged)
2. AI suggests which endpoint pairs to connect (ranked by confidence)
3. User selects from AI suggestions or picks manually
4. AI matches fields between selected endpoints with confidence scores
5. User confirms or edits the mapping
6. Matching metadata (mode, model, confidence, transformations) is stored in the template config
