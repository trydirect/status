# DAG Pipes — Part 3: REST API Deep Dive

Automate pipeline creation with curl/scripts. Full API reference, gRPC streaming, and advanced DAG features.

> **Other guides:**
> [Part 1: CLI Guide](./DAG_PIPES_PART1_CLI_GUIDE.md) ·
> [Part 2: Visual Editor (Web UI)](./DAG_PIPES_PART2_WEB_EDITOR.md)

---

## Setup

```bash
# Auth token (all API calls require this)
BASE="http://localhost:8080/api/v1"
AUTH="Authorization: Bearer $(stacker token)"
CT="Content-Type: application/json"
```

---

## Concepts

### Templates vs Instances

- **Template** = reusable pipeline definition (steps + edges). Shareable across deployments.
- **Instance** = a template bound to a specific deployment. Tracks status, trigger counts, execution history.

### DAG Structure

A template contains **steps** (nodes) and **edges** (connections):

```
Steps: [source, transform, condition, target, ...]
Edges: [source→transform, transform→condition, condition→target, ...]
```

Steps are executed **level-by-level** (topological sort). Steps at the same level run in parallel.

### Validation Rules

- At least **one source** step required
- At least **one target** step required
- **No cycles** (it's a Directed Acyclic Graph)

---

## Step Types Reference

### Sources

| Type | Config Fields | Description |
|------|--------------|-------------|
| `source` | `url`, `method`, `headers` | Generic REST source |
| `cdc_source` | `replication_slot`, `publication`, `tables` | PostgreSQL CDC |
| `amqp_source` | `queue`, `exchange`, `routing_key` | RabbitMQ consumer |
| `kafka_source` | `brokers`, `topic`, `group_id` | Kafka consumer |
| `ws_source` | `url` | WebSocket consumer |
| `http_stream_source` | `url`, `event_filter` | Server-Sent Events |
| `grpc_source` | `endpoint`, `pipe_instance_id`, `step_id` | gRPC server-streaming |

### Processing

| Type | Config Fields | Description |
|------|--------------|-------------|
| `transform` | `field_mapping` | JSONPath field mapping |
| `condition` | `field`, `operator`, `value` | Conditional branching |
| `parallel_split` | *(none)* | Fork into parallel branches |
| `parallel_join` | *(none)* | Merge parallel branches |

### Targets

| Type | Config Fields | Description |
|------|--------------|-------------|
| `target` | `url`, `method`, `headers`, `body_template` | Generic REST target |
| `ws_target` | `url` | WebSocket sender |
| `grpc_target` | `endpoint`, `pipe_instance_id`, `step_id` | gRPC unary call |

### Condition Operators

| Operator | Meaning |
|----------|---------|
| `eq` | Equals |
| `ne` | Not equals |
| `gt` | Greater than |
| `lt` | Less than |
| `gte` | Greater or equal |
| `lte` | Less or equal |

---

## Example: Contact Form → Telegram + Slack (scripted)

Complete automation script — creates the pipeline, validates, and runs it.

```bash
#!/bin/bash
# example1-contact-to-telegram-slack.sh
set -euo pipefail

BASE="http://localhost:8080/api/v1"
AUTH="Authorization: Bearer $(stacker token)"
CT="Content-Type: application/json"

# Helper functions
add_step() {
  curl -sf -X POST "$DAG/steps" -H "$AUTH" -H "$CT" -d "$1" | jq -r '.item.id'
}
add_edge() {
  curl -sf -X POST "$DAG/edges" -H "$AUTH" -H "$CT" -d "$1" > /dev/null
}

# --- Create template ---
TEMPLATE=$(curl -sf -X POST "$BASE/pipes/templates" \
  -H "$AUTH" -H "$CT" \
  -d '{"name":"Contact Form → Telegram + Slack"}' \
  | jq -r '.item.id')
echo "Template: $TEMPLATE"
DAG="$BASE/pipes/$TEMPLATE/dag"

# --- Add steps ---
SOURCE=$(add_step '{
  "name": "contact_form",
  "step_type": "source",
  "step_order": 1,
  "config": {"url": "http://website:3000/api/contact", "method": "POST"}
}')

SPLIT=$(add_step '{
  "name": "fan_out",
  "step_type": "parallel_split",
  "step_order": 2,
  "config": {}
}')

TELEGRAM=$(add_step '{
  "name": "telegram_notify",
  "step_type": "target",
  "step_order": 3,
  "config": {
    "url": "https://api.telegram.org/bot<BOT_TOKEN>/sendMessage",
    "method": "POST",
    "headers": {"Content-Type": "application/json"},
    "body_template": {
      "chat_id": "<CHAT_ID>",
      "text": "📬 New contact from {{name}} ({{email}}): {{message}}"
    }
  }
}')

SLACK=$(add_step '{
  "name": "slack_notify",
  "step_type": "target",
  "step_order": 3,
  "config": {
    "url": "https://hooks.slack.com/services/T.../B.../xxx",
    "method": "POST",
    "headers": {"Content-Type": "application/json"},
    "body_template": {
      "text": "📬 *New contact*\n• {{name}} ({{email}})\n• {{message}}"
    }
  }
}')

JOIN=$(add_step '{"name":"merge","step_type":"parallel_join","step_order":4,"config":{}}')

# --- Connect edges ---
add_edge "{\"from_step_id\":\"$SOURCE\",\"to_step_id\":\"$SPLIT\"}"
add_edge "{\"from_step_id\":\"$SPLIT\",\"to_step_id\":\"$TELEGRAM\"}"
add_edge "{\"from_step_id\":\"$SPLIT\",\"to_step_id\":\"$SLACK\"}"
add_edge "{\"from_step_id\":\"$TELEGRAM\",\"to_step_id\":\"$JOIN\"}"
add_edge "{\"from_step_id\":\"$SLACK\",\"to_step_id\":\"$JOIN\"}"

# --- Validate ---
echo "Validating..."
curl -sf -X POST "$DAG/validate" -H "$AUTH" -H "$CT" | jq .

# --- Create instance & execute ---
INSTANCE=$(curl -sf -X POST "$BASE/pipes/instances" \
  -H "$AUTH" -H "$CT" \
  -d "{\"pipe_template_id\":\"$TEMPLATE\",\"deployment_hash\":\"my-deploy\",\"name\":\"Contact notifications\"}" \
  | jq -r '.item.id')

echo "Executing with test data..."
curl -sf -X POST "$BASE/pipes/instances/$INSTANCE/dag/execute" \
  -H "$AUTH" -H "$CT" \
  -d '{
    "input_data": {
      "name": "Alice",
      "email": "alice@example.com",
      "message": "Hello, I need help!"
    }
  }' | jq '.status, .completed_steps, .failed_steps'

echo "✅ Done! Instance: $INSTANCE"
```

---

## Example: CDC → Telegram (scripted)

```bash
#!/bin/bash
# example2-cdc-contact-to-telegram.sh
set -euo pipefail

BASE="http://localhost:8080/api/v1"
AUTH="Authorization: Bearer $(stacker token)"
CT="Content-Type: application/json"

add_step() { curl -sf -X POST "$DAG/steps" -H "$AUTH" -H "$CT" -d "$1" | jq -r '.item.id'; }
add_edge() { curl -sf -X POST "$DAG/edges" -H "$AUTH" -H "$CT" -d "$1" > /dev/null; }

TEMPLATE=$(curl -sf -X POST "$BASE/pipes/templates" \
  -H "$AUTH" -H "$CT" \
  -d '{"name":"CDC Contact → Telegram"}' | jq -r '.item.id')
DAG="$BASE/pipes/$TEMPLATE/dag"

CDC=$(add_step '{
  "name": "pg_contacts",
  "step_type": "cdc_source",
  "step_order": 1,
  "config": {
    "replication_slot": "contacts_pipe_slot",
    "publication": "contact_pub",
    "tables": ["public.contacts"]
  }
}')

TRANSFORM=$(add_step '{
  "name": "format_message",
  "step_type": "transform",
  "step_order": 2,
  "config": {
    "field_mapping": {
      "chat_id": "<YOUR_CHAT_ID>",
      "text": "📬 New contact!\nName: $.after.name\nEmail: $.after.email\nMessage: $.after.message"
    }
  }
}')

TELEGRAM=$(add_step '{
  "name": "telegram",
  "step_type": "target",
  "step_order": 3,
  "config": {
    "url": "https://api.telegram.org/bot<BOT_TOKEN>/sendMessage",
    "method": "POST"
  }
}')

add_edge "{\"from_step_id\":\"$CDC\",\"to_step_id\":\"$TRANSFORM\"}"
add_edge "{\"from_step_id\":\"$TRANSFORM\",\"to_step_id\":\"$TELEGRAM\"}"

curl -sf -X POST "$DAG/validate" -H "$AUTH" -H "$CT" | jq .
echo "✅ Template: $TEMPLATE"
```

Test with simulated CDC event:
```bash
curl -sf -X POST "$BASE/pipes/instances/$INSTANCE/dag/execute" \
  -H "$AUTH" -H "$CT" \
  -d '{
    "input_data": {
      "table_name": "contacts",
      "operation": "INSERT",
      "after": {"id": 42, "name": "Bob", "email": "bob@example.com", "message": "Hi there"},
      "captured_at": "2026-04-16T13:00:00Z"
    }
  }' | jq .
```

---

## REST API Reference

### Templates

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/pipes/templates` | Create template |
| `GET` | `/api/v1/pipes/templates` | List templates |
| `GET` | `/api/v1/pipes/templates/{id}` | Get template |
| `DELETE` | `/api/v1/pipes/templates/{id}` | Delete template |

### DAG Steps

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/pipes/{template_id}/dag/steps` | Add step |
| `GET` | `/api/v1/pipes/{template_id}/dag/steps` | List steps |
| `GET` | `/api/v1/pipes/{template_id}/dag/steps/{step_id}` | Get step |
| `PUT` | `/api/v1/pipes/{template_id}/dag/steps/{step_id}` | Update step |
| `DELETE` | `/api/v1/pipes/{template_id}/dag/steps/{step_id}` | Delete step |

### DAG Edges

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/pipes/{template_id}/dag/edges` | Add edge |
| `GET` | `/api/v1/pipes/{template_id}/dag/edges` | List edges |
| `DELETE` | `/api/v1/pipes/{template_id}/dag/edges/{edge_id}` | Delete edge |

### DAG Validation & Execution

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/pipes/{template_id}/dag/validate` | Validate DAG |
| `POST` | `/api/v1/pipes/instances/{instance_id}/dag/execute` | Execute DAG |
| `GET` | `/api/v1/pipes/{template_id}/dag/executions/{exec_id}/steps` | Step execution details |

### Instances

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/pipes/instances` | Create instance |
| `GET` | `/api/v1/pipes/instances/{deployment_hash}` | List by deployment |
| `GET` | `/api/v1/pipes/instances/local` | List local instances |
| `GET` | `/api/v1/pipes/instances/detail/{id}` | Get instance |
| `PUT` | `/api/v1/pipes/instances/{id}/status` | Update status |
| `POST` | `/api/v1/pipes/instances/{id}/deploy` | Promote local → remote |
| `DELETE` | `/api/v1/pipes/instances/{id}` | Delete instance |

### Executions

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/pipes/instances/{id}/executions` | List executions |
| `GET` | `/api/v1/pipes/executions/{id}` | Get execution |
| `POST` | `/api/v1/pipes/executions/{id}/replay` | Replay execution |

### Streaming

| Protocol | Path | Description |
|----------|------|-------------|
| WebSocket | `/api/v1/pipes/instances/{id}/stream` | Live execution events |

### Resilience (Circuit Breaker + Dead Letter Queue)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/pipes/*/dlq` | List dead-letter items |
| `POST` | `/api/v1/pipes/*/dlq/{id}/retry` | Retry failed item |
| `POST` | `/api/v1/pipes/*/dlq/{id}/discard` | Discard failed item |
| `GET` | `/api/v1/pipes/*/circuit-breaker` | Get circuit breaker state |
| `PUT` | `/api/v1/pipes/*/circuit-breaker` | Configure thresholds |
| `POST` | `/api/v1/pipes/*/circuit-breaker/reset` | Reset circuit breaker |

---

## gRPC Streaming

For high-throughput or real-time pipelines, use gRPC steps instead of REST.

### Protocol (proto/pipe.proto)

```protobuf
service PipeService {
  // Send data to a target (unary)
  rpc Send(PipeMessage) returns (PipeResponse);

  // Subscribe to a source (server-streaming)
  rpc Subscribe(SubscribeRequest) returns (stream PipeMessage);
}

message PipeMessage {
  string pipe_instance_id = 1;
  string step_id = 2;
  google.protobuf.Struct payload = 3;  // Arbitrary JSON
  int64 timestamp_ms = 4;
}

message PipeResponse {
  bool success = 1;
  string message = 2;
}

message SubscribeRequest {
  string pipe_instance_id = 1;
  string step_id = 2;
  map<string, string> filters = 3;
}
```

### Using gRPC in a DAG

```bash
# gRPC source step — subscribes to server-streaming RPC
add_step '{
  "name": "live_feed",
  "step_type": "grpc_source",
  "config": {
    "endpoint": "http://grpc-service:50051",
    "pipe_instance_id": "...",
    "step_id": "..."
  }
}'

# gRPC target step — sends via unary RPC
add_step '{
  "name": "push_to_grpc",
  "step_type": "grpc_target",
  "config": {
    "endpoint": "http://grpc-service:50051",
    "pipe_instance_id": "...",
    "step_id": "..."
  }
}'
```

---

## API Response Formats

### Single item (POST, GET by ID)
```json
{"item": {"id": "uuid", "name": "...", ...}}
```

### List (GET collection)
```json
{"list": [{"id": "uuid", ...}, {"id": "uuid", ...}]}
```

### DELETE
Returns `204 No Content` (empty body).

### Validation
```json
{"valid": true, "total_steps": 5, "execution_levels": 3, "sources": ["source"], "targets": ["target"]}
```

### Execution result
```json
{
  "execution_id": "uuid",
  "status": "completed",
  "total_steps": 5,
  "completed_steps": 5,
  "failed_steps": 0,
  "skipped_steps": 0,
  "execution_order": ["step1", "step2", "..."],
  "step_results": [{"step_id": "...", "status": "completed", "output_data": {...}}, ...]
}
```

---

## Troubleshooting

### "No source step found"
DAG needs at least one source. Valid types: `source`, `cdc_source`, `amqp_source`, `kafka_source`, `ws_source`, `http_stream_source`, `grpc_source`.

### "No target step found"
Add a `target`, `ws_target`, or `grpc_target` step.

### "Cycle detected"
Edges form a loop. Remove the circular edge.

### 401 Unauthorized
Run `stacker login` or check your `Authorization: Bearer <token>` header.

### Step execution failed
```bash
curl -s "$BASE/pipes/$TEMPLATE/dag/executions/$EXEC_ID/steps" \
  -H "$AUTH" | jq '.[] | select(.status == "failed") | {name: .name, error: .error}'
```

### CDC not receiving events
1. PostgreSQL: `wal_level = logical` in postgresql.conf
2. Replication slot exists: `SELECT * FROM pg_replication_slots;`
3. Publication exists: `SELECT * FROM pg_publication_tables;`

### AMQP not consuming
1. RabbitMQ accessible? Check Management UI (port 15672)
2. Queue exists? Exchange and routing key match publisher?

### Kafka not subscribing
1. Brokers reachable? `kafkacat -b localhost:9092 -L`
2. Topic exists? `kafka-topics.sh --list --bootstrap-server localhost:9092`
3. `group_id` conflicts with another consumer?
