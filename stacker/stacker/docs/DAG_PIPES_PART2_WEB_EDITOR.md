# DAG Pipes — Part 2: Visual Editor (Web UI)

Build data pipelines with drag-and-drop — no terminal needed.

> **Other guides:**
> [Part 1: CLI Guide](./DAG_PIPES_PART1_CLI_GUIDE.md) ·
> [Part 3: REST API Deep Dive](./DAG_PIPES_PART3_API_DEEP_DIVE.md)

---

## Open the Editor

```
http://localhost:8080/editor
```

> **Demo Mode**: The editor works without login for local experimentation. Changes exist only in the browser. Click **"Sign Up / Login"** to save pipelines to the server.

---

## Quick Start: Contact Form → Telegram + Slack

Let's build Example 1 from the CLI guide — visually.

### 1. Start with a template (optional)

Click **"Use Template"** and pick one:

| Template | What you get |
|----------|-------------|
| **ETL Pipeline** | source → transform → target (simplest) |
| **Webhook Router** | source → condition → two targets |
| **CDC Replicator** | CDC source → transform → target |

Or start from scratch (next step).

### 2. Drag steps from the palette

The **left sidebar** has all available step types organized by category:

**Sources** (where data comes from):
| Step | Icon | Use for |
|------|------|---------|
| Source | 📥 | REST API / webhook |
| CDC Source | 🔄 | PostgreSQL table changes |
| AMQP Source | 🐰 | RabbitMQ messages |
| Kafka Source | 📨 | Kafka topics |
| WebSocket Source | 🔌 | WebSocket streams |
| HTTP Stream | 🌊 | Server-Sent Events |
| gRPC Source | ⚡ | gRPC server-streaming |

**Processing** (transform and route):
| Step | Icon | Use for |
|------|------|---------|
| Transform | 🔀 | Map/rename fields |
| Condition | ❓ | Filter (if/else branching) |
| Parallel Split | ⑃ | Fan-out to multiple targets |
| Parallel Join | ⑂ | Merge parallel branches |

**Targets** (where data goes):
| Step | Icon | Use for |
|------|------|---------|
| Target | 📤 | REST API / webhook |
| WebSocket Target | 🔌 | Send via WebSocket |
| gRPC Target | ⚡ | Send via gRPC |

For our example, drag these onto the canvas:

1. **Source** 📥 — the contact form
2. **Parallel Split** ⑃ — fan out to both targets
3. **Target** 📤 — Telegram
4. **Target** 📤 — Slack
5. **Parallel Join** ⑂ — merge results

### 3. Connect the steps

Click the **output handle** (small circle on the right side of a node) and drag to the **input handle** (left side of the next node):

```
Source ──→ Parallel Split ──→ Target (Telegram)
                           ──→ Target (Slack)
           Target (Telegram) ──→ Parallel Join
           Target (Slack)    ──→ Parallel Join
```

### 4. Configure each step

**Click any node** to open the **config panel** on the right side.

#### Source: contact_form
- **Name**: `contact_form`
- **URL**: `http://website:3000/api/contact`
- **Method**: `POST`

#### Target: telegram
- **Name**: `telegram_notify`
- **URL**: `https://api.telegram.org/bot<YOUR_TOKEN>/sendMessage`
- **Method**: `POST`

#### Target: slack
- **Name**: `slack_notify`
- **URL**: `https://hooks.slack.com/services/T.../B.../xxx`
- **Method**: `POST`

> **Advanced config**: Toggle **"Advanced JSON"** at the bottom of the config panel to edit the raw JSON config directly.

### 5. Validate

Click the **"Validate"** button in the toolbar.

- ✅ **Green toast** = DAG is valid
- ❌ **Red toast** = something's wrong (missing source, missing target, cycle detected, etc.)

### 6. Execute

Click **"Execute"** to run the pipeline with test data.

---

## Building Example 2: CDC → Telegram

1. Drag **CDC Source** 🔄 onto the canvas
2. Click it and configure:
   - **Replication Slot**: `contacts_pipe_slot`
   - **Publication**: `contact_pub`
   - **Tables**: `public.contacts`
3. Drag **Transform** 🔀 → configure field mappings
4. Drag **Target** 📤 → set Telegram API URL
5. Connect: CDC Source → Transform → Target
6. Click **Validate** → **Execute**

---

## Building Example 3: Form → Email + Slack

1. Drag **Source** 📥 (form webhook)
2. Drag **Parallel Split** ⑃
3. Drag two **Target** 📤 nodes (email service + Slack)
4. Drag **Parallel Join** ⑂
5. Connect: Source → Split → both Targets → Join
6. Configure each target with its URL
7. **Validate** → **Execute**

---

## Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `Delete` / `Backspace` | Delete selected edge or node |
| Drag from handle | Create a connection |
| Click a node | Open config panel |
| Scroll wheel | Zoom in / out |
| Click + drag canvas | Pan around |

---

## Tips

- **Delete a connection**: Click on the edge (it highlights), then press `Delete` or `Backspace`
- **Delete a step**: Click the node, then press `Delete`
- **Move a step**: Click and drag it to a new position
- **Zoom to fit**: Scroll out or use the minimap (bottom-right)
- **Switch to JSON editing**: Toggle "Advanced JSON" in the config panel for full control
- **Start from a template**: Much faster than building from scratch — customize from there

---

## Demo Mode vs Authenticated

| Feature | Demo Mode | Logged In |
|---------|-----------|-----------|
| Build pipelines | ✅ | ✅ |
| Drag & drop | ✅ | ✅ |
| Validate | ❌ (skipped) | ✅ |
| Execute | ❌ (skipped) | ✅ |
| Save to server | ❌ | ✅ |
| Load existing pipes | ❌ | ✅ |

Demo mode is great for learning the interface. Sign in to actually run pipelines.

> **💡 Local mode (CLI)**: For local experimentation with _real_ execution, use `stacker target local` and the CLI pipe commands (see [Part 1: Local Mode](./DAG_PIPES_PART1_CLI_GUIDE.md#local-mode-experimental)). Local pipes can later be promoted to remote via `stacker pipe deploy`.

---

## What's Next?

- **[Part 1: CLI Guide](./DAG_PIPES_PART1_CLI_GUIDE.md)** — Same examples using terminal commands
- **[Part 3: REST API Deep Dive](./DAG_PIPES_PART3_API_DEEP_DIVE.md)** — Full API reference, automation scripts, gRPC streaming
