<div align="center">

<a href="https://discord.gg/mNhsa8VdYX"><img alt="Discord" src="https://img.shields.io/discord/578119430391988232?label=discord"></a>
<img alt="Version" src="https://img.shields.io/badge/version-0.2.8-blue">
<img alt="License" src="https://img.shields.io/badge/license-MIT-green">

<br><br>
<img width="300" src="https://repository-images.githubusercontent.com/448846514/3468f301-0ba6-4b61-9bf1-164c06c06b08">

**Build, deploy, and manage containerised applications with a single config file.**

</div>

Stacker is a platform for turning any project into a deployable Docker stack. Add a `stacker.yml` to your repo, and Stacker generates Dockerfiles, docker-compose definitions, reverse-proxy configs, and deploys locally or to cloud providers — optionally with AI assistance.

**v0.2.8 highlights:** remote Vault-backed secrets now work for deployable
service/app targets from `stacker.yml` and supported Compose services, paused or
failed cloud/server installs retain discovered IP addresses, cloud-provider
firewalls can be managed without SSH, and MCP now exposes remote service secret
tools.


## Quick Start

### Install the CLI

```bash
curl -fsSL https://raw.githubusercontent.com/trydirect/stacker/main/install.sh | bash
```

### Create & deploy a project

```bash
cd my-project
stacker init              # auto-detects project type, generates stacker.yml
stacker deploy            # builds and runs locally via docker compose
stacker status            # check running containers
```

### AI-powered init (optional)

Stacker can scan your project files and use an LLM to generate a tailored `stacker.yml`:

```bash
# Local AI with Ollama (free, private, default)
stacker init --with-ai

# OpenAI
stacker init --with-ai --ai-provider openai --ai-api-key sk-...

# Anthropic (key from env)
export ANTHROPIC_API_KEY=sk-ant-...
stacker init --with-ai --ai-provider anthropic
```

If the AI provider is unreachable, Stacker falls back to template-based generation automatically.

When the project looks like a simple HTML or Next.js website and the configured
Ollama model is `qwen2.5-code` or `qwen2.5-coder`, `stacker init --with-ai`
can also bootstrap a website deployment scenario. The bootstrap seeds values
from the generated `stacker.yml`, asks only for the missing deploy inputs, and
saves scenario state under `.stacker/scenarios/qwen2.5-code/website-deploy/`
for later continuation with `stacker ai`.

### AI deployment workflows

For the canonical AI/MCP deployment flow — inspect state, explain topology or
env provenance, preview a plan, apply it safely, and recover with events or
rollback — see [AI deployment workflows](docs/AI_DEPLOYMENT_WORKFLOWS.md).

For the qwen-specific website scenario flow, including `--scenario` and `--step`
continuation, see the same guide.

---

## `stacker.yml` example

```yaml
name: my-app
app:
  type: node
  path: ./src
  ports:
    - "8080:3000"
  environment:
    NODE_ENV: production

services:
  - name: postgres
    image: postgres:16
    environment:
      POSTGRES_DB: myapp
      POSTGRES_PASSWORD: ${DB_PASSWORD}

proxy:
  type: nginx
  auto_detect: true
  domains:
    - domain: app.example.com
      ssl: auto
      upstream: app:3000

deploy:
  target: local    # or: cloud, server

ai:
  enabled: true
  provider: ollama
  model: llama3

monitoring:
  status_panel: true
  healthcheck:
    endpoint: /health
    interval: 30s
```

Full schema reference: [docs/STACKER_YML_REFERENCE.md](docs/STACKER_YML_REFERENCE.md)

---


### Three components

| Component | What it does | Binary |
|-----------|-------------|--------|
| **Stacker CLI** | Developer tool — init, deploy, monitor from the terminal | `stacker-cli` |
| **Stacker Server** | REST API + Stack Builder UI + deployment orchestration + MCP Server | `server` |
| **Status Panel Agent** | Deployed alongside your app on the target server — executes commands, streams logs, reports health | *(separate repo)* |

```
┌──────────────┐         ┌──────────────────┐         ┌─────────────────────┐
│  Stacker CLI │────────►│  Stacker Server  │────────►│  Status Panel Agent │
│              │  REST   │                  │  queue  │  (on target server) │
│  stacker.yml │  API    │  Stack Builder UI│  pull   │                     │
│  init/deploy │         │  85+ MCP tools   │◄────────│  health / logs /    │
│  status/logs │         │  Vault · AMQP    │  HMAC   │  restart / exec /   │
└──────────────┘         └──────────────────┘         │  deploy_app / proxy │
                                │                     └─────────────────────┘
                                ▼
                    Terraform + Ansible ──► Cloud
                    (Hetzner, DO, AWS, Linode)
```

---




## 1. Stacker CLI

The end-user tool. No server required for local deploys.

### Commands

| Command | Description |
|---------|-------------|
| `stacker init` | Detect project type, generate `stacker.yml` + `.stacker/` artifacts |
| `stacker deploy` | Build & deploy the stack (local, cloud, or server). Cloud deploys also install a local SSH backup key when possible. `--runtime kata\|runc` selects container runtime |
| `stacker status` | Show running containers and health |
| `stacker logs` | View container logs (`--follow`, `--service`, `--tail`) |
| `stacker secrets` | Manage local `.env` secrets or remote Vault-backed `service` / `server` secrets |
| `stacker list deployments` | List deployments on the Stacker server |
| `stacker destroy` | Tear down the deployed stack |
| `stacker config validate` | Validate `stacker.yml` syntax |
| `stacker config show` | Show resolved configuration |
| `stacker config example` | Print a full commented reference |
| `stacker config setup cloud` | Guided cloud deployment setup |
| `stacker config setup ai` | Configure AI provider, endpoint, model, and tasks |
| `stacker ai ask "question"` | Ask the AI about your stack |
| `stacker proxy add` | Add a reverse-proxy domain entry |
| `stacker proxy detect` | Auto-detect existing reverse-proxy containers |
| `stacker cloud firewall add` | Open cloud-provider firewall ports without SSH, for example `--public-ports 8000/tcp` on Hetzner |
| `stacker cloud firewall remove` | Remove Stacker-managed cloud-provider firewall rules |
| `stacker cloud firewall list` | List cloud-provider firewall rules for a server |
| `stacker ssh-key generate` | Generate a new SSH key pair for a server (Vault-backed) |
| `stacker ssh-key show` | Display the public SSH key for a server |
| `stacker ssh-key upload` | Upload an existing SSH key pair for a server |
| `stacker ssh-key inject` | Repair Vault-key trust by using an already-working private key to update `authorized_keys` |
| `stacker service add` | Add a service from the template catalog to `stacker.yml` |
| `stacker service list` | List available service templates (20+ built-in) |
| `stacker agent health` | Check Status Panel agent connectivity and health |
| `stacker agent status` | Display agent snapshot — containers, versions, uptime |
| `stacker agent logs <app>` | Retrieve container logs from the remote agent |
| `stacker agent restart <app>` | Restart a container via the agent |
| `stacker agent deploy-app` | Deploy or update an app container on the target server. `--runtime kata\|runc` selects container runtime; `--env <name>` selects the deploy environment/profile |
| `stacker agent remove-app` | Remove an app container (with optional volume/image cleanup) |
| `stacker agent configure-proxy` | Configure Nginx Proxy Manager via the agent; use `--no-ssl` for plain HTTP hosts (credentials are resolved from Vault and are auto-seeded for managed Status Panel + NPM deploys) |
| `stacker agent configure-firewall` | Configure guest OS firewall rules via the Status Panel agent; use `stacker cloud firewall` for provider firewalls |
| `stacker agent history` | Show recent command execution history |
| `stacker agent exec` | Execute a raw agent command with JSON parameters |
| `stacker pipe scan` | Discover local endpoints/resources from running containers (when target is `local`) |
| `stacker pipe scan --containers [filter]` | Discover local endpoints/resources for matching containers |
| `stacker pipe scan --app <app>` | Probe a remote app for API endpoints |
| `stacker pipe create <src> <tgt>` | Create a data pipe between two containers (interactive) |
| `stacker pipe list` | List pipe instances for the current deployment |
| `stacker pipe activate <id>` | Activate a pipe (start listening for triggers) |
| `stacker pipe deactivate <id>` | Pause an active pipe |
| `stacker pipe trigger <id>` | One-shot pipe execution with optional input data |
| `stacker pipe deploy <id>` | Promote a local pipe to a remote deployment |
| `stacker pipe history <id>` | View execution history for a pipe |
| `stacker pipe replay <exec-id>` | Re-run a previous pipe execution |
| `stacker target [local\|cloud\|server]` | Switch deployment target mode |
| `stacker env [local\|dev\|prod]` | Show or persist the active deploy environment/profile used by app-only updates |
| `stacker submit` | Package current stack and submit to marketplace for review |
| `stacker marketplace status` | Check submission status for your marketplace templates |
| `stacker marketplace logs <name>` | Show review comments and history for a submission |
| `stacker login` | Authenticate with the TryDirect platform |
| `stacker update` | Check for updates and self-update |

### Deploy targets

```bash
stacker deploy --target local     # docker compose up (default)
stacker deploy --target cloud     # Terraform + Ansible → cloud provider
stacker deploy --target server    # deploy to existing server via SSH
stacker deploy --dry-run          # preview generated files without executing
```

After a successful cloud deploy, Stacker creates or reuses a local backup key at
`~/.config/stacker/ssh/server-<id>_ed25519` (or under `$XDG_CONFIG_HOME`) and
authorizes its public key on the server when possible. The CLI prints a normal
`ssh -i ...` command, while the Vault private key remains server-side.

When a cloud/server deploy includes `deploy.registry` credentials (or the
equivalent `STACKER_DOCKER_*` environment variables), Stacker stores that
registry auth securely and reuses it for later Status-managed image refreshes
such as `stacker agent deploy-app`. This keeps private-image redeploys working
without depending on host-level `docker login` state or mounting `/root/.docker`
into the agent container.

### Secrets workflow

```bash
# Local project .env secret
stacker secrets set DB_PASSWORD=supersecret

# Discover valid remote deployable service/app targets first
stacker secrets apps

# Remote service secret used at render/deploy time for one target
stacker secrets set S3_SECRET_KEY \
  --scope service \
  --service uploader \
  --body supersecret

# Remote server secret for future host-level consumers
stacker secrets set NPM_TOKEN \
  --scope server \
  --server-id 42 \
  --body-file .npm-token

# Remote reads are metadata-only in v1
stacker secrets list --scope service --service uploader --json
stacker secrets get S3_SECRET_KEY --scope service --service uploader --json

# Push stored remote secrets into the target's runtime env
stacker secrets push --service uploader
stacker secrets push --service uploader --env prod
# Aliases: stacker secrets deploy --service uploader
#          stacker secrets apply --service uploader

```

- Local mode remains the default and reads/writes the project `.env` file.
- Remote mode is enabled only with `--scope service` or `--scope server`.
- Service-scoped remote commands default `--project` from `stacker.yml -> project.identity`; `--project` still overrides it explicitly.
- Service-scoped secrets target deployable service/app codes listed by `stacker secrets apps`, including registered `stacker.yml` services and supported image-backed Compose services after a deploy/update sync.
- Service-scoped secrets are merged only into the matching rendered service/app env at deploy time.
- `stacker secrets push --service <target>` applies stored service secrets to the remote runtime env without changing secret values. Use `--env <name>` for a one-off environment selection, or `stacker env <name>` to persist the active environment/profile for future app-only updates. Use `--force` only when the remote env drift check reports an out-of-band change.
- Remote `get` and `list` do **not** return plaintext values in v1.
- MCP env inspection now exposes explicit secure metadata for Vault-backed
  variables: `get_app_env_vars` keeps the redacted
  `environment_variables` object for compatibility and also returns
  `environment_entries[]` with `secure`, `redacted`, and `source` fields.

Remote deploys render runtime env into one canonical host file:
`/home/trydirect/project/.env`. Generated compose uses `env_file: .env`, so the
path is relative to the deployed compose file. To inspect paths and contributing
layers without exposing values, run:

```bash
stacker config show --resolved
```

For app-only updates, `stacker agent deploy-app <target>` resolves the deploy
environment from `--env`, then `.stacker/active-env`, then `stacker.yml`. If
`<target>/docker/<env>/compose.yml` exists, Stacker uses the app-local service
definition for that target but merges it into the full project-level compose
file before sending it to the agent. This prevents app-only updates from
replacing the remote stack compose with a single-service compose file. Any
app-local `.env` referenced by that compose file is uploaded in the config
bundle, and Stacker appends the Vault-rendered service secrets for the same
target to that file before the agent writes it on the server. Repeated app-only
updates replace the prior `# stacker-render ...` block in that file instead of
stacking duplicate rendered secret sections.

### Marketplace workflow (for stack developers)

```bash
stacker deploy --target local           # 1. test locally
stacker deploy --target server          # 2. test on remote server
stacker submit                          # 3. submit for marketplace review
stacker marketplace status              # 4. check review status
# Stack is auto-published once approved by the review team
```

### Marketplace install (for buyers)

```bash
# Option A: Deploy from your laptop to a remote server
stacker deploy my-stack --target server --host 1.2.3.4

# Option B: Run directly on the target server (one-liner)
curl -sL https://marketplace.try.direct/<purchase-token>/install.sh | sh
```

### Key features

- **Auto-detection** — identifies Node, Python, Rust, Go, PHP, static sites from project files
- **Dockerfile generation** — produces optimised multi-stage Dockerfiles per app type
- **Docker Compose generation** — wires app + services + proxy + monitoring
- **Remote service secrets** — Vault-backed service/app target secrets are metadata-only when read and isolated to the selected service
- **AI-assisted config** — scans project, calls LLM to generate tailored `stacker.yml`
- **AI troubleshooting** — on deploy failure, suggests fixes via AI or deterministic fallback hints
- **Service catalog** — 20+ built-in service templates (Postgres, Redis, WordPress, etc.) — add with `stacker service add`
- **AI service addition** — ask `stacker ai ask --write "add wordpress"` and the AI uses the template catalog
- **Agent control** — `stacker agent` subcommand to manage remote Status Panel agents (health, logs, restart, deploy, proxy) with `--json` output
- **SSH key management** — generate, view, upload, and repair server SSH keys
  (Vault-backed), with automatic local backup SSH access after cloud deploy
- **Reverse proxy** — auto-detects Nginx / Nginx Proxy Manager, configures domains + SSL
- **Cloud deployment** — Hetzner, DigitalOcean, AWS, Linode, with provider firewall operations and paused/failed install IP retention
- **MCP Server** — 85+ tools, including deployment, agent control, config, proxy, firewall, and remote service secret management
- **Marketplace** — submit stacks for review, auto-publish on approval, check status from CLI
- **Buyer install** — purchase tokens, one-liner install scripts, agent self-registration

---

## 2. Stacker Server

The backend platform powering the Stack Builder UI, REST API, deployment orchestration, and MCP server for AI agents.

### Setup

```bash
cp configuration.yaml.dist configuration.yaml   # edit database, vault, AMQP settings
cp access_control.conf.dist access_control.conf
export DATABASE_URL=postgres://postgres:postgres@localhost:5432/stacker
sqlx migrate run
cargo run --bin server                           # http://127.0.0.1:8000
```

### Key API endpoints

| Endpoint | Description |
|----------|-------------|
| `POST /project` | Create a project from a stack definition |
| `POST /{id}/deploy/{cloud_id}` | Deploy to a cloud provider |
| `GET /project/{id}/apps` | List apps in a project |
| `DELETE /project/{id}/apps/{code}` | Remove an app from a project |
| `PUT /project/{id}/apps/{code}/env` | Update app environment variables |
| `GET /project/{id}/apps/{code}/secrets` | List service-scoped secret metadata for an app |
| `PUT /project/{id}/apps/{code}/secrets/{name}` | Create or update a Vault-backed service secret |
| `PUT /project/{id}/apps/{code}/ports` | Update port mappings |
| `PUT /project/{id}/apps/{code}/domain` | Update domain / SSL settings |
| `GET /server/{id}/secrets` | List server-scoped secret metadata |
| `PUT /server/{id}/secrets/{name}` | Create or update a Vault-backed server secret |
| `POST /api/v1/commands` | Enqueue a command for the Status Panel agent |
| `POST /api/templates` | Create or update a marketplace template (creator) |
| `POST /api/templates/{id}/submit` | Submit template for marketplace review |
| `GET /api/templates/mine` | List current user's template submissions |
| `GET /api/v1/marketplace/install/{token}` | Generate install.sh script for buyers |
| `GET /api/v1/marketplace/download/{token}` | Download stack archive (purchase token validated) |
| `POST /api/v1/marketplace/agents/register` | Agent self-registration after install |
| `POST /api/v1/pipes/templates` | Create a reusable pipe template (source→target mapping) |
| `GET /api/v1/pipes/templates` | List pipe templates (with optional filters) |
| `POST /api/v1/pipes/instances` | Create a pipe instance for a deployment |
| `GET /api/v1/pipes/instances` | List pipe instances by deployment hash |
| `PUT /api/v1/pipes/instances/{id}/status` | Update pipe instance status (active/paused) |

### MCP Server

Stacker exposes **52+ Model Context Protocol tools** over WebSocket, enabling AI agents (Claude, GPT, etc.) to manage infrastructure programmatically:

- Project & deployment management
- Container operations (start, stop, restart, exec)
- Log analysis & error summaries
- Vault config read/write
- Proxy configuration
- App environment & port management
- Server resource monitoring
- Docker Compose generation & preview
- Agent control (deploy app, remove app, configure proxy, get status)
- Firewall management (iptables rules via Status Panel or SSH)

### Key integrations

- **HashiCorp Vault** — secrets and config storage, synced to deployments
- **RabbitMQ** — deployment status updates, event-driven orchestration
- **TryDirect User Service** — OAuth, marketplace templates, payment validation
- **Marketplace** — publish and deploy community stacks

---


## 3. Status Panel Agent

A lightweight agent deployed alongside your application on the target server. It runs as a Docker container and communicates with Stacker Server using a **pull-only architecture** — the agent polls for commands, Stacker never dials out.

### How it works

```
1. UI/API creates a command       →  POST /api/v1/commands
2. Command stored in DB queue     →  commands + command_queue tables
3. Agent polls for work           →  GET /api/v1/agent/commands/wait/{hash}
4. Agent executes locally         →  Docker API on the host
5. Agent reports result           →  POST /api/v1/agent/commands/report
```

All agent requests are **HMAC-signed** (`X-Agent-Signature` header) using a token stored in Vault.

### Supported commands

| Command | Description |
|---------|-------------|
| `health` | Check container health status (single or all) |
| `logs` | Fetch container logs (stdout/stderr, with limits) |
| `restart` | Restart a container |
| `deploy_app` | Deploy or update an app container |
| `remove_app` | Remove an app container |
| `configure_proxy` | Create/update/delete reverse-proxy entries |
| `configure_firewall` | Configure iptables firewall rules (add/remove/list/flush) |
| `stacker.exec` | Execute a command inside a running container (with security blocklist) |
| `stacker.server_resources` | Collect server resource metrics (CPU, memory, disk, network) |
| `apply_config` | Pull config from Vault and apply to a running container |
| `probe_endpoints` | Discover API endpoints on containers (OpenAPI, REST, HTML forms, GraphQL) |
| `activate_pipe` | Activate a pipe instance — start polling/webhook triggers |
| `deactivate_pipe` | Deactivate a running pipe instance |
| `trigger_pipe` | One-shot pipe execution: fetch source data → map fields → post to target |

### Agent registration

```bash
# Agent self-registers on first boot (no auth required)
POST /api/v1/agent/register
  { "deployment_hash": "abc123", "capabilities": [...], "system_info": {...} }
  → { "agent_id": "...", "agent_token": "..." }
```

### Token rotation

```bash
cargo run --bin console -- Agent rotate-token \
  --deployment-hash <hash> \
  --new-token <NEW_TOKEN>
```

---

## Database migrations

```bash
sqlx migrate run      # apply
sqlx migrate revert   # rollback
```

## Testing

```bash
cargo test                         # all tests (772+ unit, 69 security integration)
cargo test user_service_client     # User Service connector
cargo test marketplace_webhook     # Marketplace webhook flows
cargo test deployment_validator    # Deployment validation
cargo test --test security_cli     # CLI endpoint IDOR security tests
```

---

## Kata Containers (Hardware Isolation)

Stacker supports [Kata Containers](https://katacontainers.io/) as an alternative runtime, providing VM-level isolation for each container using hardware virtualization (KVM).

**KVM requirement** — Kata needs nested or bare-metal KVM. Hetzner dedicated-CPU servers (CCX line) expose `/dev/kvm` out of the box, making them an ideal deployment target.

```bash
stacker deploy --runtime kata          # deploy the current stack with Kata isolation
stacker agent deploy-app --runtime kata  # deploy a single app container with Kata
```

See [docs/kata/](docs/kata/README.md) for the full setup guide, network constraints, and monitoring reference. Automated provisioning (Ansible + Terraform for Hetzner CCX) is available via the TFA infrastructure toolkit.

---

## Documentation

- [stacker.yml reference](docs/STACKER_YML_REFERENCE.md) — full configuration schema
- [CLI implementation plan](docs/STACKER_CLI_PLAN.md) — architecture and design decisions
- [Changelog](CHANGELOG.md) — release history
- [Kata Containers guide](docs/kata/README.md) — hardware-isolated containers with KVM

---

## License

[MIT](LICENSE)
