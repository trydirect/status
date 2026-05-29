# Stacker — Build, Deploy & Manage Containerised Apps

[![Discord](https://img.shields.io/discord/578119430391988232?label=discord&logo=discord&color=5865F2)](https://discord.gg/mNhsa8VdYX)
[![Version](https://img.shields.io/badge/version-0.2.8-blue)](https://github.com/trydirect/stacker/releases)
[![License](https://img.shields.io/badge/license-MIT-green)](https://github.com/trydirect/stacker/blob/main/LICENSE)
[![GitHub](https://img.shields.io/badge/source-GitHub-181717?logo=github)](https://github.com/trydirect/stacker)

**Stacker** is an open-source platform that turns any project into a deployable Docker stack using a single `stacker.yml` config file. It auto-generates Dockerfiles, docker-compose definitions, reverse-proxy configs, and deploys locally or to cloud providers — optionally with AI assistance.

---

## Architecture

```
┌──────────────┐         ┌──────────────────┐         ┌─────────────────────┐
│  Stacker CLI │────────▶│  Stacker Server  │────────▶│  Status Panel Agent │
│              │  REST   │                  │  queue  │  (on target server) │
│  stacker.yml │  API    │  Stack Builder UI│  pull   │                     │
│  init/deploy │         │  85+ MCP tools   │◀────────│  health / logs /    │
│  status/logs │         │  Vault · AMQP    │  HMAC   │  restart / exec /   │
└──────────────┘         └──────────────────┘         │  deploy_app / proxy │
                                │                     └─────────────────────┘
                                ▼
                    Terraform + Ansible ──▶ Cloud
                    (Hetzner, DO, AWS, Linode)
```

| Component | Description |
|-----------|-------------|
| **Stacker CLI** | Developer tool — init, deploy, monitor from the terminal |
| **Stacker Server** | REST API + Stack Builder UI + deployment orchestration + MCP Server (**this image**) |
| **Status Panel Agent** | Deployed on the target server — executes commands, streams logs, reports health |

---

## Quick Start

### Run the Stacker Server

```bash
docker pull trydirect/stacker:latest

docker run -d \
  --name stacker \
  -p 8000:8000 \
  -e DATABASE_URL=postgres://postgres:postgres@db:5432/stacker \
  -e RUST_LOG=info \
  trydirect/stacker:latest
```

### Using Docker Compose (recommended)

```yaml
version: "3.8"

services:
  stacker:
    image: trydirect/stacker:latest
    container_name: stacker
    restart: always
    ports:
      - "8000:8000"
    volumes:
      - ./files:/app/files
      - ./configuration.yaml:/app/configuration.yaml
      - ./access_control.conf:/app/access_control.conf
      - ./migrations:/app/migrations
    environment:
      - RUST_LOG=info
    depends_on:
      db:
        condition: service_healthy

  db:
    image: postgres:16
    restart: always
    environment:
      POSTGRES_DB: stacker
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: postgres
    volumes:
      - stackerdb:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 5s
      timeout: 5s
      retries: 5

  redis:
    image: redis:7
    restart: always

  rabbitmq:
    image: rabbitmq:3-management
    restart: always

volumes:
  stackerdb:
```

### Install the CLI

```bash
curl -fsSL https://raw.githubusercontent.com/trydirect/stacker/main/install.sh | bash
```

```bash
cd my-project
stacker init              # auto-detects project type, generates stacker.yml
stacker deploy            # builds and runs locally via docker compose
stacker status            # check running containers
```

---

## What's Inside This Image

The `trydirect/stacker` image contains the **Stacker Server** — a Rust-built backend that provides:

### REST API & Stack Builder UI
- Create, update, and manage deployment projects
- Full CRUD for apps, services, environment variables, port mappings, and domains
- Role-based access control (Casbin)

### MCP Server (Model Context Protocol)
85+ tools exposed over WebSocket, enabling AI agents (Claude, GPT, etc.) to manage infrastructure programmatically:
- Project & deployment management
- Container operations (start, stop, restart, exec)
- Log analysis & error summaries
- Vault config and remote service secret management
- Proxy and firewall configuration
- Server resource monitoring
- Docker Compose generation & preview

### Deployment Orchestration
- **Local** — `docker compose up` on the host machine
- **Cloud** — Terraform + Ansible for Hetzner, DigitalOcean, AWS, Linode
- **Server** — deploy to any existing server via SSH

### Integrations
- **HashiCorp Vault** — secrets and config storage, synced to deployments
- **RabbitMQ (AMQP)** — event-driven deployment status updates
- **PostgreSQL** — persistent storage for projects, deployments, and config
- **Redis** — caching layer for DockerHub metadata and sessions
- **TryDirect User Service** — OAuth, marketplace templates

---

## Stacker CLI Highlights

The CLI (`stacker-cli`) is a standalone binary — no server required for local deploys:

| Command | Description |
|---------|-------------|
| `stacker init` | Detect project type, generate `stacker.yml` + Dockerfile + Compose |
| `stacker deploy` | Build & deploy the stack (local, cloud, or server) |
| `stacker status` | Show running containers and health |
| `stacker logs` | View container logs (`--follow`, `--service`, `--tail`) |
| `stacker secrets` | Manage local `.env` secrets and remote Vault-backed service/server secrets |
| `stacker cloud firewall` | Manage provider firewall rules without SSH |
| `stacker destroy` | Tear down the deployed stack |
| `stacker ai ask` | Ask AI about your stack, or let it modify config |
| `stacker service add` | Add from 20+ built-in service templates |
| `stacker ssh-key generate` | Generate Vault-backed SSH keys |
| `stacker pipe scan` | Discover API endpoints on running containers |
| `stacker pipe create` | Create data pipes between containers (interactive) |
| `stacker pipe list` | List active and paused pipe instances |
| `stacker pipe activate` | Activate a pipe (start trigger-based data flow) |
| `stacker pipe deactivate` | Pause an active pipe |
| `stacker pipe trigger` | One-shot pipe execution with optional input |

### AI-Powered Init

```bash
stacker init --with-ai                          # Local AI (Ollama, free & private)
stacker init --with-ai --ai-provider openai     # OpenAI
stacker init --with-ai --ai-provider anthropic  # Anthropic
```

Scans your project files, detects the stack type, and uses an LLM to generate a tailored `stacker.yml` with services, proxy, monitoring, and hooks.

### Service Catalog (20+ templates)

```bash
stacker service list
stacker service add postgres redis nginx
```

Built-in templates: `postgres`, `mysql`, `mongodb`, `redis`, `memcached`, `rabbitmq`, `traefik`, `nginx`, `nginx_proxy_manager`, `wordpress`, `elasticsearch`, `kibana`, `qdrant`, `telegraf`, `phpmyadmin`, `mailhog`, `minio`, `portainer`, and more.

---

## `stacker.yml` Example

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
  target: local

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

---

## Supported Project Types

Stacker auto-detects and generates optimised multi-stage Dockerfiles for:

| Type | Detection |
|------|-----------|
| **Node.js** | `package.json` |
| **Python** | `requirements.txt`, `pyproject.toml`, `Pipfile` |
| **Rust** | `Cargo.toml` |
| **Go** | `go.mod` |
| **PHP** | `composer.json` |
| **Static** | `index.html`, or manual `type: static` |

---

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | — |
| `RUST_LOG` | Log level (`error`, `warn`, `info`, `debug`, `trace`) | `info` |
| `APP_HOST` | Listen address | `0.0.0.0` |
| `APP_PORT` | Listen port | `8000` |
| `VAULT_ADDRESS` | HashiCorp Vault URL | `http://127.0.0.1:8200` |
| `VAULT_TOKEN` | Vault authentication token | — |
| `AMQP_HOST` | RabbitMQ host | `127.0.0.1` |
| `AMQP_PORT` | RabbitMQ port | `5672` |

---

## Exposed Ports

| Port | Service |
|------|---------|
| `8000` | Stacker Server API |

---

## Volumes

| Path | Purpose |
|------|---------|
| `/app/files` | Generated stack files (Dockerfiles, Compose, configs) |
| `/app/configuration.yaml` | Server configuration |
| `/app/access_control.conf` | Casbin RBAC policy |
| `/app/migrations` | SQL migration files |

---

## Tags

| Tag | Description |
|-----|-------------|
| `latest` | Latest stable release |
| `x.y.z` | Specific version (e.g. `0.2.8`) |
| `test` | Development/testing builds |

---

## Links

- **Source Code**: [github.com/trydirect/stacker](https://github.com/trydirect/stacker)
- **Documentation**: [stacker.yml Reference](https://github.com/trydirect/stacker/blob/main/docs/STACKER_YML_REFERENCE.md)
- **Changelog**: [CHANGELOG.md](https://github.com/trydirect/stacker/blob/main/CHANGELOG.md)
- **Discord**: [Join the community](https://discord.gg/mNhsa8VdYX)
- **Website**: [try.direct](https://try.direct)
- **Issues**: [GitHub Issues](https://github.com/trydirect/stacker/issues)

---

## License

MIT — see [LICENSE](https://github.com/trydirect/stacker/blob/main/LICENSE) for details.
