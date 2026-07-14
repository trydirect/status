# stacker.yml Configuration Reference

> **Stacker CLI v0.2.6** — The single-file deployment configuration for containerised applications.

`stacker.yml` is the only file you need to add to your project. Stacker reads it to auto-generate Dockerfiles, docker-compose definitions, and deploy your application locally or to cloud infrastructure.

---

## Table of Contents

- [Quick Start](#quick-start)
- [Minimal Example](#minimal-example)
- [Full Example](#full-example)
- [Top-Level Fields](#top-level-fields)
  - [name](#name) · [version](#version) · [organization](#organization)
- [app — Application Source](#app)
  - [type](#apptype) · [path](#apppath) · [dockerfile](#appdockerfile) · [image](#appimage) · [build](#appbuild) · [ports](#appports) · [volumes](#appvolumes) · [environment](#appenvironment)
- [services — Sidecar Containers](#services)
- [proxy — Reverse Proxy](#proxy)
  - [type](#proxytype) · [auto_detect](#proxyauto_detect) · [domains](#proxydomains) · [config](#proxyconfig)
- [deploy — Deployment Target](#deploy)
  - [target](#deploytarget) · [compose_file](#deploycompose_file) · [cloud](#deploycloud) · [server](#deployserver)
- [ai — AI Assistant](#ai)
- [monitoring — Health & Metrics](#monitoring)
  - [status_panel](#monitoringstatus_panel) · [healthcheck](#monitoringhealthcheck) · [metrics](#monitoringmetrics)
- [hooks — Lifecycle Scripts](#hooks)
- [env / env_file — Environment Variables](#env--env_file)
- [Environment Variable Interpolation](#environment-variable-interpolation)
- [Auto-Detection](#auto-detection)
- [Generated Dockerfiles](#generated-dockerfiles)
- [Validation Rules](#validation-rules)
- [CLI Commands Reference](#cli-commands-reference)
  - [SSH Key Management](#stacker-ssh-key--ssh-key-management)
  - [Service Template Catalog](#stacker-service--service-template-catalog)
  - [Agent Control](#stacker-agent--agent-control)
  - [Firewall Management](#firewall-management)
- [Recipes](#recipes)
- [FAQ](#faq)

---

## Quick Start

```bash
# 1. Install stacker
curl -fsSL https://stacker.try.direct/install.sh | bash

# 2. Initialize in your project directory
cd my-project
stacker init

# 3. Review the generated config
cat stacker.yml

# 4. Deploy locally
stacker deploy --target local

# 5. Check status
stacker status
```

---

## Minimal Example

The smallest valid `stacker.yml`:

```yaml
name: my-app
app:
  type: static
  path: ./public
deploy:
  target: local
```

This tells Stacker to:
1. Generate an nginx-based Dockerfile serving static files from `./public`
2. Create a docker-compose.yml with the app service
3. Deploy locally via `docker compose up`

---

## Full Example

A production-ready configuration using all available sections:

```yaml
name: my-saas-app
version: "2.0"
organization: acme-corp

app:
  type: node
  path: ./src
  ports:
    - "8080:3000"
  environment:
    NODE_ENV: production
  build:
    context: .
    args:
      NODE_ENV: production

services:
  - name: postgres
    image: postgres:16
    ports:
      - "5432:5432"
    environment:
      POSTGRES_DB: myapp
      POSTGRES_USER: app
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    volumes:
      - pgdata:/var/lib/postgresql/data

  - name: redis
    image: redis:7-alpine
    ports:
      - "6379:6379"

  - name: worker
    image: myapp-worker:latest
    depends_on:
      - postgres
      - redis
    environment:
      REDIS_URL: redis://redis:6379

proxy:
  type: nginx
  auto_detect: true
  domains:
    - domain: app.example.com
      ssl: auto
      upstream: app:3000
    - domain: api.example.com
      ssl: auto
      upstream: app:3000

deploy:
  target: cloud
  cloud:
    provider: hetzner
    region: fsn1
    size: cx23
    ssh_key: ~/.ssh/id_ed25519

ai:
  enabled: true
  provider: ollama
  model: llama3
  endpoint: http://localhost:11434
  timeout: 600
  tasks:
    - dockerfile
    - troubleshoot

monitoring:
  status_panel: true
  healthcheck:
    endpoint: /health
    interval: 30s
  metrics:
    enabled: true
    telegraf: true

hooks:
  pre_build: ./scripts/pre-build.sh
  post_deploy: ./scripts/post-deploy.sh
  on_failure: ./scripts/notify-failure.sh

env_file: .env

env:
  APP_PORT: "3000"
  LOG_LEVEL: info
  NODE_ENV: production
```

---

## Top-Level Fields

### `name`

**Required** · `string` · Max 128 characters

The project name. Used as the docker-compose project name, container name prefix, and displayed in status output.

```yaml
name: my-awesome-app
```

### `version`

*Optional* · `string` · Default: none

A version label for the configuration. Informational only — does not affect behaviour.

```yaml
version: "1.0"
```

### `organization`

*Optional* · `string` · Default: none

Organisation slug. Used for scoping cloud deployments and linking to your TryDirect account.

```yaml
organization: acme-corp
```

---

## `app`

**Application source configuration.** Tells Stacker what kind of app you're building and where the source code lives.

### `app.type`

*Optional* · `enum` · Default: `static`

The application framework/runtime. Determines which Dockerfile template is generated.

| Value | Description | Default Base Image | Default Port |
|-------|-------------|-------------------|--------------|
| `static` | Static HTML/CSS/JS site | `nginx:alpine` | 80 |
| `node` | Node.js application | `node:20-alpine` | 3000 |
| `python` | Python application | `python:3.12-slim` | 8000 |
| `rust` | Rust application | `rust:1.77-alpine` | 8080 |
| `go` | Go application | `golang:1.22-alpine` | 8080 |
| `php` | PHP application | `php:8.3-fpm-alpine` | 9000 |
| `custom` | User-provided Dockerfile | — | — |

```yaml
app:
  type: node
```

> **Tip:** If you omit `type`, Stacker auto-detects it from your project files.
> See [Auto-Detection](#auto-detection).

### `app.path`

*Optional* · `string` (path) · Default: `.`

Path to the application source directory, relative to the `stacker.yml` location.

```yaml
app:
  path: ./src
```

### `app.dockerfile`

*Optional* · `string` (path) · Default: none

Path to a custom Dockerfile. When set, Stacker uses your Dockerfile instead of generating one. Requires `type: custom` or will override the generated template.

```yaml
app:
  type: custom
  dockerfile: ./docker/Dockerfile.prod
```

### `app.image`

*Optional* · `string` · Default: none

Use a pre-built Docker image instead of building from source. Mutually exclusive with `dockerfile` and auto-generation.

```yaml
app:
  type: custom
  image: ghcr.io/myorg/myapp:latest
```

### `app.build`

*Optional* · `object` · Default: none

Docker build configuration. Controls the build context and build arguments passed to `docker build`.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `context` | `string` | `.` | Build context directory |
| `args` | `map<string, string>` | `{}` | Build arguments (`--build-arg`) |

```yaml
app:
  type: node
  build:
    context: .
    args:
      NODE_ENV: production
      API_URL: https://api.example.com
```

### `app.ports`

*Optional* · `string[]` · Default: `[]` (auto-derived from `type`)

Explicit port mappings for the main app container in `"host:container"` format. When omitted, Stacker derives a default port from `app.type` (e.g. node → 3000, python → 8000).

```yaml
app:
  type: node
  ports:
    - "8080:3000"
    - "9229:9229"   # Node debugger
```

### `app.volumes`

*Optional* · `string[]` · Default: `[]`

Volume mounts for the main app container. Supports bind mounts (`./host:/container`) and named volumes (`name:/path`).

```yaml
app:
  type: node
  volumes:
    - "./uploads:/app/uploads"
    - "app_cache:/app/.cache"
```

### `app.environment`

*Optional* · `map<string, string>` · Default: `{}`

Per-app environment variables. Merged with the top-level `env:` section — app-level values take precedence on conflict. Supports `${VAR}` interpolation.

```yaml
app:
  type: node
  environment:
    NODE_ENV: production
    DATABASE_URL: postgres://app:${DB_PASSWORD}@postgres:5432/myapp
```

---

## `services`

*Optional* · `array` · Default: `[]`

Additional containers deployed alongside your main application — databases, caches, message queues, workers, etc. Each entry maps directly to a service in the generated `docker-compose.yml`.

### Service Definition Fields

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | `string` | **yes** | — | Service name (used as container/hostname) |
| `image` | `string` | **yes** | — | Docker image reference |
| `ports` | `string[]` | no | `[]` | Port mappings (`"host:container"`) |
| `environment` | `map<string, string>` | no | `{}` | Environment variables |
| `volumes` | `string[]` | no | `[]` | Volume mounts (`"name:/path"` or `"./host:/container"`) |
| `depends_on` | `string[]` | no | `[]` | Services this depends on (started first) |

```yaml
services:
  - name: postgres
    image: postgres:16
    ports:
      - "5432:5432"
    environment:
      POSTGRES_DB: myapp
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    volumes:
      - pgdata:/var/lib/postgresql/data

  - name: redis
    image: redis:7-alpine
    ports:
      - "6379:6379"

  - name: minio
    image: minio/minio:latest
    ports:
      - "9000:9000"
      - "9001:9001"
    environment:
      MINIO_ROOT_USER: admin
      MINIO_ROOT_PASSWORD: ${MINIO_PASSWORD}
    volumes:
      - minio-data:/data
```

> **Note:** Stacker detects port conflicts across services during validation.
> If two services bind the same host port, you'll get a warning (`W001`).

---

## `proxy`

*Optional* · `object` · Default: `type: none, auto_detect: true`

Reverse proxy configuration. Stacker can auto-detect a running proxy or generate configuration for one.

### `proxy.type`

*Optional* · `enum` · Default: `none`

| Value | Description |
|-------|-------------|
| `nginx` | Standard Nginx reverse proxy |
| `nginx-proxy-manager` | Nginx Proxy Manager (NPM) with web UI |
| `traefik` | Traefik reverse proxy with auto-discovery |
| `none` | No proxy configured |

```yaml
proxy:
  type: nginx
```

### `proxy.auto_detect`

*Optional* · `bool` · Default: `true`

When enabled, Stacker scans running Docker containers for an existing reverse proxy before deploying. If found, it connects your app to the existing proxy instead of creating a new one.

Detection checks for these container images (in priority order):
1. `jc21/nginx-proxy-manager` / `nginx-proxy-manager` → `nginx-proxy-manager`
2. `traefik` → `traefik`
3. `nginx` → `nginx`

```yaml
proxy:
  auto_detect: false  # Don't look for existing proxies
```

### `proxy.domains`

*Optional* · `array` · Default: `[]`

Domain routing rules. Each entry generates a proxy virtual host configuration.

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `domain` | `string` | **yes** | — | Domain name (e.g. `app.example.com`) |
| `upstream` | `string` | **yes** | — | Backend address (e.g. `app:3000`, `http://web:8080`) |
| `ssl` | `enum` | no | `off` | SSL certificate mode |

**SSL modes:**

| Value | Description |
|-------|-------------|
| `auto` | Automatic certificate provisioning (Let's Encrypt) |
| `manual` | Use manually provided certificates |
| `off` | No SSL (HTTP only) |

```yaml
proxy:
  type: nginx
  domains:
    - domain: app.example.com
      ssl: auto
      upstream: app:3000

    - domain: api.example.com
      ssl: auto
      upstream: app:3000

    - domain: staging.example.com
      ssl: off
      upstream: app:3000
```

### `proxy.config`

*Optional* · `string` (path) · Default: none

Path to a custom proxy configuration file. When set, Stacker uses your config instead of generating one.

```yaml
proxy:
  type: nginx
  config: ./nginx/custom.conf
```

---

## `deploy`

**Deployment target configuration.** Controls where and how your stack is deployed.

### `deploy.target`

*Optional* · `enum` · Default: `local`

| Value | Description |
|-------|-------------|
| `local` | Deploy on the local machine via `docker compose` |
| `cloud` | Provision cloud infrastructure and deploy (requires `deploy.cloud`) |
| `server` | Deploy to an existing remote server via SSH (requires `deploy.server`) |

```yaml
deploy:
  target: local
```

> **Pipe mode**: The `deploy.target` value also affects how `stacker pipe` commands behave. When target is `local`, pipes are created without a `deployment_hash` and execute against local Docker containers (`docker exec`). Use `stacker target` to switch modes at runtime without editing `stacker.yml`. See the [DAG Pipes CLI Guide — Local Mode](./DAG_PIPES_PART1_CLI_GUIDE.md#local-mode-experimental) for details.

### `deploy.compose_file`

*Optional* · `string` (path) · Default: none

Use a custom docker-compose file instead of the auto-generated one. Stacker will skip generation and use this file directly.

```yaml
deploy:
  target: local
  compose_file: ./docker-compose.prod.yml
```

### `deploy.cloud`

*Required when `target: cloud`* · `object`

Cloud infrastructure provisioning settings. Stacker uses Terraform/Ansible under the hood to create servers and deploy your stack.

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `provider` | `enum` | **yes** | — | Cloud provider |
| `region` | `string` | no | Provider default | Data center region |
| `size` | `string` | no | Provider default | Server size/type |
| `ssh_key` | `string` (path) | no | none | Path to SSH private key |

**Supported cloud providers:**

| Value | Provider | Example Regions | Example Sizes |
|-------|----------|----------------|---------------|
| `hetzner` | Hetzner Cloud | `fsn1`, `nbg1`, `hel1` | `cx23`, `cx33`, `cx43` |
| `digitalocean` | DigitalOcean | `nyc1`, `sfo3`, `ams3` | `s-1vcpu-1gb`, `s-2vcpu-4gb` |
| `aws` | Amazon Web Services | `us-east-1`, `eu-west-1` | `t3.micro`, `t3.small` |
| `linode` | Linode (Akamai) | `us-east`, `eu-west` | `g6-nanode-1`, `g6-standard-2` |
| `vultr` | Vultr | `ewr`, `lhr`, `fra` | `vc2-1c-1gb`, `vc2-2c-4gb` |

```yaml
deploy:
  target: cloud
  cloud:
    provider: hetzner
    region: fsn1
    size: cx23
    ssh_key: ~/.ssh/id_ed25519
```

> **Important:** Cloud deployment requires authentication.
> Run `stacker login` first to store your TryDirect credentials.

### `deploy.server`

*Required when `target: server`* · `object`

Remote server settings for deploying to an existing machine via SSH.

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `host` | `string` | **yes** | — | Server hostname or IP address |
| `user` | `string` | no | `root` | SSH username |
| `ssh_key` | `string` (path) | no | none | Path to SSH private key |
| `port` | `integer` | no | `22` | SSH port |

```yaml
deploy:
  target: server
  server:
    host: 203.0.113.42
    user: deploy
    ssh_key: ~/.ssh/deploy_key
    port: 22
```

### `deploy.registry`

*Optional* · `object`

Docker registry credentials for pulling private images during cloud/server deployment. When provided, `docker login` is executed on the target server before `docker compose pull`.

Credentials can be specified in `stacker.yml` or via environment variables. Environment variables take precedence.

For deployments managed by the Status agent, Stacker also persists this auth in
its trusted secret storage and reuses it for later image refreshes such as
`stacker agent deploy-app`. The agent performs the pull with a temporary Docker
auth directory and immediate cleanup, so private-image redeploys do not depend
on whatever `docker login` state happens to exist on the host. If no stored
registry auth exists, Stacker keeps the current anonymous-pull behavior and may
still redeploy successfully when the image is already cached locally.

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `username` | `string` | **yes** | — | Registry username |
| `password` | `string` | **yes** | — | Registry password or access token |
| `server` | `string` | no | Docker Hub | Registry server URL |

**Environment variables** (override `stacker.yml` values):

| Variable | Fallback | Description |
|----------|----------|-------------|
| `STACKER_DOCKER_USERNAME` | `DOCKER_USERNAME` | Registry username |
| `STACKER_DOCKER_PASSWORD` | `DOCKER_PASSWORD` | Registry password |
| `STACKER_DOCKER_REGISTRY` | `DOCKER_REGISTRY` | Registry server URL |

```yaml
deploy:
  target: cloud
  cloud:
    provider: hetzner
    region: fsn1
    size: cx23
  registry:
    username: "${DOCKER_USERNAME}"
    password: "${DOCKER_PASSWORD}"
    # server: "docker.io"  # Docker Hub (default)
```

> **Security tip:** Use environment variables or `${VAR}` syntax to keep credentials out of version control.

---

## `ai`

*Optional* · `object` · Default: `enabled: false`

AI/LLM assistant configuration. When enabled, `stacker ai ask` uses the configured provider to answer questions about your Dockerfile, docker-compose, and deployment.

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `enabled` | `bool` | no | `false` | Enable AI features |
| `provider` | `enum` | no | `openai` | LLM provider |
| `model` | `string` | no | Provider default | Model name |
| `api_key` | `string` | no* | none | API key (supports `${VAR}` syntax) |
| `endpoint` | `string` | no | Provider default | Custom API endpoint URL |
| `timeout` | `integer` | no | `300` | Request timeout in seconds (increase for slow models / weak hardware) |
| `tasks` | `string[]` | no | `[]` | Allowed AI task types |

**Supported providers:**

| Value | Provider | Default Endpoint | Requires API Key |
|-------|----------|-----------------|------------------|
| `openai` | OpenAI | `https://api.openai.com/v1` | Yes |
| `anthropic` | Anthropic | `https://api.anthropic.com/v1` | Yes |
| `ollama` | Ollama (local) | `http://localhost:11434` | No |
| `custom` | Any OpenAI-compatible API | Must specify `endpoint` | Varies |

**Task types** (used for prompt specialisation):
- `dockerfile` — Dockerfile optimisation and generation
- `troubleshoot` — Debugging deployment issues
- `compose` — docker-compose configuration help
- `security` — Security review and hardening

```yaml
# Using OpenAI
ai:
  enabled: true
  provider: openai
  model: gpt-4
  api_key: ${OPENAI_API_KEY}
  tasks:
    - dockerfile
    - troubleshoot

# Using local Ollama
ai:
  enabled: true
  provider: ollama
  model: llama3
  endpoint: http://localhost:11434
  timeout: 600  # 10 minutes for large models on slower hardware

# Using a custom OpenAI-compatible API (e.g. Groq, Together AI)
ai:
  enabled: true
  provider: custom
  model: mixtral-8x7b-32768
  api_key: ${GROQ_API_KEY}
  endpoint: https://api.groq.com/openai/v1
```

---

## `monitoring`

*Optional* · `object` · Default: `status_panel: false`

Monitoring and health check configuration.

### `monitoring.status_panel`

*Optional* · `bool` · Default: `false`

Enable the Stacker status panel — a web UI showing container health, resource usage, and deployment status.

```yaml
monitoring:
  status_panel: true
```

If you install the agent later with `stacker agent install`, the CLI does **not** modify local
`stacker.yml` by default. Pass `--persist-config` to also write
`monitoring.status_panel: true` back into the local config file.

### `monitoring.healthcheck`

*Optional* · `object` · Default: none

Application health check settings.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `endpoint` | `string` | `/health` | HTTP path to probe |
| `interval` | `string` | `30s` | Time between checks |

```yaml
monitoring:
  healthcheck:
    endpoint: /api/health
    interval: 15s
```

### `monitoring.metrics`

*Optional* · `object` · Default: none

Metrics collection settings.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | `bool` | `false` | Enable metrics collection |
| `telegraf` | `bool` | `false` | Deploy Telegraf agent for metrics |

```yaml
monitoring:
  metrics:
    enabled: true
    telegraf: true
```

---

## `hooks`

*Optional* · `object` · Default: none

Lifecycle hook scripts. Stacker runs these at specific points during the build and deploy process.

| Field | Type | Description | When it runs |
|-------|------|-------------|------|
| `pre_build` | `string` (path) | Script to run before Docker build | Before `docker build` |
| `post_deploy` | `string` (path) | Script to run after successful deployment | After `docker compose up` succeeds |
| `on_failure` | `string` (path) | Script to run on deployment failure | When any deploy step fails |

```yaml
hooks:
  pre_build: ./scripts/pre-build.sh
  post_deploy: ./scripts/seed-database.sh
  on_failure: ./scripts/alert-team.sh
```

> Hook scripts must be executable (`chmod +x`).

---

## `env` / `env_file`

### `env`

*Optional* · `map<string, string>` · Default: `{}`

Inline environment variables passed to all containers. Supports `${VAR}` interpolation.

```yaml
env:
  APP_PORT: "3000"
  LOG_LEVEL: info
  DATABASE_URL: postgres://app:${DB_PASSWORD}@postgres:5432/myapp
```

### `env_file`

*Optional* · `string` (path) · Default: none

Path to a `.env` file. Loaded before the config is parsed, so variables defined here can be referenced with `${VAR}` syntax anywhere in `stacker.yml`.

```yaml
env_file: .env
```

Example `.env`:
```
DB_PASSWORD=s3cret
MINIO_PASSWORD=admin123
OPENAI_API_KEY=sk-...
```

For remote deployments, Stacker renders the effective runtime env to the
canonical host path `/home/trydirect/project/.env`. Generated compose files
reference it as `env_file: .env`, relative to `docker-compose.yml`.

Top-level `env_file` is a Stacker config input: it is loaded before
`stacker.yml` is parsed so `${VAR}` placeholders can be resolved. It does not
automatically inject variables into a container. Container injection is still
controlled by Docker Compose `env_file` entries under each compose service.

For app-only remote updates, `stacker agent deploy-app <app>` resolves the
environment/profile from `--env`, then `.stacker/active-env`, then
`deploy.environment`. If `<app>/docker/<env>/compose.yml` exists, Stacker uses
the app-local service definition for that app and resolves its `env_file`
entries relative to that compose file, then merges the service definition back
into the full project-level compose before sending it to the agent. This keeps
other services in the remote `docker-compose.yml` intact without requiring
env/config files referenced only by unrelated project-level services. A
service-local file such as `<app>/docker/prod/.env` is uploaded to the remote
config bundle, and Vault-rendered service secrets for that app are appended to
that same remote `.env` before the Status agent writes it. When the same target
is updated again, Stacker refreshes the existing `# stacker-render ...` block
instead of duplicating prior rendered secret sections. If Stacker cannot render
the target runtime env, command creation fails instead of deploying a raw
app-local `.env` without the remote secrets.

The rendered runtime env is built from these layers, lowest to highest:

1. Base app env and local authoring inputs.
2. Server-scope secrets, only for services that opt in with
   `inherit_server_secrets: true`.
3. Service-scope secrets for the selected service/app target.
4. Compose `environment:` keys, which Docker Compose applies above `env_file`.

User-provided runtime env keys must match `^[A-Z_][A-Z0-9_]*$`. Keys beginning
with `STACKER_`, `DOCKER_`, `VAULT_`, or `AGENT_` are reserved and rejected.
Use `stacker config show --resolved` to inspect the local env source path,
remote runtime path, config hash/version metadata, and contributing layers
without printing secret values.

---

## Environment Variable Interpolation

Any value in `stacker.yml` can reference environment variables using `${VAR_NAME}` syntax. Variables are resolved from the process environment at parse time.

```yaml
name: ${PROJECT_NAME}
app:
  type: node
services:
  - name: postgres
    image: postgres:${PG_VERSION}
    environment:
      POSTGRES_PASSWORD: ${DB_PASSWORD}
deploy:
  target: cloud
  cloud:
    provider: ${CLOUD_PROVIDER}
ai:
  api_key: ${OPENAI_API_KEY}
```

**Rules:**
- Syntax: `${VARIABLE_NAME}` (curly braces required)
- Undefined variables cause a parse error (fail-fast, no silent empty strings)
- Interpolation happens before YAML parsing
- Works in all string values including paths, URLs, and map values

---

## Auto-Detection

When you run `stacker init` without specifying `--app-type`, Stacker scans the workspace and looks for these marker files:

| Files Found | Detected Type |
|-------------|---------------|
| `package.json` | `node` |
| `requirements.txt`, `Pipfile`, `pyproject.toml`, `setup.py` | `python` |
| `Cargo.toml` | `rust` |
| `go.mod` | `go` |
| `composer.json` | `php` |
| `index.html`, `*.html` | `static` |

Detection priority is top-to-bottom. If none of these files are found, it defaults to `custom`.

For monorepo-style projects, `stacker init` now:

- Recursively scans nested directories for app candidates with marker files and/or Dockerfiles
- Detects aggregate Docker Compose stacks, including `include:` chains
- Selects one primary app for the generated `app:` section
- Reuses a detected aggregate compose file by setting `deploy.compose_file`
- Imports image-backed compose sidecars into the generated `services:` list
- Emits warning comments when scan data suggests a required local bootstrap asset or generator is missing

Build-only compose services are still reported in the generated file comments, but they are not
imported into `services:` because the current schema requires an explicit `image`.

---

## Generated Dockerfiles

When you run `stacker deploy`, Stacker generates a Dockerfile in `.stacker/Dockerfile` based on `app.type`. Here's what each template produces:

### `static`
```dockerfile
FROM nginx:alpine
COPY . /usr/share/nginx/html
EXPOSE 80
```

### `node`
```dockerfile
FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --production
COPY . .
EXPOSE 3000
CMD ["node", "server.js"]
```

### `python`
```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8000
CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
```

### `rust`
```dockerfile
FROM rust:1.77-alpine
WORKDIR /app
RUN apk add --no-cache musl-dev
COPY . .
RUN cargo build --release
EXPOSE 8080
CMD ["./target/release/app"]
```

### `go`
```dockerfile
FROM golang:1.22-alpine
WORKDIR /app
COPY go.mod ./
COPY go.sum ./
RUN go mod download
COPY . .
RUN go build -o /app/server .
EXPOSE 8080
CMD ["/app/server"]
```

### `php`
```dockerfile
FROM php:8.3-fpm-alpine
WORKDIR /var/www/html
RUN docker-php-ext-install pdo pdo_mysql
COPY . .
EXPOSE 9000
```

### `custom`
No Dockerfile is generated. You must provide either `app.dockerfile` or `app.image`.

> **Customisation:** To modify the generated Dockerfile, deploy once with `--dry-run`, edit `.stacker/Dockerfile`, then deploy again with `--force-rebuild`.

---

## Validation Rules

Stacker validates your configuration both syntactically (YAML structure) and semantically (cross-field logic). Run `stacker config validate` to check.

### Errors (deployment will fail)

| Code | Rule | Field |
|------|------|-------|
| `E001` | Cloud deployment requires `deploy.cloud.provider` | `deploy.cloud.provider` |
| `E002` | Server deployment requires `deploy.server.host` | `deploy.server.host` |
| `E003` | Custom app type requires `app.image` or `app.dockerfile` | `app` |

### Warnings (deployment may have issues)

| Code | Rule | Field |
|------|------|-------|
| `W001` | Port conflict — multiple services bind the same host port | `services.ports` |

### Example output

```
$ stacker config validate
Configuration issues:
  - [E001] Cloud provider configuration is required for cloud deployment (deploy.cloud.provider)
  - [W001] Port 8080 is used by multiple services: api, worker (services.ports)
```

---

## CLI Commands Reference

| Command | Description |
|---------|-------------|
| `stacker init` | Initialize a new project — generates `stacker.yml` and `.stacker/` directory (Dockerfile + docker-compose.yml) |
| `stacker deploy` | Build and deploy the stack; cloud deploys also install a local SSH backup key when possible |
| `stacker status` | Show container status |
| `stacker logs` | Show container logs |
| `stacker secrets` | Manage local `.env` secrets or remote Vault-backed service/server secrets |
| `stacker destroy` | Tear down the stack |
| `stacker config validate` | Validate `stacker.yml` |
| `stacker config show` | Display resolved configuration |
| `stacker config fix` | Interactively fix missing required config fields |
| `stacker config setup ai` | Configure `ai.*` settings without hand-editing YAML |
| `stacker env` | Show or switch the active deploy environment/profile |
| `stacker login` | Authenticate with TryDirect |
| `stacker ai ask` | Ask the AI assistant a question |
| `stacker proxy add` | Add a reverse-proxy domain entry |
| `stacker proxy detect` | Detect running reverse proxies |
| `stacker cloud firewall add` | Open cloud-provider firewall ports without SSH |
| `stacker cloud firewall remove` | Remove Stacker-managed cloud-provider firewall rules |
| `stacker cloud firewall list` | List cloud-provider firewall rules for a server |
| `stacker ssh-key generate` | Generate a Vault-backed SSH key pair for a server |
| `stacker ssh-key show` | Display the public SSH key for a server |
| `stacker ssh-key upload` | Upload an existing SSH key pair for a server |
| `stacker ssh-key inject` | Repair Vault-key trust using an already-working private key |
| `stacker service add` | Add a service from the template catalog to `stacker.yml` |
| `stacker service list` | List available service templates (20+ built-in) |
| `stacker agent health` | Check Status Panel agent connectivity and health |
| `stacker agent status` | Display agent snapshot — containers, versions, uptime |
| `stacker agent logs <app>` | Retrieve container logs from the remote agent |
| `stacker agent restart <app>` | Restart a container via the agent |
| `stacker agent deploy-app` | Deploy or update an app container on the target server; use `--env <name>` to select an environment/profile |
| `stacker agent remove-app` | Remove an app container (optional volume/image cleanup) |
| `stacker agent configure-proxy` | Configure Nginx Proxy Manager via the agent; use `--no-ssl` for plain HTTP hosts |
| `stacker agent configure-firewall` | Configure guest OS firewall rules via the Status Panel agent |
| `stacker agent history` | Show recent agent command execution history |
| `stacker agent exec` | Execute a raw agent command with JSON parameters |
| `stacker update` | Check for CLI updates |

### `stacker init` flags

| Flag | Description |
|------|-------------|
| `--app-type <TYPE>` | Application type: `static`, `node`, `python`, `rust`, `go`, `php`, `custom` |
| `--with-proxy` | Include reverse-proxy (nginx) configuration |
| `--with-ai` | Use AI to scan the project and generate a tailored `stacker.yml` |
| `--ai-provider <PROVIDER>` | AI provider: `openai`, `anthropic`, `ollama`, `custom` (default: `ollama`) |
| `--ai-model <MODEL>` | AI model name (e.g. `gpt-4o`, `claude-sonnet-4-20250514`, `qwen2.5-coder`, `deepseek-r1`) |
| `--ai-api-key <KEY>` | AI API key (or set `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` env var) |

`stacker init` generates:
- `stacker.yml` — project configuration
- `.stacker/Dockerfile` — generated Dockerfile (skipped if `app.image` or `app.dockerfile` is set)
- `.stacker/docker-compose.yml` — generated compose definition (skipped if `deploy.compose_file` is set)
- `.stacker/scenarios/qwen2.5-code/website-deploy/state.json` — saved only when the qwen website scenario bootstrap is accepted

```bash
# Init
stacker init                                          # Auto-detect project type
stacker init --app-type node --with-proxy             # Explicit type + proxy
stacker init --with-ai                                # AI-powered generation (Ollama default)
stacker init --with-ai --ai-model qwen2.5-coder       # Specify Ollama model
stacker init --with-ai --ai-provider ollama --ai-model deepseek-r1
stacker init --with-ai --ai-provider openai --ai-api-key sk-...
stacker init --with-ai --ai-provider anthropic --ai-model claude-sonnet-4-20250514

# AI init environment variables (override CLI defaults)
# STACKER_AI_PROVIDER  — AI provider (openai, anthropic, ollama, custom)
# STACKER_AI_MODEL     — Model name
# STACKER_AI_API_KEY   — API key (generic, provider-specific vars also supported)
# STACKER_AI_ENDPOINT  — Custom endpoint URL
# STACKER_AI_TIMEOUT   — Request timeout in seconds (default: 300)
# OPENAI_API_KEY       — OpenAI API key (used when provider is openai)
# ANTHROPIC_API_KEY    — Anthropic API key (used when provider is anthropic)
STACKER_AI_TIMEOUT=900 stacker init --with-ai  # 15 min timeout for slow models
```

If the project is a simple HTML or Next.js website and the Ollama model is
`qwen2.5-code` or `qwen2.5-coder`, Stacker can offer a website deployment
scenario immediately after `stacker init --with-ai`. That bootstrap reads the
generated config first, asks only for missing deploy inputs, and stores the
scenario state under `.stacker/scenarios/qwen2.5-code/website-deploy/`.

### `stacker deploy` flags

```bash
stacker deploy --target local          # Deploy locally
stacker deploy --target cloud          # Deploy to cloud
stacker deploy --target local --dry-run  # Generate files without deploying
stacker deploy --file custom.yml       # Use a custom config file
stacker deploy --force-rebuild         # Force regenerate .stacker/ artifacts

```

>
> **Troubleshooting:** On deploy build/runtime failures, Stacker attempts AI-assisted diagnosis using your configured AI provider. If AI is unavailable, it prints fallback fix suggestions.
> **Note:** `deploy` reuses existing `.stacker/Dockerfile` and `.stacker/docker-compose.yml` if present (e.g. from `stacker init`). Use `--force-rebuild` to regenerate them.
> **SSH access:** After a successful cloud deploy, Stacker creates or reuses a
> local backup key in the user-scoped Stacker config directory and authorizes its
> public key on the server when possible. It prints a copy-paste-ready `ssh -i`
> command; the Vault private key is not exported to the CLI.
> **IP persistence:** If a cloud/server install pauses or fails after the
> installer has reported an IP address, Stacker saves that discovered IP in the
> local deployment context and persists it server-side when possible.

### Remote secrets

```bash
# Discover deployable service/app targets for the current project
stacker secrets apps

# Store a Vault-backed secret for one service/app target
stacker secrets set S3_BUCKET \
  --scope service \
  --service upload \
  --body superbucket

# Remote reads return metadata only, never plaintext values
stacker secrets list --scope service --service upload --json
stacker secrets get S3_BUCKET --scope service --service upload --json

# Push stored remote secrets into the target's runtime env
stacker secrets push --service upload
stacker secrets push --service upload --env prod
# Aliases: stacker secrets deploy --service upload
#          stacker secrets apply --service upload
```

Service-scoped remote secrets target the codes listed by `stacker secrets apps`.
Those codes include the main app, registered `stacker.yml` services, and
supported image-backed services extracted from `deploy.compose_file` during
cloud/server deploy preparation. A service secret is rendered only into the
matching service/app target.

Deleting a service-scoped secret removes it from the next rendered
`/home/trydirect/project/.env`; stale values are not preserved. If the remote
runtime env changed outside Stacker, Stacker refuses to overwrite it unless the
operation is explicitly forced.

`stacker secrets push --service <target>` is the explicit "apply stored secrets
now" command. It renders the runtime env for that target and sends it to the
Status agent; it does not create, update, or reveal secret values. Use
`--env <name>` for one command, or `stacker env <name>` to persist the active
environment/profile for later `stacker agent deploy-app` and
`stacker secrets push` commands.

MCP config inspection uses the same classification model. `get_app_env_vars`
retains the legacy redacted object response but also emits
`environment_entries[]`, where Vault-backed keys are marked with
`secure=true` and `source="vault"` even if the variable name itself would not
match older secret-name heuristics.

### Other commands

```bash
# Logs
stacker logs                           # All services
stacker logs --service postgres        # Specific service
stacker logs --follow                  # Stream logs
stacker logs --tail 100                # Last 100 lines
stacker logs --since 1h               # Logs from the last hour

# Status
stacker status                         # Table format
stacker status --json                  # JSON output
stacker status --watch                 # Auto-refresh

# Destroy
stacker destroy --confirm              # Required flag (safety guard)
stacker destroy --confirm --volumes    # Also remove volumes

# Config
stacker config validate                # Check stacker.yml
stacker config validate --file prod.yml
stacker config show                    # Display resolved config
stacker config setup ai --provider ollama --endpoint http://localhost:11434 --model llama3 --task dockerfile --task troubleshoot

# AI
stacker ai ask "How can I optimise this Dockerfile?"
stacker ai ask "Why is my container crashing?" --context ./logs.txt
stacker ai ask "continue" --scenario website-deploy --step image-publish
stacker ai --scenario website-deploy --step runtime-ops

# Proxy
stacker proxy add example.com --upstream http://app:3000 --ssl auto
stacker proxy detect

# Update
stacker update                         # Check stable channel
stacker update --channel beta          # Check beta channel

# Config
stacker config fix                     # Interactively fix missing fields
stacker config fix --file prod.yml     # Fix a specific config file
stacker config setup ai                # Configure ai.* interactively
```

### `stacker ssh-key` — SSH Key Management

Manage Vault-backed SSH keys for your deployed servers. Server automation keys
are stored securely in HashiCorp Vault. Cloud deploys also maintain a separate
local backup key under the Stacker config directory so users can connect with a
normal `ssh` command.

```bash
# Generate a new SSH key pair for a server
stacker ssh-key generate --server-id 42

# Generate and save the private key locally
stacker ssh-key generate --server-id 42 --save-to ~/.ssh/my-server.pem

# Show the public SSH key
stacker ssh-key show --server-id 42
stacker ssh-key show --server-id 42 --json         # JSON output

# Upload an existing SSH key pair
stacker ssh-key upload --server-id 42 \
  --public-key ~/.ssh/id_rsa.pub \
  --private-key ~/.ssh/id_rsa

# Repair a server that no longer trusts the Vault public key
stacker ssh-key inject --server-id 42 --with-key ~/.ssh/existing-private-key
```

`ssh-key generate` manages the server-side Vault key. `ssh-key inject` is a
repair command: it uses `--with-key` as a bootstrap private key that already
works on the server, then appends the Vault public key to `authorized_keys`. It
does not install your local key on the server.

Automatic cloud-deploy backup keys are stored outside the project directory:

```text
~/.config/stacker/ssh/server-42_ed25519
~/.config/stacker/ssh/server-42_ed25519.pub
```

If `$XDG_CONFIG_HOME` is set, Stacker uses
`$XDG_CONFIG_HOME/stacker/ssh/` instead.

### `stacker service` — Service Template Catalog

Add services to your `stacker.yml` from a built-in catalog of 20+ templates. Each template includes a production-ready image, default ports, environment variables, and volumes.

```bash
# Add a service (creates backup, checks for duplicates)
stacker service add postgres
stacker service add redis
stacker service add wordpress              # auto-adds mysql dependency

# Use aliases
stacker service add wp                     # → wordpress + mysql
stacker service add pg                     # → postgres
stacker service add es                     # → elasticsearch

# Specify a custom stacker.yml path
stacker service add mongodb --file ./configs/stacker.yml

# List all available templates
stacker service list                       # offline catalog (20+ services)
stacker service list --online              # also query marketplace API
```

**Built-in services:** postgres, mysql, mariadb, mongodb, redis, memcached, rabbitmq, traefik, nginx, nginx_proxy_manager, wordpress, elasticsearch, kibana, qdrant, telegraf, phpmyadmin, mailhog, minio, portainer

**Aliases:** `wp`→wordpress, `pg`/`postgresql`→postgres, `my`→mysql, `mongo`→mongodb, `es`→elasticsearch, `mq`→rabbitmq, `pma`→phpmyadmin, `mh`→mailhog, `npm`→nginx_proxy_manager

### `stacker agent` — Agent Control

Manage the Status Panel agent deployed on your target server. All commands communicate through the Stacker API using a **pull-based architecture** — the CLI enqueues commands, the agent polls for work, executes locally, and reports results.

Every command supports:
- `--json` — machine-readable JSON output
- `--deployment <HASH>` — target a specific deployment (auto-resolved if omitted)

**Deployment hash resolution order:** `--deployment` flag → `DeploymentLock` (from a previous deploy) → `stacker.yml` project identity → API lookup.

```bash
# Health & status
stacker agent health                              # Check agent connectivity
stacker agent health --app nginx                  # Health of a specific container
stacker agent status                              # Agent snapshot: containers, versions, uptime
stacker agent status --json                       # JSON output

# Logs
stacker agent logs my-app                         # Fetch container logs
stacker agent logs my-app --lines 200             # Last 200 lines
stacker agent logs my-app --json                  # JSON output

# Container lifecycle
stacker agent restart my-app                      # Restart a container
stacker agent deploy-app --app my-app --image myorg/myapp --tag v2.1
stacker agent remove-app --app my-app             # Remove container
stacker agent remove-app --app my-app --remove-volumes --remove-images

# Reverse proxy
# Managed Status Panel + Nginx Proxy Manager deploys auto-seed default Vault credentials.
# Update or repair those credentials with:
# stacker secrets set npm_credentials --scope server --server-id <server-id> --body-file ./npm_credentials.json
stacker agent configure-proxy --app my-app --domain app.example.com --ssl
stacker agent configure-proxy --app my-app --domain app.local --no-ssl

# History & raw commands
stacker agent history                             # Recent command history
stacker agent exec --command-type health          # Raw command
stacker agent exec --command-type stacker.exec --params '{"container":"app","command":"ls -la"}'

# Install Status Panel on an existing deployed server
stacker agent install                             # Remote install only; leaves local stacker.yml unchanged
stacker agent install --persist-config            # Also write monitoring.status_panel=true to local stacker.yml

# Target a specific deployment
stacker agent status --deployment abc123def
```

### AI-assisted agent control

The AI assistant can manage the agent via built-in tools:

```bash
# AI agent control in write mode
stacker ai ask --write "check if the agent is healthy"
stacker ai ask --write "show me the logs for the nginx container"
stacker ai ask --write "deploy app my-service with image myorg/myapp:latest"

# Interactive chat
stacker ai --write
> what's the status of the agent?
> restart the postgres container
```

### AI-assisted service addition

The AI assistant can also add services via the `add_service` tool:

```bash
# AI adds services using the template catalog
stacker ai ask --write "add wordpress and redis to my stack"
stacker ai ask --write "I need a postgres database with custom port 5433"

# Interactive chat mode
stacker ai --write
> add elasticsearch and kibana for logging
```

### Firewall Management

Stacker has two firewall surfaces:

| Command | Scope | Requires SSH/agent |
|---------|-------|--------------------|
| `stacker cloud firewall` | Cloud-provider firewall such as Hetzner Cloud Firewall | No SSH required |
| `stacker agent configure-firewall` | Guest OS firewall rules on the deployed server | Requires Status Panel agent |

#### Cloud provider firewall

Use `stacker cloud firewall` when a provider firewall blocks a public app port
after deployment. For example, Coolify publishes port `8000`, so this opens the
Hetzner Cloud Firewall without SSH-ing to the server:

```bash
stacker cloud firewall add --public-ports 8000/tcp
stacker cloud firewall add --server-id 42 --public-ports 8000/tcp
stacker cloud firewall remove --server-id 42 --public-ports 8000/tcp
stacker cloud firewall list --server-id 42
```

The CLI sends a provider-neutral `stacker.cloud_firewall.v1` message to Stacker
API. Stacker validates server/cloud ownership, hydrates cloud credentials
server-side, then publishes `install.firewall.{provider}.v1` to Install Service.
The CLI never receives cloud provider tokens.

Existing protocol note: the Status Panel agent schema already defines a
`FirewallPortRule` shape (`port`, `protocol`, `source`, `comment`) and cloud
deploy already sends `client_public_ports`/`ports_list` for initial provisioning.
Those are reused where appropriate, but `stacker.cloud_firewall.v1` is the
canonical post-deploy provider firewall protocol.

#### Guest OS firewall (iptables)

Stacker provides MCP tools for configuring iptables firewall rules on target servers. Rules can be derived from Ansible role port definitions or specified manually.

#### Execution Methods

| Method | Description | When to use |
|--------|-------------|-------------|
| **Status Panel** | Commands executed via Status Panel agent | Preferred — runs directly on target |
| **SSH** | Commands executed via SSH/Ansible | Fallback for servers without Status Panel |

#### Port Types

| Type | Source | Use case |
|------|--------|----------|
| **Public** | `0.0.0.0/0` (any IP) | HTTP, HTTPS, public APIs |
| **Private** | Specific CIDR | Databases, internal services |

#### MCP Tools

**`configure_firewall`** — Configure iptables rules on a deployment:

```json
{
  "deployment_hash": "abc123",
  "public_ports": [
    {"port": 80, "protocol": "tcp"},
    {"port": 443, "protocol": "tcp"}
  ],
  "private_ports": [
    {"port": 5432, "protocol": "tcp", "source": "10.0.0.0/8", "comment": "PostgreSQL"}
  ],
  "action": "add",
  "persist": true,
  "execution_method": "status_panel"
}
```

**`list_firewall_rules`** — List current iptables rules:

```json
{
  "deployment_hash": "abc123"
}
```

**`configure_firewall_from_role`** — Auto-configure from Ansible role:

```json
{
  "role_name": "postgres",
  "deployment_hash": "abc123",
  "action": "add",
  "private_network": "10.0.0.0/8"
}
```

#### Actions

| Action | Description |
|--------|-------------|
| `add` | Add firewall rules |
| `remove` | Remove firewall rules |
| `list` | List current rules |
| `flush` | Remove all rules |

#### AI-assisted firewall management

```bash
# Configure firewall via AI
stacker ai ask --write "open ports 80 and 443 publicly"
stacker ai ask --write "allow postgres port 5432 from internal network only"

# Interactive chat
stacker ai --write
> configure firewall to allow HTTP and HTTPS
> add private port 3306 for MySQL from 10.0.0.0/8
```

---

## Recipes

### Static website
```yaml
name: my-website
app:
  type: static
  path: ./dist
deploy:
  target: local
```

### Node.js API with PostgreSQL
```yaml
name: my-api
app:
  type: node
  path: .
services:
  - name: postgres
    image: postgres:16
    ports:
      - "5432:5432"
    environment:
      POSTGRES_DB: api_db
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    volumes:
      - pgdata:/var/lib/postgresql/data
deploy:
  target: local
env:
  DATABASE_URL: postgres://postgres:${DB_PASSWORD}@postgres:5432/api_db
```

### Python Django with Redis and Nginx
```yaml
name: django-app
app:
  type: python
  path: .
  build:
    args:
      DJANGO_SETTINGS_MODULE: myapp.settings.production
services:
  - name: redis
    image: redis:7-alpine
  - name: celery
    image: django-app:latest
    depends_on:
      - redis
    environment:
      CELERY_BROKER_URL: redis://redis:6379/0
proxy:
  type: nginx
  domains:
    - domain: myapp.example.com
      ssl: auto
      upstream: app:8000
deploy:
  target: cloud
  cloud:
    provider: hetzner
    region: fsn1
    size: cx23
    ssh_key: ~/.ssh/id_ed25519
```

### Rust API deployed to existing server
```yaml
name: rust-api
app:
  type: rust
  path: .
deploy:
  target: server
  server:
    host: api.example.com
    user: deploy
    ssh_key: ~/.ssh/deploy_key
monitoring:
  status_panel: true
  healthcheck:
    endpoint: /api/health
    interval: 15s
```

### Pre-built image (no source)
```yaml
name: wordpress-site
app:
  type: custom
  image: wordpress:6-apache
services:
  - name: mysql
    image: mysql:8
    environment:
      MYSQL_ROOT_PASSWORD: ${MYSQL_ROOT_PASSWORD}
      MYSQL_DATABASE: wordpress
    volumes:
      - db-data:/var/lib/mysql
proxy:
  type: nginx
  domains:
    - domain: blog.example.com
      ssl: auto
      upstream: app:80
deploy:
  target: local
```

### Multi-environment with interpolation
```yaml
name: ${APP_NAME}
version: ${APP_VERSION}
app:
  type: node
  build:
    args:
      NODE_ENV: ${NODE_ENV}
      API_URL: ${API_URL}
services:
  - name: postgres
    image: postgres:${PG_VERSION}
    environment:
      POSTGRES_PASSWORD: ${DB_PASSWORD}
deploy:
  target: ${DEPLOY_TARGET}
```

Run with different environments:
```bash
# Development
APP_NAME=myapp APP_VERSION=dev NODE_ENV=development \
  API_URL=http://localhost:3000 PG_VERSION=16 \
  DB_PASSWORD=devpass DEPLOY_TARGET=local \
  stacker deploy

# Production
APP_NAME=myapp APP_VERSION=1.2.3 NODE_ENV=production \
  API_URL=https://api.example.com PG_VERSION=16 \
  DB_PASSWORD=$PROD_DB_PASSWORD DEPLOY_TARGET=cloud \
  stacker deploy
```

---

## FAQ

**Q: Where are generated files stored?**
A: In the `.stacker/` directory. This includes `Dockerfile`, `docker-compose.yml`, and any proxy configuration. Add `.stacker/` to your `.gitignore`.

**Q: Can I edit the generated Dockerfile?**
A: Yes. After `stacker init` (or `stacker deploy --dry-run`), edit `.stacker/Dockerfile`, then `stacker deploy` to build from your modified version. Stacker reuses existing `.stacker/` files unless `--force-rebuild` is passed.

**Q: What if I already have a Dockerfile?**
A: Set `app.type: custom` and `app.dockerfile: ./Dockerfile`. Stacker will use yours instead of generating one.

**Q: Do I need Docker installed?**
A: Yes. Stacker requires Docker (with Compose v2) for local deployments. For cloud deployments, Docker is provisioned on the remote server automatically.

**Q: How do I keep secrets out of stacker.yml?**
A: Use environment variable interpolation (`${SECRET_VAR}`) and store actual values in `.env` (referenced via `env_file: .env`). Never commit `.env` to version control.

**Q: Can I use Stacker with an existing docker-compose.yml?**
A: Yes. Set `deploy.compose_file: ./docker-compose.yml` and Stacker will use it directly without generating a new one.

**Q: What cloud providers are supported?**
A: Hetzner, DigitalOcean, AWS, Linode, and Vultr. You must `stacker login` first and have the appropriate API keys configured in your TryDirect account.

---

## File Structure

After `stacker init`, your project will look like:

```
my-project/
├── stacker.yml              ← Your configuration (you write this)
├── .stacker/                ← Generated artifacts (auto-created)
│   ├── Dockerfile           ← Generated Dockerfile
│   └── docker-compose.yml   ← Generated compose definition
├── .env                     ← Secrets (optional, gitignored)
├── src/                     ← Your application source
└── scripts/                 ← Hook scripts (optional)
    ├── pre-build.sh
    ├── post-deploy.sh
    └── notify-failure.sh
```

---

*Stacker CLI is part of the [TryDirect](https://try.direct) platform.*
