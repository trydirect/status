# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added — Onboarding setup helpers

- Added `stacker config setup ai` to enable and update `ai.*` settings from the
  CLI, including Ollama-friendly `--provider`, `--endpoint`, `--model`,
  `--timeout`, and repeatable `--task` options.
- Cloud/server deploys now bootstrap missing `.env` files from adjacent
  `.env.example` files when compose or `stacker.yml` references them, using
  restrictive local permissions where supported.
- Cloud deploy `--key` and `--key-id` overrides are resolved through the active
  logged-in Stacker API before prompt selection, and non-interactive shells now
  receive actionable cloud credential guidance instead of hanging.
- Deploy validation now prints concise private registry credential guidance when
  images may require authentication and no registry auth is resolved.
- `stacker config validate` now points users to `stacker config fix` when it
  finds empty structural path fields.
- Cloud/server deploys now skip post-deploy server IP polling and local backup
  key installation after terminal paused/error statuses, avoiding repeated
  "server IP not yet assigned" retries after a failed installer run.
- Hetzner cloud deploys now normalize user-facing location aliases such as
  `nbg1` to installer-compatible datacenter values such as `nbg1-dc3` before
  publishing install-service payloads.
- `stacker config setup cloud` now suggests Hetzner `cx23` by default instead
  of older `cpx*` examples.
- Remote config bundles now keep compose `env_file` and bind-mount references
  project-relative so Docker Compose sees copied files under
  `/home/trydirect/project`.
- Cloud/server deploy output now lists config-bundle file mappings and rejects
  absolute config-bundle destinations before sending a deploy request.
- Deploy-time config files are now mirrored into the installer runtime-file
  contract so non-compose files such as `.env` are materialized before Docker
  Compose starts.

## [0.2.8] — 2026-05-15
### Added — Configuration inventory, diff, check, and promotion planning

- Added `stacker config inventory --env <name>` to list effective configuration
  keys by app/service target and source without printing secret values.
- Added `stacker config diff --from <env> --to <env>` to compare local
  environment/profile inventories and report missing, target-only, and changed
  keys.
- Added optional `config_contract` support in `stacker.yml` and
  `stacker config check --env <name> --strict` to fail when required keys are
  missing from an environment.
- Added `stacker config contract suggest --env <name>` to generate a
  reviewable `config_contract` snippet from the current inventory.
- Added `--remote` support for `config inventory`, `config diff`, and
  `config check`, enriching target inventories with remote service secret
  metadata without fetching plaintext Vault values.
- Added `stacker config promote --from <env> --to <env>` to generate safe
  target placeholders for missing keys; secret values are not copied.

### Added — App-only deploy environment selection

- Added `stacker env [environment]` to show or persist the active deploy
  environment/profile in `.stacker/active-env`.
- `stacker agent deploy-app` and `stacker secrets push` now accept
  `--env <environment>` / `--environment <environment>` for one-off environment
  selection during app-only updates.

### Fixed — App-local compose env files for deploy-app

- `stacker agent deploy-app <app>` now reads
  `<app>/docker/<env>/compose.yml` when that app-local compose file exists and
  merges that app's service definition into the full project-level compose,
  instead of replacing the remote stack compose with a single-service file.
- App-local deploys now bundle only the target app-local config files while
  using the project-level compose as topology, so missing env/config files for
  unrelated services no longer block `deploy-app <app>`.
- App-local `env_file` references are uploaded in the deploy-app config bundle,
  and Vault-rendered service secrets for the same target are merged into the
  matching remote `.env` file before the Status agent writes it.
- Deploy-app command creation now fails if Stacker cannot render the target's
  runtime env, instead of silently falling back to a stale/raw `.env` that may
  omit Vault-backed service secrets.
- `stacker agent deploy-app` and `stacker secrets push` now use the same
  server-side deploy-app enrichment path when enqueueing agent commands, so
  app-local `.env` files receive Vault-rendered service secrets during direct
  agent pushes as well as command-create flows.
- Missing config-bundle file errors now include the resolved path instead of a
  bare `No such file or directory` message.
- If an app-local `.env` exists but the selected compose service has no
  `env_file` entry, the CLI prints a warning explaining that Docker Compose will
  not inject local or remote-rendered env values into that container.

### Added — Canonical runtime environment rendering

- Remote runtime environment files now use the canonical host path
  `/home/trydirect/project/.env`; generated compose files reference it as
  `env_file: .env`.
- `stacker config show --resolved` prints the local env source path, canonical
  remote env path, compose env reference, config hash/version metadata, and
  contributing layers without printing secret values.
- Runtime env rendering now has deterministic precedence and hashing, rejects
  reserved `STACKER_*`, `DOCKER_*`, `VAULT_*`, and `AGENT_*` keys, and provides
  drift checks that require `--force` before overwriting changed remote env
  content.

### Fixed — Reuse private registry auth for agent-managed pulls

- Deploy-time `deploy.registry` credentials are now stored in trusted Stacker
  secret storage and reused for later Status-managed pulls such as
  `stacker agent deploy-app`.
- The Status agent now performs private-image pulls with a temporary
  `DOCKER_CONFIG` auth context and cleans it up immediately after the pull,
  instead of relying on host Docker login state.
- When no stored registry auth exists, pull behavior remains backward
  compatible: anonymous pull is attempted first and cached local images can
  still allow the redeploy to complete with warnings.

## [0.2.8] — 2026-05-12

### Added — Remote service/app target secrets

- `stacker secrets set --scope service --service <target>` now supports real
  deployable service/app targets, not only the main app code. Valid targets are
  discovered with `stacker secrets apps`.
- Stacker.yml `services:` entries are synced as service targets while the main
  `app:` remains the web target, so remote secrets can be scoped to support
  services such as `upload`, `worker`, or `postgres`.
- Image-backed services from `deploy.compose_file` are registered as service
  targets during cloud/server deploy preparation when they can be represented
  safely; build-only and platform-managed services are skipped with warnings.
- Service-scoped remote secrets remain isolated per target and are rendered only
  into the matching service; metadata APIs and CLI output still never return
  plaintext Vault values.
- CLI help and errors now use "deployable service/app target" wording and list
  available targets when an unknown service code is requested.

### Added — MCP remote service secret tools

- Added MCP tools for the remote service secret lifecycle:
  `list_remote_secret_targets`, `list_remote_service_secrets`,
  `get_remote_service_secret`, `set_remote_service_secret`, and
  `delete_remote_service_secret`.
- MCP remote secret reads are metadata-only, match the CLI/API target model, and
  write secret values directly to Vault without returning plaintext values.
- All MCP tool calls now require explicit per-tool Casbin `CALL` permission under
  `/mcp/tools/<tool_name>` before the handler executes; marketplace admin tools
  are granted only to `group_admin`.
- Sensitive MCP write/destructive operations, including remote secret writes and
  deletes, additionally require a token or auth profile with verified 2FA/MFA
  before Vault or deployment state is touched.

### Added — Cloud provider firewall operations

- Added `stacker cloud firewall add|remove|list` for cloud-provider firewall
  changes that do not require SSH access to the server.
- Added universal Stacker-to-Install-Service protocol
  `stacker.cloud_firewall.v1` with shared firewall rule parsing reused from the
  existing agent firewall flow.
- Added `POST /server/{id}/cloud-firewall` and Install Service MQ routing
  `install.firewall.{provider}.v1`; Hetzner (`htz`) is the first supported
  provider.
- Casbin/sqlx migration `20260717120016_casbin_cloud_firewall` grants
  `root`, `group_admin`, and `group_user` access to modify cloud firewalls.

### Added — Cloud deploy local SSH backup access

- `stacker deploy --target cloud` now creates or reuses a local Ed25519 backup
  key under the Stacker config directory and authorizes it on the deployed
  server when possible.
- New server API endpoint `POST /server/{id}/ssh-key/authorize-public-key`
  accepts caller-provided public key material, validates ownership and key
  format, then uses the server-side Vault key to append it to
  `authorized_keys` idempotently.
- The Vault private key is never returned to the CLI or written to local files;
  the CLI sends only the local public key and prints a copy-paste-ready `ssh`
  command after successful authorization.
- `stacker ssh-key inject` remains the repair path for using an
  already-working private key to re-add the Vault public key to a server.
- Casbin/sqlx migration `20260717120014_casbin_server_ssh_authorize_public_key`
  grants `group_user` and `root` access to the new authorization endpoint.

### Fixed — Managed Nginx Proxy Manager duplication

- Cloud/server project bodies no longer add `nginx_proxy_manager` as a project
  app when proxy support is already managed through `extended_features`.
- User-declared `nginx_proxy_manager` / NPM services are skipped from project app
  sync when `proxy.type` is `nginx` or `nginx-proxy-manager`, preventing the
  duplicate `project-nginx_proxy_manager-*` container alongside the managed NPM
  container.
- Server-side project app sync, compose child-service discovery, agent snapshots,
  and deploy-app upserts now treat NPM as platform-managed so older clients or
  stale records cannot keep re-registering it as a user app.
- Data migration `20260717120015_cleanup_nginx_proxy_manager_project_apps`
  removes existing stale `nginx_proxy_manager` project app rows that caused NPM
  to remain visible after upgrading.
- `stacker agent status` hides stale project-scoped platform containers such as
  `project-nginx_proxy_manager-*` while still showing the managed
  `nginx-proxy-manager` container.

### Fixed — Compose public ports in cloud firewall

- Cloud/server deploy now reads published ports from the resolved Compose file
  and passes them into project metadata before invoking the installer, so
  provider firewalls receive app ports such as Coolify's `8000:8080` instead of
  the generic custom-app fallback `8080`.

### Fixed — Deployment IP persistence on paused/failed installs

- Cloud/server deploy status handling now extracts a server IP from installer
  progress messages such as `178.104.222.170: Copy files is done` when the
  structured server record has not populated `srv_ip` yet.
- The CLI saves that fallback IP into the local deployment context, and the MQ
  listener persists the IP server-side so paused or failed deployments still
  retain a usable host address for SSH repair and retry workflows.

### Changed — Agent proxy SSL control

- `stacker agent configure-proxy` now supports `--no-ssl` to create or update a
  plain HTTP Nginx Proxy Manager host without requesting a Let's Encrypt
  certificate.

### Changed — Server bootstrap SSH key handling

- `stacker deploy --target server` now treats a user-provided `deploy.server.ssh_key` as a
  **transient bootstrap credential** for first SSH contact only.
- Stacker now persists only a **Stacker-managed generated deploy key** in Vault for ongoing
  server-side automation and later redeploys.
- The user-provided bootstrap key is still sent for the live bootstrap run, but it is no longer
  stored as the server's long-term key material on the Stacker side.

### Added — Local Pipe Mode

- **`stacker target [local|cloud|server]`** — switch deployment target mode; persists in `.stacker/active-target`
- **Local pipe creation** — `stacker pipe create` works without a cloud deployment (`deployment_hash` is now optional, `is_local` flag on PipeInstance/PipeExecution)
- **Local scanning** — `stacker pipe scan` now performs local endpoint/resource discovery on matched containers instead of only listing Docker inventory
- **Explicit scan modes** — `stacker pipe scan --containers [FILTER]` for local container discovery + probing and `stacker pipe scan --app <APP> [--container <NAME>]` for remote endpoint probing
- **Local triggering** — `stacker pipe trigger` executes via `docker exec` / HTTP against local containers
- **`stacker pipe deploy <id> --deployment <hash>`** — promote a local pipe to a remote deployment (clones config to new remote instance)
- **`GET /api/v1/pipes/instances/local`** — list local pipe instances for the authenticated user
- **`POST /api/v1/pipes/instances/{id}/deploy`** — deploy (promote) local pipe to remote
- **`stacker init --target local`** — initialize project in local mode directly
- Database migration: `deployment_hash` nullable, `is_local BOOLEAN DEFAULT FALSE`, partial index on local instances

### Added — Canonical runtime environment rendering

- Remote runtime environment files now use the canonical host path
  `/home/trydirect/project/.env`; generated compose files reference it as
  `env_file: .env`.
- `stacker config show --resolved` prints the local env source path, canonical
  remote env path, compose env reference, config hash/version metadata, and
  contributing layers without printing secret values.
- Runtime env rendering now has deterministic precedence and hashing, rejects
  reserved `STACKER_*`, `DOCKER_*`, `VAULT_*`, and `AGENT_*` keys, and provides
  drift checks that require `--force` before overwriting changed remote env
  content.

### Fixed — App-local compose env files for deploy-app

- `stacker agent deploy-app <app>` now reads
  `<app>/docker/<env>/compose.yml` when that app-local compose file exists and
  merges that app's service definition into the full project-level compose,
  instead of replacing the remote stack compose with a single-service file.
- App-local deploys now bundle only the target app-local config files while
  using the project-level compose as topology, so missing env/config files for
  unrelated services no longer block `deploy-app <app>`.
- Deploy-app now preserves the shared project `.env` in the config bundle when
  the selected runtime topology uses root `env_file: .env`.
- App-local `env_file` references are uploaded in the deploy-app config bundle,
  and Vault-rendered service secrets for the same target are merged into the
  matching remote `.env` file before the Status agent writes it.
- Deploy-app command creation now fails if Stacker cannot render the target's
  runtime env, instead of silently falling back to a stale/raw `.env` that may
  omit Vault-backed service secrets.
- Missing config-bundle file errors now include the resolved path instead of a
  bare `No such file or directory` message.
- If an app-local `.env` exists but the selected compose service has no
  `env_file` entry, the CLI prints a warning explaining that Docker Compose will
  not inject local or remote-rendered env values into that container.

### Fixed — Reuse private registry auth for agent-managed pulls

- Deploy-time `deploy.registry` credentials are now stored in trusted Stacker
  secret storage and reused for later Status-managed pulls such as
  `stacker agent deploy-app`.
- The Status agent now performs private-image pulls with a temporary
  `DOCKER_CONFIG` auth context and cleans it up immediately after the pull,
  instead of relying on host Docker login state.
- When no stored registry auth exists, pull behavior remains backward
  compatible: anonymous pull is attempted first and cached local images can
  still allow the redeploy to complete with warnings.

## [0.2.7] — 2026-04-10

### Security — IDOR Hardening & Test Coverage

- **69 IDOR security integration tests** across 12 test files (`tests/security_*.rs`) covering every API endpoint
- **18 CLI endpoint security tests** (`tests/security_cli.rs`) — verify `stacker list`, `deploy`, `destroy` honor user boundaries
- **Defense-in-depth**: `user_id` parameter added to `project::delete`, `project::fetch_one_by_name`, `cloud::delete`, `server::delete` DB functions
- **Cross-user isolation**: all list endpoints (projects, clouds, servers, deployments, commands, pipes, clients, chats, ratings) return only the authenticated user's resources
- **Credential logging hardened**: sensitive cloud tokens and secrets no longer printed to server logs

### Added — Pipe Feature Phase 1 (Container Linking)

- `stacker pipe list` — query and display pipe instances for a deployment (status, triggers, errors, last triggered)
- `stacker pipe create <source> <target>` — interactive flow: scan both apps via agent, pick endpoints, auto-match fields by name, create template + instance via API
- `stacker pipe activate <id>` — set pipe to active, send `activate_pipe` agent command with full config (endpoints, field mapping, trigger type, poll interval)
- `stacker pipe deactivate <id>` — pause pipe, send `deactivate_pipe` agent command
- `stacker pipe trigger <id>` — one-shot pipe execution with optional `--data` JSON input
- `PUT /api/v1/pipes/instances/{id}/status` — new REST endpoint for pipe status updates
- Agent command types: `activate_pipe`, `deactivate_pipe`, `trigger_pipe` with full parameter/result validation (9 unit tests)
- 6 new client methods + 4 API request/response structs in `stacker_client.rs`

### Fixed — Per-Target Deployment Lock Files

- Deployment lock files are now namespaced by target: `.stacker/<target>.lock` (e.g. `local.lock`, `cloud.lock`, `server.lock`)
- Local deploys no longer overwrite cloud/server connection details
- Existing `deployment.lock` files automatically migrated on read

## [0.2.6] — 2026-04-08

### Added — Kata Containers Runtime Support

- `runtime` field on `deploy_app` and `deploy_with_configs` agent commands — values: `runc` (default), `kata`
- Server-side validation rejects unknown runtime values with HTTP 422
- Kata capability gating: agent `/capabilities` response checked before scheduling Kata deployments; agents without `kata` feature receive 422 rejection
- `--runtime kata|runc` flag on `stacker deploy` and `stacker agent deploy-app` CLI commands
- Database migration `20260406170000`: `runtime` column added to `deployment` table, persisted across redeploys
- Vault integration: per-deployment runtime preference (`store_runtime_preference` / `fetch_runtime_preference`) and org-level runtime policy (`fetch_org_runtime_policy`)
- Compose template support: `runtime:` field conditionally emitted in generated `docker-compose.yml` when runtime is not `runc` (both Tera and CLI generators)
- Enhanced tracing: `runtime` field added to `Agent enqueue command` span for structured log filtering
- Documentation: `docs/kata/` — setup guide, network constraints, monitoring/observability reference
- Provisioning: Ansible role and Terraform module for Hetzner dedicated-CPU (CCX) servers with KVM/Kata pre-configured (integrated into TFA)

### Fixed — Casbin ACL for marketplace compose access
- Added Casbin policy granting `group_admin` role GET access to `/admin/project/:id/compose`.
- This allows the User Service OAuth client (which authenticates as `root` → `group_admin`) to fetch compose definitions for marketplace templates.
- Migration: `20260325140000_casbin_admin_compose_group_admin.up.sql`

### Added — Agent Audit Ingest Endpoint and Query API

- New database migration `20260321000000_agent_audit_log` creating the `agent_audit_log` table
- `POST /api/v1/agent/audit` — receives audit event batches from the Status Panel
- `GET /api/v1/agent/audit` — queries the audit log with optional filters

### Added — Pipe (Container Linking) Foundation

- New `stacker pipe scan|create|list` CLI subcommands for connecting containerized apps
- `ProbeEndpoints` agent command: auto-discovers OpenAPI, HTML forms, REST endpoints on containers
- Two-level storage: `pipe_templates` (reusable) + `pipe_instances` (per-deployment)
- REST API: `POST/GET/DELETE /api/v1/pipes/templates` and `/instances`
- Data contracts with validation for probe_endpoints command parameters and results

### Added — Marketplace Developer & Buyer Flows

- New `stacker submit` command — packages the current stack and submits to marketplace for review
- New `stacker marketplace status [name]` — shows developer submissions with status badges
- New `stacker marketplace logs <name>` — shows review history
- Auto-publish on approval

### Added — Buyer Install Endpoints (Server)

- `GET /api/v1/marketplace/install/{purchase_token}` — generates install script
- `GET /api/v1/marketplace/download/{purchase_token}` — serves stack archive
- `POST /api/v1/marketplace/agents/register` — agent self-registration endpoint

## [0.2.6] — 2026-03-11

### Added — Firewall (iptables) Management

- New MCP tools for configuring iptables firewall rules on remote servers:
  - `configure_firewall` — Add, remove, list, or flush iptables rules with public/private port definitions
  - `list_firewall_rules` — List current iptables rules on a deployment target server
  - `configure_firewall_from_role` — Auto-configure firewall rules from Ansible role port definitions
- Two execution methods:
  - **Status Panel** (preferred): Commands executed via the Status Panel agent directly on the target server
  - **SSH**: Fallback for servers without Status Panel agent (uses Ansible-based execution)
- Port rule types:
  - **Public ports**: Opened to all IPs (0.0.0.0/0) — use for HTTP, HTTPS, public APIs
  - **Private ports**: Restricted to specific IPs/CIDRs — use for databases, internal services
- Integration with Ansible roles: Automatically extracts `public_ports` and `private_ports` from role configuration
- Rules can be persisted across reboots via the `persist` parameter

### Added — Status Panel `configure_firewall` command type

- New `configure_firewall` command type for Status Panel agents
- Validates action (add, remove, list, flush), port numbers, and protocols (tcp/udp)
- Supports optional comments for rule documentation

## [0.2.5] — 2026-03-07

### Added — Agent control from the CLI (`stacker agent`)

- New `stacker agent` subcommand with 9 commands for remote Status Panel agent management:
  - `stacker agent health [--app NAME]` — check agent connectivity / container health
  - `stacker agent logs <app> [--lines N]` — retrieve container logs from the target server
  - `stacker agent restart <app>` — restart a container via the agent
  - `stacker agent deploy-app --app NAME --image IMAGE [--tag TAG]` — deploy or update an app container
  - `stacker agent remove-app --app NAME [--remove-volumes] [--remove-images]` — remove an app container with optional cleanup
  - `stacker agent configure-proxy --app NAME --domain DOMAIN [--ssl]` — configure Nginx Proxy Manager
  - `stacker agent status` — display agent snapshot (containers, versions, uptime)
  - `stacker agent history` — show recent command execution history
  - `stacker agent exec --command-type TYPE [--params JSON]` — execute a raw agent command
- All commands support `--json` for machine-readable output and `--deployment <hash>` to target a specific deployment
- Smart deployment hash resolution: explicit flag → DeploymentLock → stacker.yml project identity → API lookup
- Spinner-based UX with configurable timeout while waiting for agent results

### Added — Infrastructure helpers

- `CliRuntime` (`src/cli/runtime.rs`) — eliminates ~15 lines of credentials + tokio runtime + client boilerplate per CLI command
- `fmt` module (`src/cli/fmt.rs`) — shared terminal formatting helpers: `truncate()`, `separator()`, `pretty_json()`, `display_opt()`
- `AgentEnqueueRequest` — builder pattern with `with_parameters()`, `with_priority()`, `with_timeout()`
- `AgentCommandInfo` — response type for agent command status and results
- StackerClient: added `agent_enqueue()`, `agent_command_status()`, `agent_poll_result()`, `agent_snapshot()` API methods
- 4 new agent error variants: `AgentNotFound`, `AgentOffline`, `AgentCommandTimeout`, `AgentCommandFailed`

### Added — MCP agent control tools

- `deploy_app` — deploy or update an app container via the Status Panel agent
- `remove_app` — remove an app container with optional volume/image cleanup
- `configure_proxy_agent` — configure Nginx Proxy Manager reverse-proxy entries
- `get_agent_status` — check agent registration, version, and last heartbeat

### Added — AI agent tools

- 3 new AI tool definitions: `agent_health`, `agent_status`, `agent_logs`
- Wired into `execute_tool()` via subprocess dispatch (`stacker agent ... --json`)
- Available in `stacker ai ask --write` and interactive chat modes
## [Unreleased] — 2026-03-04

### Fixed
- **Agent registration 403**: added Casbin migration `20260304220000_fix_casbin_agent_register_anon` that idempotently grants `group_anonymous` the right to `POST /api/v1/agent/register`. Ansible-driven deployments (statuspanel, etc.) call this endpoint without an Authorization header; without this policy the Casbin middleware returns 403.

## [0.2.4] — 2026-02-27

### Added — SSH key management (`stacker ssh-key`)

- New `stacker ssh-key generate --server-id N` command — generates a Vault-backed SSH key pair for a server; optional `--save-to PATH` to save the private key locally
- New `stacker ssh-key show --server-id N` command — displays the public SSH key (`--json` for machine-readable output)
- New `stacker ssh-key upload --server-id N --public-key FILE --private-key FILE` — uploads an existing SSH key pair to the server
- StackerClient: added `generate_ssh_key()`, `get_ssh_public_key()`, `upload_ssh_key()` API methods

### Added — Service template catalog (`stacker service`)

- New `stacker service add <name>` command — resolves a service template and appends it to `stacker.yml`
  - 20+ built-in templates: postgres, mysql, mongodb, redis, memcached, rabbitmq, traefik, nginx, nginx_proxy_manager, wordpress, elasticsearch, kibana, qdrant, telegraf, phpmyadmin, mailhog, minio, portainer
  - Alias support: `wp`→wordpress, `pg`→postgres, `my`→mysql, `mongo`→mongodb, `es`→elasticsearch, `mq`→rabbitmq, `pma`→phpmyadmin, `mh`→mailhog
  - Auto-adds dependencies (e.g. `wordpress` pulls in `mysql` if missing)
  - Creates `.yml.bak` backup before modifying, checks for duplicate services
  - Falls back to offline catalog if marketplace API is unreachable
- New `stacker service list [--online]` — shows available service templates grouped by category

### Added — AI `add_service` tool (write mode)

- In `stacker ai ask --write` and `stacker ai` (chat), the AI can now call `add_service` to add services from the built-in catalog to `stacker.yml`
- The AI system prompt is enriched with the full service catalog so it knows what templates are available
- Supports custom overrides: `custom_ports` and `custom_env` parameters on the tool call
- Example: `stacker ai ask --write "add postgres and redis to my stack"`

### Added — Marketplace template API methods

- StackerClient: added `list_marketplace_templates()` and `get_marketplace_template(slug)` for fetching templates from the Stacker server marketplace

## [0.2.3] — 2026-02-23

### Changed — `stacker init` now generates `.stacker/` directory

- `stacker init` now creates `.stacker/Dockerfile` and `.stacker/docker-compose.yml` alongside `stacker.yml`, so the project is ready to deploy immediately without running `deploy --dry-run` first
- Dockerfile generation is skipped when `app.image` or `app.dockerfile` is set in the config
- Compose generation is skipped when `deploy.compose_file` is set

### Changed — `stacker deploy` reuses existing `.stacker/` artifacts

- `deploy` no longer errors when `.stacker/Dockerfile` or `.stacker/docker-compose.yml` already exist (e.g. from `stacker init`)
- Existing artifacts are reused; pass `--force-rebuild` to regenerate them

### Added — `--ai-provider`, `--ai-model`, `--ai-api-key` flags on `stacker-cli init`

- The `stacker-cli` binary (`console/main.rs`) now supports all AI-related flags that the standalone `stacker` binary already had:
  - `--ai-provider <PROVIDER>` — openai, anthropic, ollama, custom
  - `--ai-model <MODEL>` — e.g. `qwen2.5-coder`, `deepseek-r1`, `gpt-4o`
  - `--ai-api-key <KEY>` — API key for cloud AI providers

### Added — AI troubleshooting suggestions on deploy failures

- On `stacker deploy` failures (`DeployFailed`), CLI now attempts AI-assisted troubleshooting automatically
- It sends the deploy error plus generated `.stacker/Dockerfile` and `.stacker/docker-compose.yml` snippets to the configured AI provider
- If AI is unavailable or not configured, CLI prints deterministic fallback hints for common issues (for example `npm ci` failures, obsolete compose `version`, missing files, permissions, and network timeouts)

### Fixed

- `stacker-cli init --with-ai --ai-model qwen2.5-coder` no longer fails with an unrecognised flag error
- `stacker deploy` after `stacker init` no longer fails with `DockerfileExists` error

## 2026-02-23

### Added - Configurable AI Request Timeout

- New `timeout` field in `ai` config section of `stacker.yml` (default: 300 seconds)
- `STACKER_AI_TIMEOUT` environment variable overrides the config value
- Timeout applies to all AI providers (OpenAI, Anthropic, Ollama, Custom)
- Useful for large models on slower hardware: `STACKER_AI_TIMEOUT=900 stacker init --with-ai`
- Example stacker.yml:
  ```yaml
  ai:
    enabled: true
    provider: ollama
    model: deepseek-r1
    timeout: 600  # 10 minutes
  ```
- 9 new tests for timeout resolution

### Added - Stacker CLI: AI-Powered Project Initialization

#### AI Scanner Module (`src/cli/ai_scanner.rs`)
- New `scan_project()` function performs deep project scanning, reading key config files (`package.json`, `requirements.txt`, `Cargo.toml`, `Dockerfile`, `docker-compose.yml`, `.env`, etc.) to build rich context for AI generation
- `build_generation_prompt()` constructs detailed prompts including detected app type, file contents, existing infrastructure, and env var keys (values redacted for security)
- `generate_config_with_ai()` sends project context to the configured AI provider and returns a tailored `stacker.yml`
- `strip_code_fences()` strips markdown code fences from AI responses
- System prompt encodes the full `stacker.yml` schema so the AI generates valid, deployable configs
- 16 unit tests

#### AI-Powered `stacker init --with-ai` (`src/console/commands/cli/init.rs`)
- `stacker init --with-ai` now scans the project and calls the AI to generate a tailored `stacker.yml` with appropriate services, proxy, monitoring, and hooks
- New CLI flags on `stacker init`:
  - `--ai-provider <PROVIDER>` — AI provider: `openai`, `anthropic`, `ollama`, `custom` (default: `ollama`)
  - `--ai-model <MODEL>` — Model name (e.g. `gpt-4o`, `claude-sonnet-4-20250514`, `llama3`)
  - `--ai-api-key <KEY>` — API key (or use environment variables)
- `resolve_ai_config()` resolves AI configuration with priority: CLI flag → environment variable → defaults
- Environment variable support: `STACKER_AI_PROVIDER`, `STACKER_AI_MODEL`, `STACKER_AI_API_KEY`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`
- Graceful fallback: if AI generation fails (provider unreachable, invalid YAML), automatically falls back to template-based generation
- AI-generated configs include a review header noting the provider and model used
- If AI output fails validation, raw draft is saved to `stacker.yml.ai-draft` for manual review
- 8 new unit tests (18 total in init.rs), 3 new integration tests (11 total in cli_init.rs)

#### Usage Examples
```bash
# AI-powered init with local Ollama
stacker init --with-ai

# AI-powered init with OpenAI
stacker init --with-ai --ai-provider openai --ai-api-key sk-...

# AI-powered init with Anthropic (key from env)
export ANTHROPIC_API_KEY=sk-ant-...
stacker init --with-ai --ai-provider anthropic

# Falls back to template if AI fails
stacker init --with-ai  # no Ollama running → template fallback
```

### Test Results
- **467 tests** (426 unit + 41 integration), 0 failures

## 2026-02-18

### Fixed
- **Container Discovery 403**: Fixed Casbin authorization rules for `/project/:id/containers/discover` (GET) and `/project/:id/containers/import` (POST)
  - Migration `20260204120000_casbin_container_discovery_rules` had wrong path prefix `/api/v1/project/...` instead of `/project/...`
  - The middleware was rejecting the request with a 403 before CORS headers could be attached, causing the browser to report a misleading "CORS header missing" error
  - New migration `20260218100000_fix_casbin_container_discovery_paths` removes the wrong rules and inserts the correct paths

## 2026-02-03

### Fixed
- **API Performance**: Fixed 1MB+ response size issue in deployment endpoints
  - **Snapshot endpoint** `/api/v1/agent/deployments/{deployment_hash}`:
    - Added `command_limit` query parameter (default: 50) to limit number of commands returned
    - Added `include_command_results` query parameter (default: false) to exclude large log results
    - Example: `GET /api/v1/agent/deployments/{id}?command_limit=20&include_command_results=true`
  - **Commands list endpoint** `/api/v1/commands/{deployment_hash}`:
    - Added `include_results` query parameter (default: false) to exclude large result/error fields
    - Added `limit` parameter enforcement (default: 50, max: 500)
    - Example: `GET /api/v1/commands/{id}?limit=50&include_results=true`
  - Created `fetch_recent_by_deployment()` in `db::command` for efficient queries
  - Browser truncation issue resolved when viewing status_panel container logs
  
### Changed
- **Frontend**: Updated `fetchStatusPanelCommandsFeed` to explicitly request `include_results=true` (blog/src/helpers/status/statusPanel.js)

## 2026-02-02

### Added - Advanced Monitoring & Troubleshooting MCP Tools (Phase 7)

#### New MCP Tools (`src/mcp/tools/monitoring.rs`)
- `GetDockerComposeYamlTool`: Fetch docker-compose.yml from Vault for a deployment
  - Parameters: deployment_hash
  - Retrieves `_compose` key from Vault KV path
  - Returns compose content or meaningful error if not found

- `GetServerResourcesTool`: Collect server resource metrics from agent
  - Parameters: deployment_hash, include_disk, include_network, include_processes
  - Queues `stacker.server_resources` command to Status Panel agent
  - Returns command_id for async result polling
  - Uses existing command queue infrastructure

- `GetContainerExecTool`: Execute commands inside running containers
  - Parameters: deployment_hash, app_code, command, timeout (1-120s)
  - **Security**: Blocks dangerous commands at MCP level before agent dispatch
  - Blocked patterns: `rm -rf /`, `mkfs`, `dd if`, `shutdown`, `reboot`, `poweroff`, `halt`, `init 0`, `init 6`, fork bombs, `:()`
  - Case-insensitive pattern matching
  - Queues `stacker.exec` command to agent with security-approved commands only
  - Returns command_id for async result polling

#### Registry Updates (`src/mcp/registry.rs`)
- Added Phase 7 imports and registration for all 3 new monitoring tools
- Total MCP tools now: 48+

### Fixed - CRITICAL: .env config file content not saved to project_app.environment

#### Bug Fix: User-edited .env files were not parsed into project_app.environment
- **Issue**: When users edited the `.env` file in the Config Files tab (instead of using the Environment form fields), the `params.env` was empty `{}`. The `.env` file content was stored in `config_files` but never parsed into `project_app.environment`, causing deployed apps to not receive user-configured environment variables.
- **Root Cause**: `ProjectAppPostArgs::from()` in `mapping.rs` only looked at `params.env`, not at `.env` file content in `config_files`.
- **Fix**:
  1. Added `parse_env_file_content()` function to parse `.env` file content
  2. Supports both `KEY=value` (standard) and `KEY: value` (YAML-like) formats
  3. Modified `ProjectAppPostArgs::from()` to extract and parse `.env` file from `config_files`
  4. If `params.env` is empty, use parsed `.env` values for `project_app.environment`
  5. `params.env` (form fields) takes precedence if non-empty
- **Files Changed**: `src/project_app/mapping.rs`
- **Tests Added**: 
  - `test_env_config_file_parsed_into_environment`
  - `test_env_config_file_standard_format`
  - `test_params_env_takes_precedence`
  - `test_empty_env_file_ignored`

## 2026-01-29

### Added - Unified Configuration Management System

#### ConfigRenderer Service (`src/services/config_renderer.rs`)
- New `ConfigRenderer` service that converts `ProjectApp` records to deployable configuration files
- Tera template engine integration for rendering docker-compose.yml and .env files
- Embedded templates: `docker-compose.yml.tera`, `env.tera`, `service.tera`
- Support for multiple input formats: JSON object, JSON array, string (docker-compose style)
- Automatic Vault sync via `sync_to_vault()` and `sync_app_to_vault()` methods

#### ProjectAppService (`src/services/project_app_service.rs`)
- High-level service wrapping database operations with automatic Vault sync
- Create/Update/Delete operations trigger config rendering and Vault storage
- `sync_all_to_vault()` for bulk deployment sync
- `preview_bundle()` for config preview without syncing
- Validation for app code format, required fields

#### Config Versioning (`project_app` table)
- New columns: `config_version`, `vault_synced_at`, `vault_sync_version`, `config_hash`
- `needs_vault_sync()` method to detect out-of-sync configs
- `increment_version()` and `mark_synced()` helper methods
- Migration: `20260129120000_add_config_versioning`

#### Dependencies
- Added `tera = "1.19.1"` for template rendering

## 2026-01-26

### Fixed - Deployment Hash Not Sent to Install Service

#### Bug Fix: `saved_item()` endpoint missing `deployment_hash` in RabbitMQ payload
- **Issue**: The `POST /{id}/deploy/{cloud_id}` endpoint (for deployments with saved cloud credentials) was generating a `deployment_hash` and saving it to the database, but NOT including it in the RabbitMQ message payload sent to the install service.
- **Root Cause**: In `src/routes/project/deploy.rs`, the `saved_item()` function published the payload without setting `payload.deployment_hash`, unlike the `item()` function which correctly delegates to `InstallServiceClient.deploy()`.
- **Fix**: Added `payload.deployment_hash = Some(deployment_hash.clone())` before publishing to RabbitMQ.
- **Files Changed**: `src/routes/project/deploy.rs`

## 2026-01-24

### Added - App Configuration Editor (Backend)

#### Project App Model & Database (`project_app`)
- New `ProjectApp` model with fields: environment (JSONB), ports (JSONB), volumes, domain, ssl_enabled, resources, restart_policy, command, entrypoint, networks, depends_on, healthcheck, labels, enabled, deploy_order
- Database CRUD operations in `src/db/project_app.rs`: fetch, insert, update, delete, fetch_by_project_and_code
- Migration `20260122120000_create_project_app_table` with indexes and triggers

#### REST API Routes (`/project/{id}/apps/*`)
- `GET /project/{id}/apps` - List all apps for a project
- `GET /project/{id}/apps/{code}` - Get single app details
- `DELETE /project/{id}/apps/{code}` - Delete a saved app from a project
- `GET /project/{id}/apps/{code}/config` - Get full app configuration
- `GET /project/{id}/apps/{code}/env` - Get environment variables (sensitive values redacted)
- `PUT /project/{id}/apps/{code}/env` - Update environment variables
- `PUT /project/{id}/apps/{code}/ports` - Update port mappings
- `PUT /project/{id}/apps/{code}/domain` - Update domain/SSL settings

#### Support Documentation
- Added `docs/SUPPORT_ESCALATION_GUIDE.md` - AI support escalation handling for support team

### Fixed - MCP Tools Type Errors
- Fixed type comparison errors in `compose.rs` and `config.rs`:
  - `project.user_id` is `String` (not `Option<String>`) - use direct comparison
  - `deployment.user_id` is `Option<String>` - use `as_deref()` for comparison
  - `app.code` and `app.image` are `String` (not `Option<String>`)
  - Replaced non-existent `cpu_limit`/`memory_limit` fields with `resources` JSONB

## 2026-01-23

### Added - Vault Configuration Management

#### Vault Configuration Tools (Phase 5 continuation)
- `get_vault_config`: Fetch app configuration from HashiCorp Vault by deployment hash and app code
- `set_vault_config`: Store app configuration in Vault (content, content_type, destination_path, file_mode)
- `list_vault_configs`: List all app configurations stored in Vault for a deployment
- `apply_vault_config`: Queue apply_config command to Status Panel agent for config deployment

#### VaultService (`src/services/vault_service.rs`)
- New service for Vault KV v2 API integration
- Path template: `{prefix}/{deployment_hash}/apps/{app_name}/config`
- Methods: `fetch_app_config()`, `store_app_config()`, `list_app_configs()`, `delete_app_config()`
- Environment config: `VAULT_ADDRESS`, `VAULT_TOKEN`, `VAULT_AGENT_PATH_PREFIX`

### Changed
- Updated `src/services/mod.rs` to export `VaultService`, `AppConfig`, `VaultError`
- Updated `src/mcp/registry.rs` to register 4 new Vault config tools (total: 41 tools)

## 2026-01-22

### Added - Phase 5: Agent-Based App Deployment & Configuration Management

#### Container Operations Tools
- `stop_container`: Gracefully stop a specific container in a deployment with configurable timeout
- `start_container`: Start a previously stopped container
- `get_error_summary`: Analyze container logs and return categorized error counts, patterns, and suggestions

#### App Configuration Management Tools (new `config.rs` module)
- `get_app_env_vars`: View environment variables for an app (with automatic redaction of sensitive values)
- `set_app_env_var`: Create or update an environment variable
- `delete_app_env_var`: Remove an environment variable
- `get_app_config`: Get full app configuration including ports, volumes, domain, SSL, and resource limits
- `update_app_ports`: Configure port mappings for an app
- `update_app_domain`: Set domain and SSL configuration for web apps

#### Stack Validation Tool
- `validate_stack_config`: Pre-deployment validation checking for missing images, port conflicts, database passwords, and common misconfigurations

#### Integration Testing & Documentation
- Added `stacker/tests/mcp_integration.rs`: Comprehensive User Service integration tests
- Added `stacker/docs/SLACK_WEBHOOK_SETUP.md`: Production Slack webhook configuration guide
- Added new environment variables to `env.dist`: `SLACK_SUPPORT_WEBHOOK_URL`, `TAWK_TO_*`, `USER_SERVICE_URL`

### Changed
- Updated `stacker/src/mcp/tools/mod.rs` to export new `config` module
- Updated `stacker/src/mcp/registry.rs` to register 10 new MCP tools (total: 37 tools)
- Updated AI-INTEGRATION-PLAN.md with Phase 5 implementation status and test documentation

## 2026-01-06

### Added
- Real HTTP-mocked tests for `UserServiceClient` covering user profile retrieval, product lookups, and template ownership checks.
- Integration-style webhook tests that verify the payloads emitted by `MarketplaceWebhookSender` for approved, updated, and rejected templates.
- Deployment validation tests ensuring plan gating and marketplace ownership logic behave correctly for free, paid, and plan-restricted templates.

## 2026-01-16

### Added
- Configurable agent command polling defaults via config and environment variables.
- Configurable Casbin reload enablement and interval.

### Changed
- OAuth token validation uses a shared HTTP client and short-lived cache for reduced latency.
- Agent command polling endpoint accepts optional `timeout` and `interval` parameters.
- Casbin reload is guarded to avoid blocking request handling and re-applies route matching after reload.

### Fixed
- Status panel command updates query uses explicit bindings to avoid SQLx type inference errors.
