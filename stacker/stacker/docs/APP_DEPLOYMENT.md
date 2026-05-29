# App Configuration Deployment Strategy (Stacker)

This document outlines the configuration management strategy for Stacker, covering how app configurations flow from the UI through Stacker's database to Vault and ultimately to Status Panel agents on deployed servers.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           Configuration Flow                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌────────────┐ │
│  │   Frontend   │───▶│   Stacker    │───▶│    Vault     │───▶│   Status   │ │
│  │  (Next.js)   │    │   (Rust)     │    │  (HashiCorp) │    │   Panel    │ │
│  └──────────────┘    └──────────────┘    └──────────────┘    └────────────┘ │
│        │                    │                   │                   │        │
│        │ AddAppDeployment   │ ConfigRenderer    │ KV v2 Storage     │ Fetch  │
│        │ Modal              │ + Tera Templates  │ Per-Deployment    │ Apply  │
│        ▼                    ▼                   ▼                   ▼        │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌────────────┐ │
│  │ User selects │    │ project_app  │    │ Encrypted    │    │ Files on   │ │
│  │ apps, ports, │    │ table (DB)   │    │ secrets with │    │ deployment │ │
│  │ env vars     │    │ + versioning │    │ audit trail  │    │ server     │ │
│  └──────────────┘    └──────────────┘    └──────────────┘    └────────────┘ │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Vault Token Security Strategy (Selected Approach)

### Decision: Per-Deployment Scoped Tokens

Each deployment receives its own Vault token, scoped to only access that deployment's secrets. This is the **recommended and selected approach** for security reasons.

| Security Property | How It's Achieved |
|-------------------|-------------------|
| **Tenant Isolation** | Each deployment has isolated Vault path: `{prefix}/{deployment_hash}/*` |
| **Blast Radius Limitation** | Compromised agent can only access its own deployment's secrets |
| **Revocation Granularity** | Individual deployments can be revoked without affecting others |
| **Audit Trail** | All Vault accesses are logged per-deployment for forensics |
| **Compliance** | Meets SOC2/ISO 27001 requirements for secret isolation |

### Vault Path Structure

```text
{VAULT_AGENT_PATH_PREFIX}/
└── {deployment_hash}/
    ├── status_panel_token     # Agent authentication token (TTL: 30 days)
    ├── compose_agent_token    # Docker Compose agent token
    └── apps/
        ├── _compose/
        │   └── _compose       # Global docker-compose.yml (legacy)
        ├── {app_code}/
        │   ├── _compose       # Per-app docker-compose.yml
        │   ├── _env           # Runtime env payload for canonical .env
        │   ├── _configs       # Bundled config files (JSON array)
        │   └── _config        # Legacy single config file
        └── {app_code_2}/
            ├── _compose
            ├── _env
            └── _configs
```

### Vault Key Format

| Key Format | Vault Path | Description | Example |
|------------|------------|-------------|---------|
| `{app_code}` | `apps/{app_code}/_compose` | docker-compose.yml | `telegraf` → compose |
| `{app_code}_env` | `apps/{app_code}/_env` | Runtime env payload for canonical `.env` | `telegraf_env` → env vars |
| `{app_code}_configs` | `apps/{app_code}/_configs` | Bundled config files (JSON) | `telegraf_configs` → multiple configs |
| `{app_code}_config` | `apps/{app_code}/_config` | Single config (legacy) | `nginx_config` → nginx.conf |
| `_compose` | `apps/_compose/_compose` | Global compose (legacy) | Full stack compose |

### Token Lifecycle

1. **Provisioning** (Install Service):
   - During deployment, Install Service creates a new Vault token
   - Token policy restricts access to `{prefix}/{deployment_hash}/*` only
   - Token stored in Vault at `{prefix}/{deployment_hash}/status_panel_token`
   - Token injected into Status Panel agent via environment variable

2. **Configuration Sync** (Stacker → Vault):
   - When `project_app` is created/updated, `ConfigRenderer` generates files
   - `ProjectAppService.sync_to_vault()` pushes configs to Vault:
     - **Compose** stored at `{app_code}` key → `apps/{app_code}/_compose`
     - **Runtime env payloads** stored at `{app_code}_env` key → `apps/{app_code}/_env`
     - **Config bundles** stored at `{app_code}_configs` key → `apps/{app_code}/_configs`
   - Config bundle is a JSON array containing all config files for the app

3. **Command Enrichment** (Stacker → Status Panel):
   - When `deploy_app` command is issued, Stacker enriches the command payload
   - Fetches from Vault: `{app_code}` (compose), `{app_code}_env` (runtime env), `{app_code}_configs` (bundle)
   - For CLI-provided app-local config bundles, merges the app-local service
     definition into the full project compose, then merges the freshly rendered
     service-secret env into any `.env` file referenced by that app's compose
     `env_file`
   - If runtime env rendering fails, command creation fails rather than falling
     back to raw bundled `.env` content that could omit remote secrets
   - Adds all configs to `config_files` array in command payload
   - Status Panel receives complete config set ready to write

4. **Runtime** (Status Panel Agent):
   - Writes the runtime env payload to `/home/trydirect/project/.env` with
     `0600` permissions
   - Uses compose-relative `env_file: .env` for generated compose files
   - For app-local compose files such as `<app>/docker/<env>/compose.yml`, writes
     bundled config files under `/opt/stacker/deployments/<env>/files/...`; if
     that compose file references an app-local `.env`, the file contains the
     local `.env` content plus the Vault-rendered service secrets for the same
     app target
   - Refuses to overwrite drifted env content unless the command is forced
   - Agent reads `VAULT_TOKEN` from environment on startup
   - Fetches configs via `VaultClient.fetch_app_config()`
   - Writes files to destination paths with specified permissions
   - For `deploy_app` commands, config_files are written before docker compose up

5. **Revocation** (On Deployment Destroy):
   - Install Service deletes the deployment's Vault path recursively
   - Token becomes invalid immediately
   - All secrets for that deployment are removed

### Vault Policy Template

```hcl
# Policy: status-panel-{deployment_hash}
# Created by Install Service during deployment provisioning

path "{prefix}/{deployment_hash}/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

# Deny access to other deployments (implicit, but explicit for clarity)
path "{prefix}/*" {
  capabilities = ["deny"]
}
```

### Why NOT Shared Tokens?

| Approach | Risk | Decision |
|----------|------|----------|
| **Single Platform Token** | One compromised agent exposes ALL deployments | ❌ Rejected |
| **Per-Customer Token** | Compromises all of one customer's deployments | ❌ Rejected |
| **Per-Deployment Token** | Limits blast radius to single deployment | ✅ Selected |

---

## Stacker Components

### Service Deployment Scope Convention

Default service deployments are project-scoped.

When a service is declared in `stacker.yml`, `stacker service deploy <name>` and
related non-platform service deploy flows must update the main project compose
deployment:

```text
/home/trydirect/project/docker-compose.yml
```

Do not create a separate compose project such as
`/home/trydirect/<service>/docker-compose.yml` for a normal custom service unless
the user explicitly opts into standalone mode, for example with a future
`--standalone` or `--scope standalone` flag.

Only platform-managed services are allowed to live outside the project directory
by default. Current examples:

```text
/home/trydirect/statuspanel
/home/trydirect/nginx_proxy_manager
```

This convention prevents duplicate runtime ownership, where the same service
exists both inside `/home/trydirect/project/docker-compose.yml` and as a separate
standalone compose project. Before adding or changing service deployment code,
verify whether the service is project-scoped or platform-managed and add
regression tests for the chosen scope.

Stacker-managed compose services must include stable runtime identity labels
under the owned `stacker.my` reverse-DNS prefix:

```yaml
labels:
  my.stacker.project_id: "123"
  my.stacker.target: "cloud"
  my.stacker.scope: "project"
  my.stacker.service: "smtp"
  my.stacker.dns: "smtp"
```

Use `my.stacker.service` for the logical Stacker service code and
`my.stacker.dns` for the Docker network name that agents should use at runtime.
For Nginx Proxy Manager, this means `my.stacker.service=nginx_proxy_manager` and
`my.stacker.dns=nginx-proxy-manager`.

### 1. ConfigRenderer Service

**Location**: `src/services/config_renderer.rs`

**Purpose**: Converts `ProjectApp` records into deployable configuration files using Tera templates.

**Responsibilities**:
- Render docker-compose.yml from app definitions
- Generate .env files with merged environment variables (stored with `_env` suffix)
- Bundle multiple config files as JSON array (stored with `_configs` suffix)
- Sync rendered configs to Vault under separate keys

**Key Methods**:
```rust
// Render all configs for a project
let bundle = renderer.render_bundle(&project, &apps, deployment_hash)?;

// Sync to Vault - stores configs at:
// - {app_code}_env for .env files
// - _compose for docker-compose.yml
renderer.sync_to_vault(&bundle).await?;

// Sync single app's .env to Vault
renderer.sync_app_to_vault(&app, &project, deployment_hash).await?;
```

### 2. VaultService

**Location**: `src/services/vault_service.rs`

**Purpose**: Manages configuration storage in HashiCorp Vault with structured key patterns.

**Key Patterns**:
```rust
// Store compose file
vault.store_app_config(deployment_hash, "telegraf", &compose_config).await?;
// → Vault path: {prefix}/{deployment_hash}/apps/telegraf/_compose

// Store .env file
vault.store_app_config(deployment_hash, "telegraf_env", &env_config).await?;
// → Vault path: {prefix}/{deployment_hash}/apps/telegraf/_env

// Store bundled config files
vault.store_app_config(deployment_hash, "telegraf_configs", &bundle_config).await?;
// → Vault path: {prefix}/{deployment_hash}/apps/telegraf/_configs
```

### 3. Config Bundling (store_configs_to_vault_from_params)

**Location**: `src/routes/command/create.rs`

**Purpose**: Extracts and bundles config files from deploy_app parameters for Vault storage.

**Flow**:
```rust
// 1. Extract compose file from config_files array
// 2. Collect non-compose config files (telegraf.conf, .env, etc.)
// 3. Bundle as JSON array with metadata
let configs_json: Vec<serde_json::Value> = app_configs.iter().map(|(name, cfg)| {
    json!({
        "name": name,
        "content": cfg.content,
        "content_type": cfg.content_type,
        "destination_path": cfg.destination_path,
        "file_mode": cfg.file_mode,
        "owner": cfg.owner,
        "group": cfg.group,
    })
}).collect();

// 4. Store bundle to Vault under {app_code}_configs key
vault.store_app_config(deployment_hash, &format!("{}_configs", app_code), &bundle_config).await?;
```

### 4. Command Enrichment (enrich_deploy_app_with_compose)

**Location**: `src/routes/command/create.rs`

**Purpose**: Enriches deploy_app command with configs from Vault before sending to Status Panel.

**Flow**:
```rust
// 1. Fetch compose from Vault: {app_code} key
// 2. Fetch bundled configs: {app_code}_configs key (or fallback to _config)
// 3. Render runtime env from app env + remote service secrets
// 4. Merge rendered env into app-local compose env_file entries when present
// 5. Add canonical runtime env and bundled files to config_files array
// 6. Send enriched command to Status Panel
```

When a CLI request already includes `compose_content` and config files from an
app-local compose bundle, Stacker uses the app-local service definition for the
target app but merges it into the full project compose before sending
`compose_content` to the Status agent. The agent still writes one
`docker-compose.yml`, but it contains all project services plus the updated
app-local service. The CLI treats the project-level compose as topology in this
path and bundles only files referenced by the target app-local compose, so a
missing `env_file` for an unrelated service does not block app-only updates.
Stacker also keeps the bundled config files and appends the Vault-rendered
service secrets to the `.env` file referenced by the matching compose service.
This lets `device-api/docker/prod/compose.yml` with `env_file: .env` receive
both local `.env` content and Vault-backed service secrets without truncating
the remote project compose file. On later resyncs, the previously appended
`# stacker-render ...` block is replaced with the freshly rendered one so
remote app-local `.env` files do not accumulate duplicate secret sections. If
the server cannot render the runtime env for a registered target, the enqueue
request fails so Status does not deploy a partial app-local `.env`.

### 5. ProjectAppService

**Location**: `src/services/project_app_service.rs`

**Purpose**: High-level service for managing project apps with automatic Vault synchronization.

**Key Features**:
- Automatic Vault sync on create/update/delete (uses `_env` key)
- Config versioning and drift detection
- Bulk sync for deployment refreshes

### 6. Database Schema (project_app)

**Migration**: `migrations/20260129120000_add_config_versioning`

**New Fields**:
```sql
ALTER TABLE project_app ADD COLUMN config_version INTEGER DEFAULT 1;
ALTER TABLE project_app ADD COLUMN config_hash VARCHAR(64);
ALTER TABLE project_app ADD COLUMN vault_synced_at TIMESTAMP;
```

---

## Configuration Delivery Method

### Selected: Individual File Sync + Optional Archive

**Rationale**:
- **Individual files**: Efficient for single-app updates, supports incremental sync
- **Archive option**: Useful for initial deployment or full-stack rollback

**Flow**:
```
project_app → ConfigRenderer → Vault KV v2 → Status Panel → Filesystem
                   ↓
            (optional tar.gz for bulk operations)
```

---

## Environment Variables

### Stacker Service

| Variable | Description | Example |
|----------|-------------|---------|
| `VAULT_ADDR` | Vault server URL | `https://vault.trydirect.io:8200` |
| `VAULT_TOKEN` | Stacker's service token (write access) | (from Install Service) |
| `VAULT_MOUNT` | KV v2 mount path | `status_panel` |

### Status Panel Agent

| Variable | Description | Example |
|----------|-------------|---------|
| `VAULT_ADDRESS` | Vault server URL | `https://vault.trydirect.io:8200` |
| `VAULT_TOKEN` | Per-deployment scoped token (read-only) | (provisioned during deploy) |
| `VAULT_AGENT_PATH_PREFIX` | KV mount/prefix | `status_panel` |

---

## Security Considerations

### Secrets Never in Git
- All sensitive data (passwords, API keys) stored in Vault
- Configuration templates use placeholders: `{{ DB_PASSWORD }}`
- Rendered values never committed to source control

### File Permissions
- Sensitive configs: `0600` (owner read/write only)
- General configs: `0644` (world readable)
- Owner/group can be specified per-file

### Audit Trail
- Vault logs all secret access with timestamps
- Stacker logs config sync operations
- Status Panel logs file write operations

### Encryption
- **At Rest**: Vault encrypts all secrets before storage
- **In Transit**: TLS for all Vault API communication
- **On Disk**: Files written with restrictive permissions

---

## Related Documentation

- [Status Panel APP_DEPLOYMENT.md](../../status/docs/APP_DEPLOYMENT.md) - Agent-side configuration handling
- [VaultClient](../../status/src/security/vault_client.rs) - Status Panel Vault integration
- [ConfigRenderer](../src/services/config_renderer.rs) - Stacker configuration rendering

---

## Firewall Configuration (iptables)

Stacker supports configuring iptables firewall rules on target servers. Rules can be derived from Ansible role port definitions or specified manually.

### Execution Methods

| Method | Description | When to Use |
|--------|-------------|-------------|
| **Status Panel** | Commands executed directly on target server via Status Panel agent | Preferred - servers with Status Panel installed |
| **SSH** | Commands executed via SSH/Ansible | Fallback - servers without Status Panel |

### Port Types

| Port Type | Description | Default Source |
|-----------|-------------|----------------|
| **Public Ports** | Accessible from any IP (internet-facing) | `0.0.0.0/0` |
| **Private Ports** | Restricted to internal networks | `10.0.0.0/8` (configurable) |

### MCP Tools

#### `configure_firewall`
Configure iptables rules on a deployment target server.

```json
{
  "deployment_hash": "abc123",
  "action": "add",
  "public_ports": [
    {"port": 80, "protocol": "tcp"},
    {"port": 443, "protocol": "tcp"}
  ],
  "private_ports": [
    {"port": 5432, "protocol": "tcp", "source": "10.0.0.0/8"}
  ],
  "persist": true,
  "execution_method": "status_panel"
}
```

#### `list_firewall_rules`
List current iptables rules on a deployment.

```json
{
  "deployment_hash": "abc123"
}
```

#### `configure_firewall_from_role`
Configure firewall rules based on an Ansible role's port definitions.

```json
{
  "role_name": "nginx",
  "deployment_hash": "abc123",
  "action": "add",
  "private_network": "10.0.0.0/8"
}
```

### Status Panel Command

The `configure_firewall` command type is sent to Status Panel agents:

```json
{
  "deployment_hash": "abc123",
  "command_type": "configure_firewall",
  "parameters": {
    "action": "add",
    "public_ports": [{"port": 80, "protocol": "tcp", "source": "0.0.0.0/0"}],
    "private_ports": [{"port": 5432, "protocol": "tcp", "source": "10.0.0.0/8"}],
    "persist": true
  }
}
```

### Integration with Ansible Roles

Ansible roles define `public_ports` and `private_ports` arrays. When deploying via SSH method or using `configure_firewall_from_role`, these port definitions are automatically converted to iptables rules:

- **Public ports**: Allow incoming TCP/UDP from `0.0.0.0/0`
- **Private ports**: Allow incoming TCP/UDP from specified internal network only
