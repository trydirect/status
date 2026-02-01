## Plan: App Configuration Deployment Strategy (Status Panel)

This plan outlines a robust, flexible approach for deploying app configurations using Status Panel, Vault, and external sources. It covers template sourcing, environment variable management, network integration, and extensibility for future needs.

---

## Vault Token Security Strategy (Selected Approach)

### Decision: Per-Deployment Scoped Tokens

Each Status Panel agent receives its own Vault token, scoped to only access that deployment's secrets. This provides:

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
        └── {app_code}/
            ├── _compose       # docker-compose.yml (key: {app_code})
            ├── _env           # .env file (key: {app_code}_env)
            ├── _configs       # Bundled config files JSON array (key: {app_code}_configs)
            └── _config        # Legacy single config (key: {app_code}_config)
```

**Key Suffix Mapping** (used by VaultService):

| Suffix Pattern | Vault Key | Purpose |
|----------------|-----------|---------|
| `{app_code}` | `_compose` | Docker compose file |
| `{app_code}_env` | `_env` | Environment file (.env) |
| `{app_code}_configs` | `_configs` | Bundled config files (JSON array) |
| `{app_code}_config` | `_config` | Legacy single config file |

**Config Bundle Format** (`_configs` key):
```json
[
  {
    "name": "telegraf.conf",
    "content": "[[inputs.cpu]]\n...",
    "content_type": "text/plain",
    "destination_path": "/etc/telegraf/telegraf.conf",
    "file_mode": "0644",
    "owner": "telegraf",
    "group": "telegraf"
  }
]
```

### Token Lifecycle

1. **Provisioning** (Install Service):
   - During deployment, Install Service creates a new Vault token
   - Token policy restricts access to `{prefix}/{deployment_hash}/*` only
   - Token stored in Vault at `{prefix}/{deployment_hash}/status_panel_token`
   - Token injected into Status Panel agent via environment variable

2. **Runtime** (Status Panel Agent):
   - Agent reads `VAULT_TOKEN` from environment on startup
   - All Vault API calls use this scoped token
   - Token TTL: 30 days with auto-renewal capability

3. **Revocation** (On Deployment Destroy):
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

### Environment Variables (Status Panel Agent)

| Variable | Description | Example |
|----------|-------------|---------|
| `VAULT_ADDRESS` | Vault server URL | `https://vault.trydirect.io:8200` |
| `VAULT_TOKEN` | Per-deployment scoped token | (provisioned by Install Service) |
| `VAULT_AGENT_PATH_PREFIX` | KV mount/prefix | `status_panel` |

### Why NOT Shared Tokens?

| Approach | Risk | Decision |
|----------|------|----------|
| **Single Platform Token** | One compromised agent exposes ALL deployments | ❌ Rejected |
| **Per-Customer Token** | Compromises all of one customer's deployments | ❌ Rejected |
| **Per-Deployment Token** | Limits blast radius to single deployment | ✅ Selected |

---

### Steps

1. **Define Configuration Sources and Flow**
   - Use Vault as the primary store for app configs and secrets.
   - Support fetching templates/scripts from public GitHub or other package sources (zip, tar, etc.).
   - Allow fallback to local or built-in templates if remote fetch fails.

2. **Template and Script Management**
   - Store default templates in Vault or a managed repo.
   - Allow user to specify a GitHub repo, branch, or path for custom templates/scripts.
   - Support bash scripts for pre/post-deploy hooks (stored in Vault or fetched remotely).

3. **Network and Environment Integration**
   - Parse and apply user-defined network settings (from Status Panel UI/API).
   - Merge user-provided ENV key/values with defaults from templates, Vault, and app_vars.
   - Validate and resolve conflicts, prioritizing user values.

4. **Deployment Execution**
   - Download and render templates/scripts with merged variables.
   - Apply network settings as defined by user (docker-compose, k8s, etc.).
   - Run pre/post-deploy scripts if present.
   - Log all actions and errors for auditability.

5. **Extensibility and Security**
   - Support additional package managers (e.g., Helm, apt, pip) as plugins.
   - Ensure all secrets/configs are encrypted at rest (Vault) and in transit.
   - Allow for future integration with other config sources (S3, GCS, etc.).

### Further Considerations

1. Should template fetching support private repos (with token)?
2. How to handle versioning/rollback of configs and deployments?
3. Should we support dry-run/preview before applying changes?