# TODO: Stacker Marketplace Payment Integration

> Canonical note: keep all Stacker TODO updates in this file (`stacker/TODO.md`); do not create or update a separate `STACKER_TODO.md` going forward.

---

## Marketplace Developer Flow: `stacker submit` → review → auto-publish

### CLI Commands (v0.2.6)
- [x] **`stacker submit`** — Package and upload current stack to Stacker Server for marketplace review
  - Reads stacker.yml for metadata, derives slug from name
  - Creates/updates template via `POST /api/templates`, submits via `POST /api/templates/{id}/submit`
  - Prints success message with `stacker marketplace status` hint
  - Supports: `--version`, `--description`, `--category`, `--plan-type`, `--price`
- [x] **`stacker marketplace status`** — List all submissions by current developer
  - Calls `GET /api/templates/mine`
  - Display table: STACK | VERSION | STATUS | SUBMITTED
  - Statuses: `pending_review`, `in_review`, `approved`, `rejected`, `published`
- [x] **`stacker marketplace status <stack-name>`** — Show detail for one submission
  - Filters by name or slug, shows status, submitted date, reviewer reason
- [x] **`stacker marketplace logs <stack-name>`** — Show review history with decisions/reasons
- [x] **StackerClient methods**: `marketplace_create_or_update()`, `marketplace_submit()`, `marketplace_list_mine()`, `marketplace_reviews()`
- [x] **Response types**: `MarketplaceTemplateInfo`, `MarketplaceReviewInfo`

### Server API — Marketplace Submissions (pre-existing)
- [x] `POST /api/templates` — Create/update template (creator.rs)
- [x] `POST /api/templates/{id}/submit` — Submit for review (creator.rs)
- [x] `GET /api/templates/mine` — List developer's submissions (creator.rs)
- [x] `PUT /api/admin/templates/{id}/review` — Admin approves/rejects (admin.rs)
- [x] Auto-publish logic: on approval, `stack_template` updated with `published_at`

### Buyer Flow — Remote Deploy from Laptop
- [ ] **`stacker deploy <stack-name> --target server --host <IP>`** — Deploy marketplace stack to remote server (needs marketplace stack resolution in deploy strategy)
- [x] `GET /api/v1/marketplace/download/{purchase_token}` — Serve stack archive (placeholder, needs User Service token validation)

### Buyer Flow — curl one-liner (direct on server)
- [x] `GET /api/v1/marketplace/install/{purchase_token}` — Generate install.sh script
  - Script installs: Stacker CLI + Status Panel agent
  - Script downloads stack archive using purchase token
  - Status Panel calls `stacker deploy` locally (no Install Service involved)
- [x] `POST /api/v1/marketplace/agents/register` — Agent self-registration endpoint
  - Generates agent_id, agent_token, deployment_hash
  - TODO: validate purchase token with User Service, persist agent in DB, call `/marketplace/link-deployment`

---

## ✅ Recent Fixes

### May 15, 2026 - Remote runtime `.env` merge strategy hardening
- [x] Fixed `stacker agent deploy-app` to keep the shared project `.env` in the deploy-app config bundle when the target service topology uses root `env_file: .env`
- [ ] Replace append-based runtime env merge with **key-aware env merge**
  - Parse existing/base `.env` content into key/value pairs instead of concatenating text blocks
  - Build one final deduplicated runtime `.env` file per actual runtime path
  - Eliminate duplicate keys such as `PORT=...` appearing twice after merge
- [ ] Define and document strict runtime env precedence
  - base authoring env from `stacker.yml env_file`
  - server-scope secrets
  - service-scope secrets
  - generated runtime keys such as `DEPLOYMENT_HASH`
- [ ] Add deletion semantics for rendered env output
  - when a rendered/secret-backed key is removed, the next render must remove it from the target runtime `.env`
  - do not preserve stale keys just because they existed in the previous file
- [ ] Split merge behavior by runtime topology, not by secret scope
  - shared `/home/trydirect/project/.env` must be rendered as one canonical deduplicated file
  - app-local env files should only be used when the compose topology truly points to app-local env files
- [ ] Add regression tests for runtime env merge behavior
  - shared root `.env` survives `stacker agent deploy-app`
  - app-local `.env` merge still works
  - override precedence is deterministic
  - removed keys disappear on next render
  - registry auth never leaks into runtime `.env`

### May 2, 2026 - Vault-backed NPM credential contract
- [x] Status Panel `configure_proxy` no longer relies on hard-coded `admin@example.com` / `changeme` defaults
- [x] Installer contract now emits `STACKER_SERVER_ID` and a host-scoped Vault path for Nginx Proxy Manager credentials
- [x] Deployment-scoped Vault tokens can be extended with an exact read grant for `secret/{env}/status_panel/hosts/{server_id}/npm_credentials`
- [x] Status Panel linking now advertises `npm_credential_source=vault`; Stacker surfaces it in deployment capabilities and can gate `configure_proxy` with `STACKER_CONFIGURE_PROXY_CAPABILITY_MODE=warn|enforce`
- [x] Rollout order: ship Status Panel reader → provision installer secret/policy → re-link agents so capabilities are refreshed → keep Stacker in `warn` mode → switch to `enforce` after all active agents report `npm_credential_source=vault`
- [ ] Future Vault hardening: expose `vault.try.direct` for Status Panel agents behind identity-based access (prefer mTLS; a private mesh or tunnel is also acceptable) instead of relying on static source-IP allowlists. Keep Vault tokens short-lived and path-scoped to the exact Status Panel host/deployment secrets they need.

### February 16, 2026 - CORS Headers Fix
- [x] Fixed CORS configuration to properly support Authorization header with credentials
- [x] Changed from whitelist (`allowed_headers(vec![...])`) to `.allow_any_header()` + `.expose_any_header()`
- [x] Resolves browser console warning about Authorization header not being covered

## 🚨 CRITICAL BUGS - ENV VARS NOT SAVED TO project_app

> **Date Identified**: 2026-02-02  
> **Priority**: P0 - Blocks user deployments  
> **Status**: ✅ FIXED (2026-02-02)

### Bug 1: .env config file content not parsed into project_app.environment

**File**: `src/project_app/mapping.rs`

**Problem**: When users edited the `.env` file in the Config Files tab (instead of using the Environment form fields), the `params.env` was empty `{}`. The `.env` file content in `config_files` was never parsed into `project_app.environment`.

**Fix Applied**:
1. Added `parse_env_file_content()` function to parse `.env` file content
2. Supports both `KEY=value` (standard) and `KEY: value` (YAML-like) formats
3. Modified `ProjectAppPostArgs::from()` to:
   - Extract and parse `.env` file content from `config_files`
   - If `params.env` is empty, use parsed `.env` values for `project_app.environment`
   - `params.env` (form fields) takes precedence if non-empty

### Bug 2: `create.rs` looks for nested `parameters.parameters`

**File**: `src/routes/command/create.rs` lines 145-146

**Status**: ⚠️ MITIGATED - The fallback path at lines 155-158 uses `req.parameters` directly which now works with the mapping.rs fix. Full fix would simplify the code but is lower priority.

### Bug 3: Image not provided in parameters - validation fails

**File**: `src/services/project_app_service.rs` validate_app()

**Problem**: When user edits config files via the modal, parameters don't include `image`. The `validate_app()` function requires non-empty `image`, causing saves to fail with "Docker image is required".

**Root Cause**: The app's `dockerhub_image` is stored in User Service's `app` table and `request_dump`, but was never passed to Stacker.

**Fix Applied (2026-02-02)**:
1. **User Service** (`app/deployments/services.py`):
   - Added `_get_app_image_from_installation()` helper to extract image from `request_dump.apps`
   - Modified `trigger_action()` to enrich parameters with `image` before calling Stacker
   - Logs when image is enriched or cannot be found

2. **Stacker** (`src/project_app/mapping.rs`):
   - Added `parse_image_from_compose()` as fallback to extract image from docker-compose.yml
   - If no image in params and compose content provided, extracts from compose

3. **Comprehensive logging** added throughout:
   - `create.rs`: Logs incoming parameters, env, config_files, image
   - `upsert.rs`: Logs project lookup, app exists/merge, final project_app
   - `mapping.rs`: Logs image extraction from compose
   - `project_app_service.rs`: Logs validation failures with details

### Verification Tests Added:
- [x] `test_env_config_file_parsed_into_environment` - YAML-like format
- [x] `test_env_config_file_standard_format` - Standard KEY=value format
- [x] `test_params_env_takes_precedence` - Form fields override file
- [x] `test_empty_env_file_ignored` - Empty files don't break
- [x] `test_custom_config_files_saved_to_labels` - Config files preserved

---

## Context
Per [PAYMENT_MODEL.md](/PAYMENT_MODEL.md), Stacker now sends webhooks to User Service when templates are published/updated. User Service owns the `products` table for monetization, while Stacker owns `stack_template` (template definitions only).

### New Open Questions (Status Panel & MCP)

**Status**: ✅ PROPOSED ANSWERS DOCUMENTED  
**See**: [OPEN_QUESTIONS_RESOLUTIONS.md](docs/OPEN_QUESTIONS_RESOLUTIONS.md)

**Questions** (awaiting team confirmation):
- Health check contract per app: exact URL/expected status/timeout that Status Panel should register and return.
- Per-app deploy trigger rate limits: allowed requests per minute/hour to expose in User Service.
- Log redaction patterns: which env var names/secret regexes to strip before returning logs via Stacker/User Service.
- Container→app_code mapping: confirm canonical source (deployment_apps.metadata.container_name) for Status Panel health/logs responses.

**Current Proposals**:
1. **Health Check**: `GET /api/health/deployment/{deployment_hash}/app/{app_code}` with 10s timeout
2. **Rate Limits**: Deploy 10/min, Restart 5/min, Logs 20/min (configurable by plan tier)
3. **Log Redaction**: 6 pattern categories + 20 env var blacklist (regex-based)
4. **Container Mapping**: `app_code` is canonical; requires `deployment_apps` table in User Service

### Status Panel Command Payloads (proposed)
- Commands flow over existing agent endpoints (`/api/v1/commands/execute` or `/enqueue`) signed with HMAC headers from `AgentClient`.
- **Health** request:
  ```json
  {"type":"health","deployment_hash":"<hash>","app_code":"<app>","include_metrics":true}
  ```
  **Health report** (agent → `/api/v1/commands/report`):
  ```json
  {"type":"health","deployment_hash":"<hash>","app_code":"<app>","status":"ok|unhealthy|unknown","container_state":"running|exited|starting|unknown","last_heartbeat_at":"2026-01-09T00:00:00Z","metrics":{"cpu_pct":0.12,"mem_mb":256},"errors":[]}
  ```
- **Logs** request:
  ```json
  {"type":"logs","deployment_hash":"<hash>","app_code":"<app>","cursor":"<opaque>","limit":400,"streams":["stdout","stderr"],"redact":true}
  ```
  **Logs report**:
  ```json
  {"type":"logs","deployment_hash":"<hash>","app_code":"<app>","cursor":"<next>","lines":[{"ts":"2026-01-09T00:00:00Z","stream":"stdout","message":"...","redacted":false}],"truncated":false}
  ```
- **Restart** request:
  ```json
  {"type":"restart","deployment_hash":"<hash>","app_code":"<app>","force":false}
  ```
  **Restart report**:
  ```json
  {"type":"restart","deployment_hash":"<hash>","app_code":"<app>","status":"ok|failed","container_state":"running|failed|unknown","errors":[]}
  ```
- Errors: agent reports `{ "type":"<same>", "deployment_hash":..., "app_code":..., "status":"failed", "errors":[{"code":"timeout","message":"..."}] }`.
- Tasks progress:
  1. ✅ add schemas/validation for these command payloads → implemented in `src/forms/status_panel.rs` and enforced via `/api/v1/commands` create/report handlers.
  2. ✅ document in agent docs → see `docs/AGENT_REGISTRATION_SPEC.md`, `docs/STACKER_INTEGRATION_REQUIREMENTS.md`, and `docs/QUICK_REFERENCE.md` (field reference + auth note).
  3. ✅ expose in Stacker UI/Status Panel integration notes → new `docs/STATUS_PANEL_INTEGRATION_NOTES.md` consumed by dashboard team.
  4. ⏳ ensure Vault token/HMAC headers remain the auth path (UI + ops playbook updates pending).

### Dynamic Agent Capabilities Endpoint
- [x] Expose `GET /api/v1/deployments/{deployment_hash}/capabilities` returning available commands based on `agents.capabilities` JSONB (implemented in `routes::deployment::capabilities_handler`).
- [x] Define command→capability mapping (static config) embedded in the handler:
  ```json
  {
    "restart": { "requires": "docker", "scope": "container", "label": "Restart", "icon": "fas fa-redo" },
    "start":   { "requires": "docker", "scope": "container", "label": "Start", "icon": "fas fa-play" },
    "stop":    { "requires": "docker", "scope": "container", "label": "Stop", "icon": "fas fa-stop" },
    "pause":   { "requires": "docker", "scope": "container", "label": "Pause", "icon": "fas fa-pause" },
    "logs":    { "requires": "logs",   "scope": "container", "label": "Logs", "icon": "fas fa-file-alt" },
    "rebuild": { "requires": "compose", "scope": "deployment", "label": "Rebuild Stack", "icon": "fas fa-sync" },
    "backup":  { "requires": "backup", "scope": "deployment", "label": "Backup", "icon": "fas fa-download" }
  }
  ```
- [x] Return only commands whose `requires` capability is present in the agent's capabilities array (see `filter_commands` helper).
- [x] Include agent status (online/offline) and last_heartbeat plus existing metadata in the response so Blog can gate UI.

### Pull-Only Command Architecture (No Push)
**Key principle**: Stacker never dials out to agents. Commands are enqueued in the database; agents poll and sign their own requests.
- [x] `POST /api/v1/agent/commands/enqueue` validates user auth, inserts into `commands` + `command_queue` tables, returns 202. No outbound HTTP to agent.
- [x] Agent polls `GET /api/v1/agent/commands/wait/{deployment_hash}` with HMAC headers it generates using its Vault-fetched token.
- [x] Stacker verifies agent's HMAC, returns queued commands.
- [x] Agent executes locally and calls `POST /api/v1/agent/commands/report` (HMAC-signed).
- [x] Remove any legacy `agent_dispatcher::execute/enqueue` code that attempted to push to agents; keep only `rotate_token` for Vault token management.
- [x] Document that `AGENT_BASE_URL` env var is NOT required for Status Panel; Stacker is server-only (see README.md).

### Dual Endpoint Strategy (Status Panel + Compose Agent)
- [ ] Maintain legacy proxy routes under `/api/v1/deployments/{hash}/containers/*` for hosts without Compose Agent; ensure regression tests continue to cover restart/start/stop/logs flows.
- [ ] Add Compose control-plane routes (`/api/v1/compose/{hash}/status|logs|restart|metrics`) that translate into cagent API calls using the new `compose_agent_token` from Vault.
- [ ] For Compose Agent path only: `agent_dispatcher` may push commands if cagent exposes an HTTP API; this is the exception, not the rule.
- [ ] Return `"compose_agent": true|false` in `/capabilities` response plus a `"fallback_reason"` field when Compose Agent is unavailable (missing registration, unhealthy heartbeat, token fetch failure).
- [ ] Write ops playbook entry + automated alert when Compose Agent is offline for >15 minutes so we can investigate hosts stuck on the legacy path.

### Coordination Note
Sub-agents can communicate with the team lead via the shared memory tool (see /memories/subagents.md). If questions remain, record them in TODO.md and log work in CHANGELOG.md.

### Nginx Proxy Routing
**Browser → Stacker** (via nginx): `https://dev.try.direct/stacker/` → `stacker:8000`
**Stacker → User Service** (internal): `http://user:4100/marketplace/sync` (no nginx prefix)
**Stacker → Payment Service** (internal): `http://payment:8000/` (no nginx prefix)

Stacker responsibilities:
1. **Maintain `stack_template` table** (template definitions, no pricing/monetization)
2. **Send webhook to User Service** when template status changes (approved, updated, rejected)
3. **Query User Service** for product information (pricing, vendor, etc.)
4. **Validate deployments** against User Service product ownership

## Improvements
### Top improvements
- [x] Cache OAuth token validation in Stacker (30–60s TTL) to avoid a User Service call on every request.
- [x] Reuse/persist the HTTP client with keep-alive and a shared connection pool for User Service; avoid starting new connections per request.
- [x] Stop reloading Casbin policies on every request; reload on policy change.
- [x] Reduce polling frequency and batch command status queries; prefer streaming/long-poll responses.
- [ ] Add server-side aggregation: return only latest command states instead of fetching full 150+ rows each time.
- [x] Add gzip/br on internal HTTP responses and trim response payloads.

### Local pipe discovery follow-up
- [ ] Design a local-only persistence layer for AI/discovery pipe hints before adding runtime semantics or `stacker.yml` schema changes.
  - Scope: cache advisory local scan results for commands such as a future `stacker pipe scan-local`
  - Preferred first option: SQLite in the workspace or `.stacker/` state
  - Minimal tables:
    - `pipe_scans(id, project_root, project_name, scanned_at)`
    - `pipe_hints(id, scan_id, pipe_key, category, title, confidence, source, evidence, target)`
  - Keep this separate from remote/runtime-verified pipe records and from server-side Postgres models
  - Add user-confirmed decisions later only if the local discovery workflow proves useful
- [x] Co-locate Stacker and User Service (same network/region) or use private networking to cut latency.

### Backlog hygiene
- [ ] Capture ongoing UX friction points from Stack Builder usage and log them here.
- [ ] Track recurring operational pain points (timeouts, retries, auth failures) for batch fixes.
- [ ] Record documentation gaps that slow down onboarding or integration work.

## Tasks

### Data Contract Notes (2026-01-04)
- `project_id` in Stacker is the same identifier as `stack_id` in the User Service `installation` table; use it to link records across services.
- Include `deployment_hash` from Stacker in payloads sent to Install Service (RabbitMQ) and User Service so both can track deployments by the unique deployment key. Coordinate with try.direct.tools to propagate this field through shared publishers/helpers.

### 0. Setup ACL Rules Migration (User Service)
**File**: `migrations/setup_acl_rules.py` (in Stacker repo)

**Purpose**: Automatically configure Casbin ACL rules in User Service for Stacker endpoints

**Required Casbin rules** (to be inserted in User Service `casbin_rule` table):
```python
# Allow root/admin to manage marketplace templates via Stacker
rules = [
    ('p', 'root', '/templates', 'POST', '', '', ''),      # Create template
    ('p', 'root', '/templates', 'GET', '', '', ''),       # List templates
    ('p', 'root', '/templates/*', 'GET', '', '', ''),     # View template
    ('p', 'root', '/templates/*', 'PUT', '', '', ''),     # Update template
    ('p', 'root', '/templates/*', 'DELETE', '', '', ''),  # Delete template
    ('p', 'admin', '/templates', 'POST', '', '', ''),
    ('p', 'admin', '/templates', 'GET', '', '', ''),
    ('p', 'admin', '/templates/*', 'GET', '', '', ''),
    ('p', 'admin', '/templates/*', 'PUT', '', '', ''),
    ('p', 'developer', '/templates', 'POST', '', '', ''),  # Developers can create
    ('p', 'developer', '/templates', 'GET', '', '', ''),   # Developers can list own
]
```

**Implementation**:
- Run as part of Stacker setup/init
- Connect to User Service database
- Insert rules if not exist (idempotent)
- **Status**: NOT STARTED
- **Priority**: HIGH (Blocks template creation via Stack Builder)
- **ETA**: 30 minutes

### 0.5. Add Category Table Fields & Sync (Stacker)
**File**: `migrations/add_category_fields.py` (in Stacker repo)

**Purpose**: Add missing fields to Stacker's local `category` table and sync from User Service

**Migration Steps**:
1. Add `title VARCHAR(255)` column to `category` table (currently only has `id`, `name`)
2. Add `metadata JSONB` column for flexible category data
3. Create `UserServiceConnector.sync_categories()` method
4. On application startup: Fetch categories from User Service `GET http://user:4100/api/1.0/category`
5. Populate/update local `category` table:
   - Map User Service `name` → Stacker `name` (code)
   - Map User Service `title` → Stacker `title`
   - Store additional data in `metadata` JSONB

**Example sync**:
```python
# User Service category
{"_id": 5, "name": "ai", "title": "AI Agents", "priority": 5}

# Stacker local category (after sync)
{"id": 5, "name": "ai", "title": "AI Agents", "metadata": {"priority": 5}}
```

**Status**: NOT STARTED  
**Priority**: HIGH (Required for Stack Builder UI)  
**ETA**: 1 hour

### 1. Create User Service Connector
**File**: `app/<stacker-module>/connectors/user_service_connector.py` (in Stacker repo)

**Required methods**:
```python
class UserServiceConnector:
    def get_categories(self) -> list:
        """
        GET http://user:4100/api/1.0/category
        
        Returns list of available categories for stack classification:
        [
            {"_id": 1, "name": "cms", "title": "CMS", "priority": 1},
            {"_id": 2, "name": "ecommerce", "title": "E-commerce", "priority": 2},
            {"_id": 5, "name": "ai", "title": "AI Agents", "priority": 5}
        ]
        
        Used by: Stack Builder UI to populate category dropdown
        """
        pass
    
    def get_user_profile(self, user_token: str) -> dict:
        """
        GET http://user:4100/oauth_server/api/me
        Headers: Authorization: Bearer {user_token}
        
        Returns:
        {
            "email": "user@example.com",
            "plan": {
                "name": "plus",
                "date_end": "2026-01-30"
            },
            "products": [
                {
                    "product_id": "uuid",
                    "product_type": "template",
                    "code": "ai-agent-stack",
                    "external_id": 12345,  # stack_template.id from Stacker
                    "name": "AI Agent Stack",
                    "price": "99.99",
                    "owned_since": "2025-01-15T..."
                }
            ]
        }
        """
        pass
    
    def get_template_product(self, stack_template_id: int) -> dict:
        """
        GET http://user:4100/api/1.0/products?external_id={stack_template_id}&product_type=template
        
        Returns product info for a marketplace template (pricing, vendor, etc.)
        """
        pass
    
    def user_owns_template(self, user_token: str, stack_template_id: int) -> bool:
        """
        Check if user has purchased/owns this marketplace template
        """
        profile = self.get_user_profile(user_token)
        return any(p['external_id'] == stack_template_id and p['product_type'] == 'template' 
                   for p in profile.get('products', []))
```

**Implementation Note**: Use OAuth2 token that Stacker already has for the user.

### 2. Create Webhook Sender to User Service (Marketplace Sync)
**File**: `app/<stacker-module>/webhooks/marketplace_webhook.py` (in Stacker repo)

**When template status changes** (approved, updated, rejected):
```python
import requests
from os import environ

class MarketplaceWebhookSender:
    """
    Send template sync webhooks to User Service
    Mirrors PAYMENT_MODEL.md Flow 3: Stacker template changes → User Service products
    """
    
    def send_template_approved(self, stack_template: dict, vendor_user: dict):
        """
        POST http://user:4100/marketplace/sync
        
        Body:
        {
            "action": "template_approved",
            "stack_template_id": 12345,
            "external_id": 12345,  # Same as stack_template_id
            "code": "ai-agent-stack-pro",
            "name": "AI Agent Stack Pro",
            "description": "Advanced AI agent deployment...",
            "category_code": "ai",  # String code from local category.name (not ID)
            "price": 99.99,
            "billing_cycle": "one_time",  # or "monthly"
            "currency": "USD",
            "vendor_user_id": 456,
            "vendor_name": "John Doe"
        }
        """
        headers = {'Authorization': f'Bearer {self.get_service_token()}'}
        
        payload = {
            'action': 'template_approved',
            'stack_template_id': stack_template['id'],
            'external_id': stack_template['id'],
            'code': stack_template.get('code'),
            'name': stack_template.get('name'),
            'description': stack_template.get('description'),
            'category_code': stack_template.get('category'),  # String code (e.g., "ai", "cms")
            'price': stack_template.get('price'),
            'billing_cycle': stack_template.get('billing_cycle', 'one_time'),
            'currency': stack_template.get('currency', 'USD'),
            'vendor_user_id': vendor_user['id'],
            'vendor_name': vendor_user.get('full_name', vendor_user.get('email'))
        }
        
        response = requests.post(
            f"{environ['URL_SERVER_USER']}/marketplace/sync",
            json=payload,
            headers=headers
        )
        
        if response.status_code != 200:
            raise Exception(f"Webhook send failed: {response.text}")
        
        return response.json()
    
    def send_template_updated(self, stack_template: dict, vendor_user: dict):
        """Send template updated webhook (same format as approved)"""
        payload = {...}
        payload['action'] = 'template_updated'
        # Send like send_template_approved()
    
    def send_template_rejected(self, stack_template: dict):
        """
        Notify User Service to deactivate product
        
        Body:
        {
            "action": "template_rejected",
            "stack_template_id": 12345
        }
        """
        headers = {'Authorization': f'Bearer {self.get_service_token()}'}
        
        payload = {
            'action': 'template_rejected',
            'stack_template_id': stack_template['id']
        }
        
        response = requests.post(
            f"{environ['URL_SERVER_USER']}/marketplace/sync",
            json=payload,
            headers=headers
        )
        
        return response.json()
    
    @staticmethod
    def get_service_token() -> str:
        """Get Bearer token for service-to-service communication"""
        # Option 1: Use static bearer token
        return environ.get('STACKER_SERVICE_TOKEN')
        
        # Option 2: Use OAuth2 client credentials flow (preferred)
        # See User Service `.github/copilot-instructions.md` for setup
```

**Integration points** (where to call webhook sender):

1. **When template is approved by admin**:
```python
def approve_template(template_id: int):
    template = StackTemplate.query.get(template_id)
    vendor = User.query.get(template.created_by_user_id)
    template.status = 'approved'
    db.session.commit()
    
    # Send webhook to User Service to create product
    webhook_sender = MarketplaceWebhookSender()
    webhook_sender.send_template_approved(template.to_dict(), vendor.to_dict())
```

2. **When template is updated**:
```python
def update_template(template_id: int, updates: dict):
    template = StackTemplate.query.get(template_id)
    template.update(updates)
    db.session.commit()
    
    if template.status == 'approved':
        vendor = User.query.get(template.created_by_user_id)
        webhook_sender = MarketplaceWebhookSender()
        webhook_sender.send_template_updated(template.to_dict(), vendor.to_dict())
```

3. **When template is rejected**:
```python
def reject_template(template_id: int):
    template = StackTemplate.query.get(template_id)
    template.status = 'rejected'
    db.session.commit()
    
    webhook_sender = MarketplaceWebhookSender()
    webhook_sender.send_template_rejected(template.to_dict())
```

### 3. Add Deployment Validation
**File**: `app/<stacker-module>/services/deployment_service.py` (update existing)

**Before allowing deployment, validate**:
```python
from .connectors.user_service_connector import UserServiceConnector

class DeploymentValidator:
    def validate_marketplace_template(self, stack_template: dict, user_token: str):
        """
        Check if user can deploy this marketplace template
        
        If template has a product in User Service:
        - Check if user owns product (in user_products table)
        - If not owned, block deployment
        """
        connector = UserServiceConnector()
        
        # If template is not marketplace template, allow deployment
        if not stack_template.get('is_from_marketplace'):
            return True
        
        # Check if template has associated product
        template_id = stack_template['id']
        product_info = connector.get_template_product(template_id)
        
        if not product_info:
            # No product = free marketplace template, allow deployment
            return True
        
        # Check if user owns this template product
        user_owns = connector.user_owns_template(user_token, template_id)
        
        if not user_owns:
            raise TemplateNotPurchasedError(
                f"This verified pro stack requires purchase. "
                f"Price: ${product_info.get('price')}. "
                f"Please purchase from User Service."
            )
        
        return True
```

**Integrate into deployment flow**:
```python
def start_deployment(template_id: int, user_token: str):
    template = StackTemplate.query.get(template_id)
    
    # Validate permission to deploy this template
    validator = DeploymentValidator()
    validator.validate_marketplace_template(template.to_dict(), user_token)
    
    # Continue with deployment...
```

## Environment Variables Needed (Stacker)
Add to Stacker's `.env`:
```bash
# User Service
URL_SERVER_USER=http://user:4100/

# Service-to-service auth token (for webhook sender)
STACKER_SERVICE_TOKEN=<bearer-token-from-user-service>

# Or use OAuth2 client credentials (preferred)
STACKER_CLIENT_ID=<from-user-service>
STACKER_CLIENT_SECRET=<from-user-service>
```

## Testing Checklist

### Unit Tests
- [ ] `test_user_service_connector.py`:
  - [ ] `get_user_profile()` returns user with products list
  - [ ] `get_template_product()` returns product info
  - [ ] `user_owns_template()` returns correct boolean
- [ ] `test_marketplace_webhook_sender.py`:
  - [ ] `send_template_approved()` sends correct webhook payload
  - [ ] `send_template_updated()` sends correct webhook payload
  - [ ] `send_template_rejected()` sends correct webhook payload
  - [ ] `get_service_token()` returns valid bearer token
- [ ] `test_deployment_validator.py`:
  - [ ] `validate_marketplace_template()` allows free templates
  - [ ] `validate_marketplace_template()` allows user-owned paid templates
  - [ ] `validate_marketplace_template()` blocks non-owned paid templates
  - [ ] Raises `TemplateNotPurchasedError` with correct message

### Integration Tests
- [ ] `test_template_approval_flow.py`:
  - [ ] Admin approves template in Stacker
  - [ ] Webhook sent to User Service `/marketplace/sync`
  - [ ] User Service creates product
  - [ ] `/oauth_server/api/me` includes new product
- [ ] `test_template_update_flow.py`:
  - [ ] Vendor updates template in Stacker
  - [ ] Webhook sent to User Service
  - [ ] Product updated in User Service
- [ ] `test_template_rejection_flow.py`:
  - [ ] Admin rejects template
  - [ ] Webhook sent to User Service
  - [ ] Product deactivated in User Service
- [ ] `test_deployment_validation_flow.py`:
  - [ ] User can deploy free marketplace template
  - [ ] User cannot deploy paid template without purchase
  - [ ] User can deploy paid template after product purchase
  - [ ] Correct error messages in each scenario

### Manual Testing
- [ ] Stacker can query User Service `/oauth_server/api/me` (with real user token)
- [ ] Stacker connector returns user profile with products list
- [ ] Approve template in Stacker admin → webhook sent to User Service
- [ ] User Service `/marketplace/sync` creates product
- [ ] Product appears in `/api/1.0/products` endpoint
- [ ] Deployment validation blocks unpurchased paid templates
- [ ] Deployment validation allows owned paid templates
- [ ] All environment variables configured correctly

## Coordination

**Dependencies**:
1. ✅ User Service - `/marketplace/sync` webhook endpoint (created in User Service TODO)
2. ✅ User Service - `products` + `user_products` tables (created in User Service TODO)
3. ⏳ Stacker - User Service connector + webhook sender (THIS TODO)
4. ✅ Payment Service - No changes needed (handles all webhooks same way)

**Service Interaction Flow**:

```
Vendor Creates Template in Stacker
  ↓
Admin Approves in Stacker
  ↓
Stacker calls MarketplaceWebhookSender.send_template_approved()
  ↓
POST http://user:4100/marketplace/sync
  {
    "action": "template_approved",
    "stack_template_id": 12345,
    "price": 99.99,
    "vendor_user_id": 456,
    ...
  }
  ↓
User Service creates `products` row
  (product_type='template', external_id=12345, vendor_id=456, price=99.99)
  ↓
Template now available in User Service `/api/1.0/products?product_type=template`
  ↓
Blog queries User Service for marketplace templates
  ↓
User views template in marketplace, clicks "Deploy"
  ↓
User pays (Payment Service handles all payment flows)
  ↓
Payment Service webhook → User Service (adds row to `user_products`)
  ↓
Stacker queries User Service `/oauth_server/api/me`
  ↓
User Service returns products list (includes newly purchased template)
  ↓
DeploymentValidator.validate_marketplace_template() checks ownership
  ↓
Deployment proceeds (user owns product)
```

## Notes

**Architecture Decisions**:
1. Stacker only sends webhooks to User Service (no bi-directional queries)
2. User Service owns monetization logic (products table)
3. Payment Service forwards webhooks to User Service (same handler for all product types)
4. `stack_template.id` (Stacker) links to `products.external_id` (User Service) via webhook
5. Deployment validation queries User Service for product ownership

**Key Points**:
- DO NOT store pricing in Stacker `stack_template` table
- DO NOT create products table in Stacker (they're in User Service)
- DO send webhooks to User Service when template status changes
- DO use Bearer token for service-to-service auth in webhooks
- Webhook sender is simpler than Stacker querying User Service (one-way communication)

## Timeline Estimate

- Phase 1 (User Service connector): 1-2 hours
- Phase 2 (Webhook sender): 1-2 hours
- Phase 3 (Deployment validation): 1-2 hours
- Phase 4 (Testing): 3-4 hours
- **Total**: 6-10 hours (~1 day)

## Reference Files
- [PAYMENT_MODEL.md](/PAYMENT_MODEL.md) - Architecture
- [try.direct.user.service/TODO.md](try.direct.user.service/TODO.md) - User Service implementation
- [try.direct.tools/TODO.md](try.direct.tools/TODO.md) - Shared utilities
- [blog/TODO.md](blog/TODO.md) - Frontend marketplace UI

---

## Synced copy from /STACKER_TODO.md (2026-01-03)

# TODO: Stacker Marketplace Payment Integration

## Context
Per [PAYMENT_MODEL.md](/PAYMENT_MODEL.md), Stacker now sends webhooks to User Service when templates are published/updated. User Service owns the `products` table for monetization, while Stacker owns `stack_template` (template definitions only).

Stacker responsibilities:
1. **Maintain `stack_template` table** (template definitions, no pricing/monetization)
2. **Send webhook to User Service** when template status changes (approved, updated, rejected)
3. **Query User Service** for product information (pricing, vendor, etc.)
4. **Validate deployments** against User Service product ownership

## Tasks

### Bugfix: Return clear duplicate slug error
- [x] When `stack_template.slug` violates uniqueness (code 23505), return 409/400 with a descriptive message (e.g., "slug already exists") instead of 500 so clients (blog/stack-builder) can surface a user-friendly error.

### 1. Create User Service Connector
**File**: `app/<stacker-module>/connectors/user_service_connector.py` (in Stacker repo)

**Required methods**:
```python
class UserServiceConnector:
    def get_user_profile(self, user_token: str) -> dict:
        """
        GET http://user:4100/oauth_server/api/me
        Headers: Authorization: Bearer {user_token}
        
        Returns:
        {
            "email": "user@example.com",
            "plan": {
                "name": "plus",
                "date_end": "2026-01-30"
            },
            "products": [
                {
                    "product_id": "uuid",
                    "product_type": "template",
                    "code": "ai-agent-stack",
                    "external_id": 12345,  # stack_template.id from Stacker
                    "name": "AI Agent Stack",
                    "price": "99.99",
                    "owned_since": "2025-01-15T..."
                }
            ]
        }
        """
        pass
    
    def get_template_product(self, stack_template_id: int) -> dict:
        """
        GET http://user:4100/api/1.0/products?external_id={stack_template_id}&product_type=template
        
        Returns product info for a marketplace template (pricing, vendor, etc.)
        """
        pass
    
    def user_owns_template(self, user_token: str, stack_template_id: int) -> bool:
        """
        Check if user has purchased/owns this marketplace template
        """
        profile = self.get_user_profile(user_token)
        return any(p['external_id'] == stack_template_id and p['product_type'] == 'template' 
                   for p in profile.get('products', []))
```

**Implementation Note**: Use OAuth2 token that Stacker already has for the user.

### 2. Create Webhook Sender to User Service (Marketplace Sync)
**File**: `app/<stacker-module>/webhooks/marketplace_webhook.py` (in Stacker repo)

**When template status changes** (approved, updated, rejected):
```python
import requests
from os import environ

class MarketplaceWebhookSender:
    """
    Send template sync webhooks to User Service
    Mirrors PAYMENT_MODEL.md Flow 3: Stacker template changes → User Service products
    """
    
    def send_template_approved(self, stack_template: dict, vendor_user: dict):
        """
        POST http://user:4100/marketplace/sync
        
        Body:
        {
            "action": "template_approved",
            "stack_template_id": 12345,
            "external_id": 12345,  # Same as stack_template_id
            "code": "ai-agent-stack-pro",
            "name": "AI Agent Stack Pro",
            "description": "Advanced AI agent deployment...",
            "price": 99.99,
            "billing_cycle": "one_time",  # or "monthly"
            "currency": "USD",
            "vendor_user_id": 456,
            "vendor_name": "John Doe"
        }
        """
        headers = {'Authorization': f'Bearer {self.get_service_token()}'}
        
        payload = {
            'action': 'template_approved',
            'stack_template_id': stack_template['id'],
            'external_id': stack_template['id'],
            'code': stack_template.get('code'),
            'name': stack_template.get('name'),
            'description': stack_template.get('description'),
            'price': stack_template.get('price'),
            'billing_cycle': stack_template.get('billing_cycle', 'one_time'),
            'currency': stack_template.get('currency', 'USD'),
            'vendor_user_id': vendor_user['id'],
            'vendor_name': vendor_user.get('full_name', vendor_user.get('email'))
        }
        
        response = requests.post(
            f"{environ['URL_SERVER_USER']}/marketplace/sync",
            json=payload,
            headers=headers
        )
        
        if response.status_code != 200:
            raise Exception(f"Webhook send failed: {response.text}")
        
        return response.json()
    
    def send_template_updated(self, stack_template: dict, vendor_user: dict):
        """Send template updated webhook (same format as approved)"""
        payload = {...}
        payload['action'] = 'template_updated'
        # Send like send_template_approved()
    
    def send_template_rejected(self, stack_template: dict):
        """
        Notify User Service to deactivate product
        
        Body:
        {
            "action": "template_rejected",
            "stack_template_id": 12345
        }
        """
        headers = {'Authorization': f'Bearer {self.get_service_token()}'}
        
        payload = {
            'action': 'template_rejected',
            'stack_template_id': stack_template['id']
        }
        
        response = requests.post(
            f"{environ['URL_SERVER_USER']}/marketplace/sync",
            json=payload,
            headers=headers
        )
        
        return response.json()
    
    @staticmethod
    def get_service_token() -> str:
        """Get Bearer token for service-to-service communication"""
        # Option 1: Use static bearer token
        return environ.get('STACKER_SERVICE_TOKEN')
        
        # Option 2: Use OAuth2 client credentials flow (preferred)
        # See User Service `.github/copilot-instructions.md` for setup
```

**Integration points** (where to call webhook sender):

1. **When template is approved by admin**:
```python
def approve_template(template_id: int):
    template = StackTemplate.query.get(template_id)
    vendor = User.query.get(template.created_by_user_id)
    template.status = 'approved'
    db.session.commit()
    
    # Send webhook to User Service to create product
    webhook_sender = MarketplaceWebhookSender()
    webhook_sender.send_template_approved(template.to_dict(), vendor.to_dict())
```

2. **When template is updated**:
```python
def update_template(template_id: int, updates: dict):
    template = StackTemplate.query.get(template_id)
    template.update(updates)
    db.session.commit()
    
    if template.status == 'approved':
        vendor = User.query.get(template.created_by_user_id)
        webhook_sender = MarketplaceWebhookSender()
        webhook_sender.send_template_updated(template.to_dict(), vendor.to_dict())
```

3. **When template is rejected**:
```python
def reject_template(template_id: int):
    template = StackTemplate.query.get(template_id)
    template.status = 'rejected'
    db.session.commit()
    
    webhook_sender = MarketplaceWebhookSender()
    webhook_sender.send_template_rejected(template.to_dict())
```

### 3. Add Deployment Validation
**File**: `app/<stacker-module>/services/deployment_service.py` (update existing)

**Before allowing deployment, validate**:
```python
from .connectors.user_service_connector import UserServiceConnector

class DeploymentValidator:
    def validate_marketplace_template(self, stack_template: dict, user_token: str):
        """
        Check if user can deploy this marketplace template
        
        If template has a product in User Service:
        - Check if user owns product (in user_products table)
        - If not owned, block deployment
        """
        connector = UserServiceConnector()
        
        # If template is not marketplace template, allow deployment
        if not stack_template.get('is_from_marketplace'):
            return True
        
        # Check if template has associated product
        template_id = stack_template['id']
        product_info = connector.get_template_product(template_id)
        
        if not product_info:
            # No product = free marketplace template, allow deployment
            return True
        
        # Check if user owns this template product
        user_owns = connector.user_owns_template(user_token, template_id)
        
        if not user_owns:
            raise TemplateNotPurchasedError(
                f"This verified pro stack requires purchase. "
                f"Price: ${product_info.get('price')}. "
                f"Please purchase from User Service."
            )
        
        return True
```

**Integrate into deployment flow**:
```python
def start_deployment(template_id: int, user_token: str):
    template = StackTemplate.query.get(template_id)
    
    # Validate permission to deploy this template
    validator = DeploymentValidator()
    validator.validate_marketplace_template(template.to_dict(), user_token)
    
    # Continue with deployment...
```

## Environment Variables Needed (Stacker)
Add to Stacker's `.env`:
```bash
# User Service
URL_SERVER_USER=http://user:4100/

# Service-to-service auth token (for webhook sender)
STACKER_SERVICE_TOKEN=<bearer-token-from-user-service>

# Or use OAuth2 client credentials (preferred)
STACKER_CLIENT_ID=<from-user-service>
STACKER_CLIENT_SECRET=<from-user-service>
```

## Testing Checklist

### Unit Tests
- [ ] `test_user_service_connector.py`:
  - [ ] `get_user_profile()` returns user with products list
  - [ ] `get_template_product()` returns product info
  - [ ] `user_owns_template()` returns correct boolean
- [ ] `test_marketplace_webhook_sender.py`:
  - [ ] `send_template_approved()` sends correct webhook payload
  - [ ] `send_template_updated()` sends correct webhook payload
  - [ ] `send_template_rejected()` sends correct webhook payload
  - [ ] `get_service_token()` returns valid bearer token
- [ ] `test_deployment_validator.py`:
  - [ ] `validate_marketplace_template()` allows free templates
  - [ ] `validate_marketplace_template()` allows user-owned paid templates
  - [ ] `validate_marketplace_template()` blocks non-owned paid templates
  - [ ] Raises `TemplateNotPurchasedError` with correct message

### Integration Tests
- [ ] `test_template_approval_flow.py`:
  - [ ] Admin approves template in Stacker
  - [ ] Webhook sent to User Service `/marketplace/sync`
  - [ ] User Service creates product
  - [ ] `/oauth_server/api/me` includes new product
- [ ] `test_template_update_flow.py`:
  - [ ] Vendor updates template in Stacker
  - [ ] Webhook sent to User Service
  - [ ] Product updated in User Service
- [ ] `test_template_rejection_flow.py`:
  - [ ] Admin rejects template
  - [ ] Webhook sent to User Service
  - [ ] Product deactivated in User Service
- [ ] `test_deployment_validation_flow.py`:
  - [ ] User can deploy free marketplace template
  - [ ] User cannot deploy paid template without purchase
  - [ ] User can deploy paid template after product purchase
  - [ ] Correct error messages in each scenario

### Manual Testing
- [ ] Stacker can query User Service `/oauth_server/api/me` (with real user token)
- [ ] Stacker connector returns user profile with products list
- [ ] Approve template in Stacker admin → webhook sent to User Service
- [ ] User Service `/marketplace/sync` creates product
- [ ] Product appears in `/api/1.0/products` endpoint
- [ ] Deployment validation blocks unpurchased paid templates
- [ ] Deployment validation allows owned paid templates
- [ ] All environment variables configured correctly

## Coordination

**Dependencies**:
1. ✅ User Service - `/marketplace/sync` webhook endpoint (created in User Service TODO)
2. ✅ User Service - `products` + `user_products` tables (created in User Service TODO)
3. ⏳ Stacker - User Service connector + webhook sender (THIS TODO)
4. ✅ Payment Service - No changes needed (handles all webhooks same way)

**Service Interaction Flow**:

```
Vendor Creates Template in Stacker
  ↓
Admin Approves in Stacker
  ↓
Stacker calls MarketplaceWebhookSender.send_template_approved()
  ↓
POST http://user:4100/marketplace/sync
  {
    "action": "template_approved",
    "stack_template_id": 12345,
    "price": 99.99,
    "vendor_user_id": 456,
    ...
  }
  ↓
User Service creates `products` row
  (product_type='template', external_id=12345, vendor_id=456, price=99.99)
  ↓
Template now available in User Service `/api/1.0/products?product_type=template`
  ↓
Blog queries User Service for marketplace templates
  ↓
User views template in marketplace, clicks "Deploy"
  ↓
User pays (Payment Service handles all payment flows)
  ↓
Payment Service webhook → User Service (adds row to `user_products`)
  ↓
Stacker queries User Service `/oauth_server/api/me`
  ↓
User Service returns products list (includes newly purchased template)
  ↓
DeploymentValidator.validate_marketplace_template() checks ownership
  ↓
Deployment proceeds (user owns product)
```

## Notes

**Architecture Decisions**:
1. Stacker only sends webhooks to User Service (no bi-directional queries)
2. User Service owns monetization logic (products table)
3. Payment Service forwards webhooks to User Service (same handler for all product types)
4. `stack_template.id` (Stacker) links to `products.external_id` (User Service) via webhook
5. Deployment validation queries User Service for product ownership

**Key Points**:
- DO NOT store pricing in Stacker `stack_template` table
- DO NOT create products table in Stacker (they're in User Service)
- DO send webhooks to User Service when template status changes
- DO use Bearer token for service-to-service auth in webhooks
- Webhook sender is simpler than Stacker querying User Service (one-way communication)

## Timeline Estimate

- Phase 1 (User Service connector): 1-2 hours
- Phase 2 (Webhook sender): 1-2 hours
- Phase 3 (Deployment validation): 1-2 hours
- Phase 4 (Testing): 3-4 hours
- **Total**: 6-10 hours (~1 day)

## Reference Files
- [PAYMENT_MODEL.md](/PAYMENT_MODEL.md) - Architecture
- [try.direct.user.service/TODO.md](try.direct.user.service/TODO.md) - User Service implementation
- [try.direct.tools/TODO.md](try.direct.tools/TODO.md) - Shared utilities
- [blog/TODO.md](blog/TODO.md) - Frontend marketplace UI


## Marketplace Template Hardened Images — Docker Hub API Enhancement

**Status:** Static analysis implemented. API-based verification pending.

### What is implemented (static analysis in `security_validator.rs`)
- `:latest` / untagged image detection
- Non-root `user:` directive detection
- `image@sha256:` digest pinning detection
- Known hardened sources: `cgr.dev/`, `gcr.io/distroless/`, `bitnami/`, `rapidfort/`, `registry1.dso.mil/`
- Docker Official Images (no-namespace single-word images like `nginx:1.25`)
- `hardened_images` auto-set in `verifications` JSONB when security scan passes
- Priority sort boost: hardened templates float to top of all `list_approved` sort orders

### TODO: Docker Hub API integration

To verify `is_official` and `is_verified_publisher` status for each image:

1. **Extend `DockerHubConnector` trait** (`src/connectors/docker_hub/connector.rs`):
   ```rust
   async fn get_repository_info(&self, namespace: &str, name: &str) -> Result<RepositoryInfo, ConnectorError>;
   ```
   Where `RepositoryInfo` adds:
   ```rust
   pub is_official: bool,
   pub is_verified_publisher: bool,
   pub pull_count: u64,
   ```

2. **Make `security_scan_handler` call Docker Hub API** for each image found in the stack:
   - Parse image names from `services.*.image`
   - For each: call `docker_hub.get_repository_info(namespace, name)`
   - Aggregate: set `hardened_images=true` if all images are official/verified-publisher OR from static hardened sources
   - Currently the validator is sync — need to either make it async or do the Docker Hub check separately in the handler (preferred)

3. **Rate limiting**: Docker Hub API allows 100 requests/hour for unauthenticated, 200/hour for authenticated. Cache results in Redis (`docker_hub:repo:{namespace}/{name}`) with 24h TTL.

4. **Trivy/Grype integration** (separate from hardened_images):
   - Run `trivy image --format json {image}` in a subprocess for each scanned stack
   - Parse CVE list, severity counts
   - Store results in `stack_template_review.security_checklist["cve_scan"]`
   - Auto-set `verifications.vulnerability_scanned = true` when scan passes (no HIGH/CRITICAL CVEs)

## Missing Features Implementation Plan (2026-04)

### Phase 1 - Marketplace Foundation and Revenue Loop
- [x] **[stacker-vendor-payouts]** Implement vendor verification and payout foundations for marketplace sellers.
  - [x] Add `marketplace_vendor_profile` storage plus admin template detail exposure with safe default fallback.
  - [x] Add admin-only partial updates for vendor verification, onboarding, payout linkage, and metadata.
  - [x] Add creator-visible vendor profile status so marketplace sellers can inspect onboarding and payout readiness.
  - [x] Add a creator self-service vendor profile endpoint that is not tied to a specific template ID.
  - [x] Add a creator onboarding-link bootstrap endpoint that idempotently creates or reuses payout linkage.
  - [x] Persist auditable onboarding metadata and completion transitions for later real provider integration.
- [x] **[stacker-template-requirements]** Add real infrastructure requirements to marketplace templates.
  - [x] Store supported clouds, minimum RAM/disk/CPU, supported OS, and related compatibility metadata.
  - [x] Use these fields in marketplace create/read/update flows and webhook payloads.
  - [x] Use `supported_clouds` and `supported_os` in deployment validation so incompatible targets are blocked early.
  - [x] Add a shared backend server-capacity resolver for normalized App Service `/servers` catalog data.
  - [x] Enforce `min_ram_mb` during deploy validation using the shared capacity resolver on both deploy entry points.
  - [x] Extend numeric deploy validation to `min_disk_gb` and `min_cpu_cores`.
- [ ] **[stacker-review-notifications]** Close the creator feedback loop for template reviews.
  - [x] Normalize `needs_changes` as a real admin review outcome with creator-visible review history and guarded admin routing.
  - [ ] Send notifications for submit/approve/reject/update-required events.
  - Include actionable review reasons and the next expected developer action.

### Phase 2 - Reliability and User-Facing Correctness
- [x] **[stacker-duplicate-slug-409]** Return a clear conflict response when a marketplace slug already exists.
  - Convert duplicate-slug failures from generic 500 errors into explicit 409/validation feedback.
  - Keep CLI and UI messaging aligned so the user gets a recoverable error.
- [ ] **[stacker-agent-alerts]** Add server-side endpoint to receive outbound alerts from Status Panel agents.
  - Status Panel now sends `POST` webhook with `X-Agent-Id` header when host metrics breach thresholds.
  - Implement `POST /api/v1/agents/alerts` (or similar) to receive the payload:
    ```json
    {
      "alerts": [{
        "kind": "high_cpu" | "high_memory" | "high_disk",
        "severity": "warning" | "critical",
        "message": "CPU usage at 96.2% (threshold: 95%)",
        "value": 96.2,
        "threshold": 95.0,
        "recovered": false,
        "timestamp_ms": 1700000000000,
        "agent_id": "agent-123"
      }],
      "agent_id": "agent-123",
      "timestamp_ms": 1700000000000
    }
    ```
  - Return `2xx` on success, `4xx` on bad request (agent won't retry), `5xx` triggers agent retry (3x, exponential backoff).
  - Validate `X-Agent-Id` header and match to known agent registration.
  - Store alerts in DB for history; optionally fan out to notification channels (email/Slack).
  - Surface active/recent alerts in admin dashboard per-server view.
- [ ] **[stacker-rollback]** Add version-aware deployment rollback.
  - Allow operators to choose a prior template or deployment version and roll back safely.
  - Persist rollback history and expose the effective version in deployment details.

### Phase 3 - Team and Integration Expansion
- [x] **[stacker-ci-exporters]** Extend CI/CD export support beyond GitHub and GitLab.
  - [x] Add Bitbucket Pipelines export and validate support, including aliases and stale/missing file checks.
  - [x] Add Jenkinsfile export and validate support using the same `STACKER_TOKEN` convention.
  - Keep export templates aligned with current Stacker project and secret conventions.
- [ ] **[stacker-team-projects]** Add shared project ownership and team collaboration primitives.
  - Introduce org/team ownership, invitations, seat-aware permissions, and shared deployment visibility.
  - Define how ownership flows through marketplace, deployments, and future billing.

### Phase 4 - Control Plane Completion
- [ ] **[stacker-pipe-execution]** Finish pipe execution end-to-end across Stacker and Status Panel.
  - Ensure the server, queueing layer, and agent all support the same pipe command set.
  - Coordinate command provenance, reporting, and error surfaces with Status Panel.

### Delivery Order
- [ ] Start with `stacker-vendor-payouts`, `stacker-template-requirements`, and `stacker-duplicate-slug-409`.
- [ ] Follow with `stacker-agent-alerts`, `stacker-review-notifications`, and `stacker-rollback` once the marketplace data contract is stable.
- [ ] Treat `stacker-team-projects` and `stacker-pipe-execution` as multi-sprint workstreams with cross-project coordination.


## MCP safe troubleshooting snapshots

- Added `request_server_snapshot` MCP tool for Hetzner-first pre-remediation snapshots.
- Snapshot creation requires explicit `confirm_snapshot=true` because it is a provider write operation.
- Follow-up: add a shared risk guard to destructive MCP tools (`get_container_exec`, `restart_container`, `stop_container`, `remove_app`, force `deploy_app`, proxy/firewall writes) so they can require a recent `snapshot_id`/provider action before execution.
