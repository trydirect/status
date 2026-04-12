# TODO

## Marketplace Integration: Agent Registration & Local Deploy

### Agent Self-Registration (for curl one-liner and manual install entry points)
- [x] **`POST /api/v1/register`** (local endpoint on Status Panel) — Triggered after install.sh completes
  - Accept `{ purchase_token, stack_id }` from install script
  - Collect server fingerprint (hostname, IP, OS, CPU, RAM, disk)
  - Call Stacker Server: `POST /api/v1/agents/register { purchase_token, server_fingerprint, stack_id }`
  - Store returned `agent_id`, `deployment_hash`, `dashboard_url` locally
  - Begin heartbeat loop to Stacker Server
- [x] **Local `stacker deploy` trigger** — After registration, Status Panel invokes Stacker CLI locally
  - `stacker deploy --from /opt/stacker/stacks/{stack_id}/` (the downloaded archive)
  - Monitor deploy progress, report status back to Stacker Server via existing agent report endpoint
  - No Install Service involved — fully local execution

### Dashboard Linking (optional, user-initiated)
- [x] Provide web UI page at `http://localhost:{STATUS_PORT}/link` to connect Status Panel to TryDirect dashboard
- [x] Support unlinking from dashboard (agent continues to work standalone)
- [x] **Login-based linking flow (Entry Point C):**
  - User logs in with TryDirect email + password from Status Panel UI
  - Status Panel calls Stacker: `POST /api/v1/auth/login { email, password }` → returns `session_token` + user's deployments
  - User selects a deployment from the list → Status Panel calls Stacker: `POST /api/v1/agents/link { session_token, deployment_id, server_fingerprint }`
  - Stacker validates session, checks user owns the deployment, issues `agent_id` + `agent_token`
  - No purchase_token needed — user's identity is the trust anchor
  - `purchase_token` flow retained only for headless Entry Point B (curl one-liner)
- [x] Add "Use Standalone" option for users without TryDirect account (skip linking entirely)

### Standalone Status Panel Entry Point (Phase 2)
- [x] **"Deploy a Stack" page** in Status Panel web UI
  - Browse available stacks from marketplace API: `GET /api/v1/marketplace/stacks`
  - User selects stack → Status Panel downloads archive + calls `stacker deploy` locally
  - This enables Entry Point C: user installs Status Panel first, then deploys stacks from its UI

### Notifications Relay
- [x] Forward marketplace notifications (stack published, update available) from Stacker Server to Status Panel UI
- [x] Show "Update Available" badge when a newer version of the deployed stack exists

---
- ~~Align build and runtime images so the compiled `status` binary links against the same glibc version (or older) as production.~~ ✅ Done — Dockerfiles use `clux/muslrust:stable` → `gcr.io/distroless/cc`, musl avoids glibc drift.
- ~~Add a musl-based build target and image variant to provide a statically linked binary that avoids glibc drift.~~ ✅ Done — CI builds `x86_64-unknown-linux-musl` target, releases musl binary.
- Update CI to build/test using the production base image to prevent future GLIBC_x.y.z mismatches.
- Add a simple container start-up check that surfaces linker/runtime errors early in the pipeline.

## Missing Features Implementation Plan (2026-04)

### Phase 1 - Reliability and Production Readiness
- [ ] **[status-auth-refresh]** Refresh agent auth immediately on 401/403 and retry polling/report calls with backoff.
  - Wire the retry path into the polling loop instead of waiting for the periodic refresh task.
  - Define the Vault path/role contract for `status_panel_token` and document failure handling.
- [ ] **[status-alerting]** Add outbound alert delivery for unhealthy containers, command failures, and host-level incidents.
  - Start with webhook delivery, then add Slack/email adapters if needed.
  - Include alert deduplication, severity, and recovery notifications.
- [x] **[status-command-provenance]** Surface which control plane executed each action (`status_panel` vs `compose_agent`).
  - Expose provenance in command reports, health metrics, and `/capabilities`-driven diagnostics.
  - Publish and implement the separate token/cache schema for `compose_agent_token`.
- [ ] **[status-ssl-renewal]** Automate SSL certificate renewal for hosts that enable HTTPS.
  - Add renewal scheduling, renewal result logging, and certificate reload without manual intervention.

### Phase 2 - Data Safety and Day-2 Operations
- [ ] **[status-volume-backups]** Add scheduled backup and restore support for Docker volumes.
  - Support policy-driven backups for stateful services, retention, restore validation, and signed metadata.
  - Reuse existing backup/security primitives where possible instead of introducing a separate backup path.

### Phase 3 - Standalone and Dashboard UX
- [x] **[status-login-linking]** Complete the login-based dashboard linking flow and standalone mode.
  - Finish the UI + daemon wiring for email/password linking to an owned deployment.
  - Add "Use Standalone" so the panel is usable without a TryDirect account.
- [x] **[status-deploy-stack-ui]** Build the local "Deploy a Stack" flow in Status Panel.
  - Browse marketplace stacks, download the selected archive, and trigger local `stacker deploy`.
  - Show deployment progress, update availability, and compatibility checks in the local UI.

### Cross-Project Coordination
- [ ] Coordinate `status-deploy-stack-ui` with Stacker marketplace archive/download validation.
- [ ] Coordinate `status-command-provenance` and future pipe execution with the Stacker control-plane roadmap.

## Status Panel Agent Commands (Pull Model)
**Key principle**: Agent polls Stacker; Stacker never pushes to the agent. Agent is responsible for adding HMAC headers on its outbound calls.

- [x] Implement command handlers (`health`, `logs`, `restart`) that execute locally when commands are dequeued.
- [x] Health: return container state, status enum (`ok|unhealthy|unknown`), last heartbeat, optional CPU/mem metrics; fail closed if container unreachable.
- [x] Logs: support cursor + limit, streams stdout/stderr, redact secrets before returning, mark `truncated` flag.
- [x] Restart: restart container by app_code, then emit updated state in report payload; include errors array on failure.
- [x] Reporting: call Stacker `POST /api/v1/agent/commands/report` with HMAC headers (`X-Agent-Id`, `X-Timestamp`, `X-Request-Id`, `X-Agent-Signature`) signed using Vault token.
- [x] Wire agent to poll loop: `GET /api/v1/agent/commands/wait/{deployment_hash}` with HMAC headers.
- [ ] On 401/403, refresh token from Vault and retry with backoff (which Vault path/role should we use for the agent token?).
- [x] Ensure agent generates HMAC signature for every outbound request (wait + report + app status); no secrets expected from Stacker side.

## Compose Agent Sidecar
- [x] Ship a separate `compose-agent` container (Docker Compose + MCP Gateway) deployed alongside the Status Panel container; Service file should ensure it mounts the Docker socket while Status Panel does not.
- [x] Implement watchdog to restart only the compose container on failure/glibc mismatch without touching the Status Panel daemon; prove via integration test.
- [x] Expose health metrics indicating which control plane executed each command (`status_panel` vs `compose_agent`) so ops can track rollout and fallbacks.
- [x] Publish Vault secret schema: `secret/agent/{hash}/status_panel_token` and `secret/agent/{hash}/compose_agent_token`; refresh + cache them independently.
- [x] Add config flag to disable compose agent (legacy mode) and emit warning log so Blog receives `compose_agent=false` via `/capabilities`.

## Kata Containers Support (Stacker Server)
**Context**: The Status Panel Agent now supports `runtime` field (`runc`/`kata`) on `deploy_app` and `deploy_with_configs` commands, detects Kata availability via `docker info`, injects `runtime:` per-service into compose YAML, and reports `"kata"` in `/capabilities` features when available.

### Stacker API Changes
- [ ] Add `runtime` field (string, optional, default `"runc"`) to `POST /api/v1/agent/commands/enqueue` payload for `deploy_app` and `deploy_with_configs` commands.
- [ ] Add `runtime` field to the deployment model/database so per-deployment runtime preference is persisted across redeploys and restarts.
- [ ] Validate `runtime` values on the Stacker side (`runc`, `kata`); reject unknown values with 422.
- [ ] Read agent `/capabilities` response and store `kata` feature flag per agent; use this to prevent scheduling Kata deployments on agents that don't support it.

### CLI / UI Integration
- [ ] Add `--runtime kata|runc` flag to `stacker deploy` CLI command; pass through to the agent command payload.
- [ ] Show runtime selection option in the deployment UI (dropdown or toggle); default to `runc`, show `kata` only if agent capabilities include it.
- [ ] Display effective runtime in deployment detail view (agent reports `"runtime"` in deploy result body).
- [ ] Show `kata_fallback` warnings from agent result in the UI/CLI output so users know when Kata was unavailable.

### Vault / Config Management
- [ ] Allow per-deployment runtime preference in Vault (`secret/agent/{hash}/runtime_preference`); agent can read this as a default when no explicit `runtime` is in the command payload.
- [ ] Support org-level policy: "all deployments must use Kata" — Stacker enforces this before enqueuing commands.

### J2 Template Updates
- [ ] Update compose J2 templates to optionally include `runtime:` field per-service when Kata is requested (alternative to agent-side YAML injection for new deployments).
- [ ] Document that `runtime:` in compose YAML and `runtime` in command payload are complementary — agent-side injection is the fallback when templates don't include it.

### Host Provisioning
- [ ] Create Ansible playbook for Kata setup: install `kata-containers`, configure `daemon.json` with Kata runtime, validate KVM access.
- [ ] Add Terraform module for provisioning Kata-ready bare-metal hosts (Hetzner, OVH) with KVM enabled.
- [ ] Document network constraints: Kata containers cannot use `network_mode: host`; advise `bridge` or `macvlan`.

### Monitoring & Observability
- [ ] Add Prometheus metric `agent_deploy_runtime{runtime="kata|runc"}` counter to track Kata adoption.
- [ ] Log `kata_fallback` events in agent audit trail for ops visibility.
- [ ] Add dashboard widget showing Kata vs runc deployment distribution across fleet.
