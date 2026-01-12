# Status Panel Integration Notes (Stacker UI)

**Audience**: Stacker dashboard + Status Panel UI engineers  
**Scope**: How to consume/emit the canonical Status Panel command payloads and show them in the UI.

---

## 1. Command Dispatch Surfaces

| Action | HTTP call | Payload source |
|--------|-----------|----------------|
| Queue new command | `POST /api/v1/commands` (Stacker UI) | Uses `src/forms/status_panel.rs::validate_command_parameters` |
| Agent report | `POST /api/v1/agent/commands/report` (Status Panel Agent) | Validated via `forms::status_panel::validate_command_result` |
| Command feed | `GET /api/v1/commands/{deployment_hash}` | UI polling for history |

All POST requests continue to use Vault-issued HMAC headers (`X-Agent-Id`, `X-Timestamp`, `X-Request-Id`, `X-Agent-Signature`). There is no alternate auth path—reuse the existing AgentClient helpers.

---

## 2. Payload Details (UI Expectations)

### Health
Request fields:
- `deployment_hash`, `app_code`, `include_metrics` (default `true`)

Report fields:
- `status` (`ok|unhealthy|unknown`)
- `container_state` (`running|exited|starting|failed|unknown`)
- `last_heartbeat_at` (RFC3339) for charts/tooltips
- `metrics` (object, e.g., `{ "cpu_pct": 0.12, "mem_mb": 256 }`)
- `errors[]` list of `{code,message,details?}` rendered inline when present

**UI**: Show health badge using `status`, render container state chip, and optionally chart CPU/memory using `metrics` when `include_metrics=true`.

### Logs
Request fields:
- `cursor` (nullable resume token)
- `limit` (1-1000, default 400)
- `streams` (subset of `stdout|stderr`)
- `redact` (default `true`)

Report fields:
- `cursor` (next token)
- `lines[]` entries: `{ ts, stream, message, redacted }`
- `truncated` boolean so UI can show “results trimmed” banner

**UI**: Append `lines` to log viewer keyed by `stream`. When `redacted=true`, display lock icon / tooltip. Persist the returned `cursor` to request more logs.

### Restart
Request fields:
- `force` (default `false`) toggled via UI “Force restart” checkbox

Report fields:
- `status` (`ok|failed`)
- `container_state`
- `errors[]` (same format as health)

**UI**: Show toast based on `status`, and explain `errors` when restart fails.

---

## 3. UI Flow Checklist

1. **App selection**: Use `app_code` from `deployment_apps` table (already exposed via `/api/v1/project/...` APIs).
2. **Command queue modal**: When user triggers Health/Logs/Restart, send the request body described above via `/api/v1/commands`.
3. **Activity feed**: Poll `/api/v1/commands/{deployment_hash}` and map `command.type` to the templates above for rendering.
4. **Error surfaces**: Display aggregated `errors` list when commands finish with failure; they are already normalized server-side.
5. **Auth**: UI never handles agent secrets directly. Handoff happens server-side; just call the authenticated Stacker API.

---

## 4. References

- Canonical Rust schemas: `src/forms/status_panel.rs`
- API surface + auth headers: [STACKER_INTEGRATION_REQUIREMENTS.md](STACKER_INTEGRATION_REQUIREMENTS.md#status-panel-command-payloads)
- Field-by-field documentation: [AGENT_REGISTRATION_SPEC.md](AGENT_REGISTRATION_SPEC.md#field-reference-canonical-schemas)
- Operational overview: [QUICK_REFERENCE.md](QUICK_REFERENCE.md#status-panel-command-payloads)

Keep this document in sync when new command types or fields are introduced.
