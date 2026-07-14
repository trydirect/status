# AI Deployment Workflows

This guide documents the canonical AI-facing deployment workflow for Stacker.
It is intended for MCP clients, frontend chat integrations, and evaluation
fixtures that need a stable inspect -> explain -> plan -> apply -> recover
sequence.

## Canonical tools

| Tool | Purpose | Notes |
| --- | --- | --- |
| `get_deployment_state` | Inspect canonical machine-readable deployment state | Prefer this over parsing `get_deployment_status` |
| `explain_topology` | Explain runtime compose and env paths without secret values | Safe for path and service reasoning |
| `explain_env` | Explain env provenance for one app without disclosing secret values | Returns layer names, key names, hashes, and destination metadata |
| `get_deployment_plan` | Preview deploy or rollback actions and produce a stable fingerprint | Use before any mutation |
| `apply_deployment_plan` | Apply a previously previewed plan | Requires `confirm=true`, `expected_fingerprint`, and MFA |
| `get_deployment_events` | Observe progress, failure, and remediation signals | Use during apply and recovery loops |
| `get_app_env_vars` | Inspect app env values with explicit secure metadata | Prefer `environment_entries` for `secure`/`source` flags |

## Compatibility rules

1. Prefer `get_deployment_state`, `get_deployment_plan`, and
   `get_deployment_events` over `get_deployment_status` when an AI client needs
   stable structured fields.
2. Treat MCP tool payloads as explicit allow-list responses. Do not depend on
   internal model fields that are not present in the documented response.
3. For tool failures, read `result.isError` and parse the JSON string in
   `result.content[0].text` as a typed error envelope.
4. `apply_deployment_plan` is intentionally narrower than local CLI deploy:
   server-side MCP supports `deploy_app` and `rollback_deploy`, but rejects full
   `deploy` apply because that still requires local workspace context.

## Recommended workflow

### 1. Inspect current state

Call `get_deployment_state` first to inspect status, drift, last command, agent
health, and app inventory.

```json
{
  "name": "get_deployment_state",
  "arguments": {
    "deployment_hash": "deployment_state_online"
  }
}
```

### 2. Explain topology or env provenance

Use `explain_topology` when the AI needs runtime paths and service inventory.
Use `explain_env` when it needs to reason about env provenance for one app.
Use `get_app_env_vars` when it needs the redacted env payload itself together
with explicit `secure` and `source` metadata for each variable.

```json
{
  "name": "explain_topology",
  "arguments": {
    "deployment_hash": "deployment_state_online"
  }
}
```

```json
{
  "name": "explain_env",
  "arguments": {
    "deployment_hash": "deployment_state_online",
    "app_code": "device-api"
  }
}
```

```json
{
  "name": "get_app_env_vars",
  "arguments": {
    "project_id": 42,
    "app_code": "device-api"
  }
}
```

The response preserves the legacy redacted object in `environment_variables`,
but new clients should prefer `environment_entries` because Vault-backed
service-secret keys are marked with `secure=true` and `source="vault"` even
when their names are not obviously secret-like.

### 3. Preview a plan and capture its fingerprint

Always preview with `get_deployment_plan` before a mutation. The returned
`fingerprint` is the stale-plan guard that must be echoed into
`apply_deployment_plan`.

```json
{
  "name": "get_deployment_plan",
  "arguments": {
    "deployment_hash": "deployment_state_online",
    "operation": "deploy_app",
    "app_code": "device-api"
  }
}
```

For rollback preview:

```json
{
  "name": "get_deployment_plan",
  "arguments": {
    "deployment_hash": "deployment_state_online",
    "operation": "rollback_deploy",
    "rollback_target": "previous"
  }
}
```

### 4. Apply with confirmation

Mutations require an explicit human confirmation signal. Frontends should gate
this tool behind a confirmation prompt and step-up auth/MFA check.

```json
{
  "name": "apply_deployment_plan",
  "arguments": {
    "deployment_hash": "deployment_state_online",
    "operation": "deploy_app",
    "app_code": "device-api",
    "expected_fingerprint": "plan_fingerprint_from_preview",
    "confirm": true
  }
}
```

### 5. Recover using events and rollback

If an apply fails or the deployment enters an unhealthy state:

1. Call `get_deployment_events` to read remediation signals.
2. Preview a rollback with `get_deployment_plan` and
   `operation=rollback_deploy`.
3. Apply that rollback with `apply_deployment_plan`.
4. Re-read `get_deployment_events` and `get_deployment_state` until the state is
   healthy or a typed error indicates the next remediation step.

## Frontend integration requirements

- Add `apply_deployment_plan` to the frontend's confirmation-required tool list.
- Preserve the exact `expected_fingerprint` returned by preview.
- Surface typed MCP errors directly instead of flattening them into generic
  failure text.
- Do not request or display raw secret values from explain or state payloads;
  those surfaces are intentionally redaction-first.

## Evaluation fixtures

The versioned evaluation scenarios live in
`tests/contracts/stacker-ai-workflows.v1alpha1.json`.
The stable response schemas and samples live alongside them in
`tests/contracts/`.

## Qwen website scenario bootstrap

Stacker also includes a model-targeted convenience layer for simple website
projects. This is separate from the canonical MCP workflow above.

### Trigger

- `stacker init --with-ai` generates `stacker.yml` and `.stacker/` artifacts as
  usual.
- If the project looks like a simple HTML/static site or a Next.js app, and the
  configured Ollama model contains `qwen2.5-code` or `qwen2.5-coder`, Stacker
  offers to bootstrap the built-in `website-deploy` scenario.

### What the bootstrap does

1. Reads the generated `stacker.yml` and local project hints.
2. Seeds known scenario variables such as project name, app type, proxy shape,
   cloud settings, and AI provider/model settings.
3. Prompts only for missing deploy-critical values such as public domain, image
   repository/tag, and cloud target details.
4. Saves state under `.stacker/scenarios/qwen2.5-code/website-deploy/state.json`.
5. Starts the scenario at the `init-validate` step and prints the next exact
   commands to run.

### Continue a scenario later

```bash
stacker ai ask "continue" --scenario website-deploy --step init-validate
stacker ai ask "continue" --scenario website-deploy --step image-publish
stacker ai ask "continue" --scenario website-deploy --step cloud-deploy
stacker ai --scenario website-deploy --step runtime-ops
```

### Scenario content layout

- Built-in files live under `scenarios/qwen2.5-code/website-deploy/`.
- Project-local overrides can be placed under
  `.stacker/scenarios/qwen2.5-code/website-deploy/`.
- The saved state file lives beside those overrides in the same `.stacker`
  directory tree.
