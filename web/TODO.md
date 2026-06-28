# TODO

## MCP coverage gaps from the Status website scenario

Use this table to complete MCP parity and then re-check the full onboarding
scenario end to end.

| Scenario step | MCP coverage |
|---|---|
| `npm install`, `npm run build` | No - local workstation command, outside Stacker MCP |
| `docker build`, `docker run`, local health check | No - local Docker/runtime validation |
| `stacker login` | No - authentication/bootstrap flow, not an MCP tool |
| `stacker init` generating `stacker.yml` and `.stacker/Dockerfile` | No direct equivalent |
| `.env` bootstrap from `.env.example` | Gap - no MCP/local-bootstrap tool |
| `stacker config setup ai` | Gap - no MCP tool for local AI config setup |
| Parse/discover compose services | Yes - `discover_stack_services` |
| Create project/app records | Yes - `create_project`, `create_project_app` |
| Validate server-side stack config | Partial - `validate_stack_config`, but not the same as local `stacker config validate` |
| `stacker config fix`, `show`, `inventory`, `diff`, `check`, `promote` | Gap - no MCP parity for local config workflows |
| Deploy project/app | Yes - `start_deployment`, `initiate_deployment`, `deploy_app`, deployment plan tools |
| Paused deploy troubleshooting | Yes - `diagnose_deployment` now returns MCP tool sequence, safe AI context rules, and `stacker-cli` recovery commands |
| Agent status | Yes - `get_agent_status` |
| Logs/health/containers | Yes - `get_container_logs`, `get_container_health`, `list_containers` |
| Proxy/NPM setup | Yes - `configure_proxy`, `configure_proxy_agent`, `list_proxies`, `delete_proxy` |
| Remote service secrets | Yes - `list_remote_secret_targets`, `set_remote_service_secret`, and related remote secret tools |
| Private registry auth setup | Gap - no MCP/local workflow for deploy registry credentials |
| Cloud provider firewall commands | Partial/gap - MCP has target/server firewall tools, but not the same cloud-provider firewall list/add flow |
| `stacker agent install` / managed runtime refresh | Gap - no MCP tool found for agent install/refresh |
| Pipes | Gap - no MCP tools found for `pipe scan/create/activate/trigger/history` |

## Follow-up MCP work

1. Add a local/bootstrap MCP or companion workflow for `stacker init` parity.
2. Add MCP parity for local config workflows: inventory, diff, promote, check,
   and local `stacker config validate`.
3. Add cloud-provider firewall MCP tools that match `stacker cloud firewall`
   list/add behavior.
4. Add an agent install/refresh MCP tool for the Status Panel and managed
   runtime features.
5. Add pipe management MCP tools for scan, create, activate, trigger, and
   history.
6. Re-run the Status website onboarding story and update this table after each
   gap is closed.

## Stacker onboarding UX gaps found during the walkthrough

These are places where the walkthrough required manual editing or manual
diagnosis that Stacker should handle directly.

| Gap | Better Stacker behavior |
|---|---|
| Missing `.env` required by `docker-compose.yml` | `stacker init` or `stacker deploy` should detect `env_file: .env`, offer to create `.env` from `.env.example`, and apply safe permissions |
| `--key` / `--key-id` still entered the cloud-selection path when `deploy.cloud` was missing | CLI cloud overrides should populate cloud config in memory before any prompt or remote lookup |
| Generated config had nullable structural fields | `stacker init` should emit compact, validation-clean YAML by default |
| Existing config still has nullable structural fields | `stacker config fix` should remove null structural fields without hand-editing YAML |
| Private image registry auth required explanation | `stacker deploy` should detect likely private-image pull risk and prompt for registry auth source or show exact env/config options |
| AI configuration required manual YAML editing | Add `stacker config setup ai` or `stacker ai configure --provider ollama --endpoint ... --model ...` |
| User-facing API errors exposed raw route/body details | Hide endpoints and raw bodies by default; show details only with `DEBUG=true`, `STACKER_DEBUG=true`, or `RUST_LOG=debug` |

## Completed Stacker fixes during this walkthrough

| Fix | Status |
|---|---|
| Compact `stacker init` output for future generated configs | Implemented in Stacker repo by background agent |
| Debug-gated Stacker API route/body errors | Implemented in Stacker repo by background agent |
| Missing `.env` referenced by compose/config | Implemented in Stacker repo: deploy copies from `.env.example` with restrictive permissions or returns actionable guidance |
| `--key` / `--key-id` cloud deploy overrides | Implemented in Stacker repo: resolved through the logged-in Stacker API before prompt selection |
| Non-interactive cloud selection | Implemented in Stacker repo: skips hanging prompts and tells the user to pass `--key`, `--key-id`, or configure cloud defaults |
| Existing config with nullable structural fields | Implemented in Stacker repo: validation suggests `stacker config fix`; fix removes empty structural path fields |
| Private image registry auth guidance | Implemented in Stacker repo: deploy prints concise credential guidance when needed |
| AI configuration without manual YAML edits | Implemented in Stacker repo: `stacker config setup ai` |
| Hetzner location/datacenter mismatch during cloud provisioning | Implemented in Stacker repo: deploy preserves the requested size and normalizes Hetzner locations such as `nbg1` before publishing installer payloads |
| Remote `.env` path mismatch during cloud install | Implemented in Stacker repo: config bundles now keep compose file references project-relative so copied files and Docker Compose paths match |
| Remote `.env` not materialized by installer | Implemented in Stacker repo: deploy-time config files are mirrored into installer runtime-file metadata before deployment |
| Paused deployment recovery path was tribal knowledge | Documented in `docs/recover-paused-deployment.md`: inspect status, use backup SSH key, classify failure, apply temporary fixes, ask AI safely, and redeploy |
