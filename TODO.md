# TODO
- Align build and runtime images so the compiled `status` binary links against the same glibc version (or older) as production.
- Add a musl-based build target and image variant to provide a statically linked binary that avoids glibc drift.
- Update CI to build/test using the production base image to prevent future GLIBC_x.y.z mismatches.
- Add a simple container start-up check that surfaces linker/runtime errors early in the pipeline.

## Status Panel Agent Commands
- [x] Implement handlers for Stacker command types (`health`, `logs`, `restart`) on `/api/v1/commands/execute|enqueue` with HMAC verification.
- [x] Health: return container state, status enum (`ok|unhealthy|unknown`), last heartbeat, optional CPU/mem metrics; fail closed if container unreachable.
- [x] Logs: support cursor + limit, streams stdout/stderr, redact secrets before returning, mark `truncated` flag.
- [x] Restart: restart container by app_code, then emit updated state in report payload; include errors array on failure.
- [x] Reporting: respond via `/api/v1/agent/commands/report` with the proposed schemas in stacker/docs/AGENT_REGISTRATION_SPEC.md (keep deployment_hash + app_code).
- [ ] Wire agent to `wait` loop using Vault-fetched token; refresh token on 401/403 and retry with backoff.

## Compose Agent Sidecar
- [ ] Ship a separate `compose-agent` container (Docker Compose + MCP Gateway) deployed alongside the Status Panel container; Service file should ensure it mounts the Docker socket while Status Panel does not.
- [ ] Implement watchdog to restart only the compose container on failure/glibc mismatch without touching the Status Panel daemon; prove via integration test.
- [ ] Expose health metrics indicating which control plane executed each command (`status_panel` vs `compose_agent`) so ops can track rollout and fallbacks.
- [ ] Publish Vault secret schema: `secret/agent/{hash}/status_panel_token` and `secret/agent/{hash}/compose_agent_token`; refresh + cache them independently.
- [ ] Add config flag to disable compose agent (legacy mode) and emit warning log so Blog receives `compose_agent=false` via `/capabilities`.
