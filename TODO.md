# TODO
- Align build and runtime images so the compiled `status` binary links against the same glibc version (or older) as production.
- Add a musl-based build target and image variant to provide a statically linked binary that avoids glibc drift.
- Update CI to build/test using the production base image to prevent future GLIBC_x.y.z mismatches.
- Add a simple container start-up check that surfaces linker/runtime errors early in the pipeline.

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
- [ ] Expose health metrics indicating which control plane executed each command (`status_panel` vs `compose_agent`) so ops can track rollout and fallbacks.
- [ ] Publish Vault secret schema: `secret/agent/{hash}/status_panel_token` and `secret/agent/{hash}/compose_agent_token`; refresh + cache them independently.
- [x] Add config flag to disable compose agent (legacy mode) and emit warning log so Blog receives `compose_agent=false` via `/capabilities`.
