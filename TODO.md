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
