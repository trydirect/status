# Stacker ⇄ Status Panel Agent: Integration Requirements (v2)

Date: 2025-12-25
Status: Ready for Stacker implementation
Scope: Applies to POST calls from Stacker to the agent (execute/enqueue/report/rotate-token). GET /wait remains ID-only with rate limiting.

---

## Overview
The agent now enforces authenticated, integrity-protected, and replay-safe requests for all POST endpoints using HMAC-SHA256 with the existing `AGENT_TOKEN`. Additionally, per-agent rate limiting and scope-based authorization are enforced. This document describes what the Stacker team must implement and how to migrate safely.

---

## Required Headers (POST requests)
Stacker must include the following headers on every POST request to the agent:

- Authorization: Bearer <AGENT_TOKEN>
- X-Agent-Id: <AGENT_ID>
- X-Timestamp: <unix_seconds>            // request creation time
- X-Request-Id: <uuid_v4>                // unique per request
- X-Agent-Signature: <base64 HMAC-SHA256(body, AGENT_TOKEN)>

Notes:
- Signature is computed over the raw HTTP request body (exact bytes) using `AGENT_TOKEN`.
- `X-Timestamp` freshness window defaults to 300 seconds (configurable on agent).
- `X-Request-Id` is cached to prevent replays for a TTL of 600 seconds by default.

---

## Scopes and Authorization
The agent enforces scope checks. Scopes are configured on the agent side via `AGENT_SCOPES` env var. Stacker must ensure it only calls operations allowed by these scopes. Required scopes by endpoint/operation:

- POST /api/v1/agent/commands/execute: `commands:execute`
  - When `name` is a Docker operation, also require one of:
    - `docker:restart` | `docker:stop` | `docker:pause` | `docker:logs` | `docker:inspect`
- POST /api/v1/agent/commands/enqueue: `commands:enqueue`
- POST /api/v1/agent/commands/report: `commands:report`
- POST /api/v1/auth/rotate-token: `auth:rotate`

Example agent configuration (set at deploy time):
- `AGENT_SCOPES=commands:execute,commands:report,commands:enqueue,auth:rotate,docker:restart,docker:logs`

---

## Rate Limiting
The agent limits requests per-agent (keyed by `X-Agent-Id`) within a sliding one-minute window.
- Default: `RATE_LIMIT_PER_MIN=120` (configurable on agent)
- On 429 Too Many Requests, Stacker should back off with jitter (e.g., exponential backoff) and retry later.

---

## Endpoints (with requirements)

1) POST /api/v1/agent/commands/execute
- Headers: All required POST headers above
- Body: JSON `AgentCommand`
- Scopes: `commands:execute` and, for Docker operations, the specific docker:* scope
- Errors: 400 invalid JSON; 401 missing/invalid signature or Agent-Id; 403 insufficient scope; 409 replay; 429 rate limited; 500 internal

2) POST /api/v1/agent/commands/enqueue
- Headers: All required POST headers above
- Body: JSON `AgentCommand`
- Scope: `commands:enqueue`
- Errors: same as execute

3) POST /api/v1/agent/commands/report
- Headers: All required POST headers above
- Body: JSON `CommandResult`
- Scope: `commands:report`
- Errors: same as execute

4) POST /api/v1/auth/rotate-token
- Headers: All required POST headers above (signed with current/old token)
- Body: `{ "new_token": "..." }`
- Scope: `auth:rotate`
- Behavior: On success, agent replaces in-memory `AGENT_TOKEN` with `new_token` (no restart needed)
- Errors: same as execute

5) GET /api/v1/agent/commands/wait/{hash}
- Headers: `Authorization: Bearer <AGENT_TOKEN>`, `X-Agent-Id` (signature not enforced on GET)
- Behavior: Long-poll queue; returns 204 No Content on timeout
- Added: Lightweight per-agent rate limiting and audit logging

---

## Signature Calculation

Pseudocode:
```
body_bytes = raw_request_body
key = AGENT_TOKEN
signature = Base64( HMAC_SHA256(key, body_bytes) )
Send header: X-Agent-Signature: signature
```

Validation behavior:
- Agent decodes `X-Agent-Signature` (base64, with hex fallback) and compares to local HMAC in constant time.
- `X-Timestamp` is required and must be fresh (default skew ≤ 300s).
- `X-Request-Id` is required and must be unique within replay TTL (default 600s).

---

## Example: cURL

```
# assumes AGENT_ID and AGENT_TOKEN known, and we computed signature over body.json
curl -sS -X POST http://agent:5000/api/v1/agent/commands/execute \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $AGENT_TOKEN" \
  -H "X-Agent-Id: $AGENT_ID" \
  -H "X-Timestamp: $(date +%s)" \
  -H "X-Request-Id: $(uuidgen)" \
  -H "X-Agent-Signature: $SIGNATURE" \
  --data-binary @body.json
```

Where `SIGNATURE` = base64(HMAC_SHA256(AGENT_TOKEN, contents of body.json)).

---

## Error Codes & Responses

- 400 Bad Request: Malformed JSON; missing `X-Request-Id` or `X-Timestamp`
- 401 Unauthorized: Missing/invalid `Authorization` bearer token or `X-Agent-Id`, or invalid signature
- 403 Forbidden: Insufficient scope
- 409 Conflict: Replay detected (duplicate `X-Request-Id` within TTL)
- 429 Too Many Requests: Rate limit exceeded (per `AGENT_ID`)
- 500 Internal Server Error: Unhandled server error

Response payload on error:
```
{ "error": "<message>" }
```

---

## Token Rotation Flow

1) Stacker decides to rotate an agent’s token and generates `NEW_TOKEN`.
2) Stacker calls `POST /api/v1/auth/rotate-token` with body `{ "new_token": "NEW_TOKEN" }`.
   - Request must be signed with the CURRENT token to authorize rotation.
3) On success, agent immediately switches to `NEW_TOKEN` for signature verification.
4) Stacker must update its stored credential and use `NEW_TOKEN` for all subsequent requests.

Recommendations:
- Perform rotation in maintenance window or with retry logic in case of race conditions.
- Keep short retry loop (e.g., re-sign with old token on first attempt if new token not yet active).

---

## Migration Plan (Stacker)

1) Prereqs
- Ensure you have `AGENT_ID` and `AGENT_TOKEN` for each agent (already part of registration flow).
- Confirm agent version includes HMAC verification (this release).

2) Client Changes
- Add required headers: `X-Agent-Id`, `X-Timestamp`, `X-Request-Id`, `X-Agent-Signature`.
- Compute signature over the raw body.
- Implement retry/backoff for 429.
- Handle 401/403/409 with clear operator surfaced error messages.

3) Scopes
- Align your usage with agent’s `AGENT_SCOPES` set at deployment time.
- For Docker operations via `/execute` using `name="docker:..."`, include the corresponding docker:* scopes in agent config, otherwise requests will be 403.

4) Rollout Strategy
- Enable HMAC calls in a staging environment and validate:
  - Valid signature success path
  - Invalid signature rejected (401)
  - Old timestamp rejected
  - Replay (duplicate X-Request-Id) rejected (409)
  - Missing scope rejected (403)
  - Rate limiting returns 429 with backoff
- Roll out to production agents.

---

## Agent Configuration Reference (for context)

- `AGENT_ID` (string) – identity check
- `AGENT_TOKEN` (string) – HMAC signing key; updated via rotate-token endpoint
- `AGENT_SCOPES` (csv) – allowed scopes on the agent (e.g. `commands:execute,commands:report,...`)
- `RATE_LIMIT_PER_MIN` (number, default 120)
- `REPLAY_TTL_SECS` (number, default 600)
- `SIGNATURE_MAX_SKEW_SECS` (number, default 300)

---

## Audit & Observability
The agent logs (structured via `tracing`) under an `audit` target for key events:
- auth_success, auth_failure, signature_invalid, rate_limited, replay_detected,
- scope_denied, command_executed, token_rotated.

Stacker should monitor:
- Increased 401/403/409/429 rates during rollout
- Any signature invalid or replay events as security signals

---

## Compatibility Notes
- This is a breaking change for POST endpoints: HMAC headers are now mandatory.
- GET `/wait` remains compatible (Agent-Id header + rate limiting only). Stacker may optionally add signing in the future.

---

## FAQ

Q: Which encoding for signature?
A: Base64 preferred. Hex is accepted as fallback.

Q: What if clocks drift?
A: Default allowed skew is 300s. Keep your NTP in sync or adjust `SIGNATURE_MAX_SKEW_SECS` on the agent.

Q: How to handle retries safely?
A: Use a unique `X-Request-Id` per attempt. If you repeat the same ID, the agent will return 409.

Q: Can Stacker use JWTs instead?
A: Not in this version. We use HMAC with `AGENT_TOKEN`. mTLS/JWT can be considered later.

---

## Contact
Please coordinate with the Agent team for rollout gates and staged verifications. Include example payloads and signatures from staging during validation.
