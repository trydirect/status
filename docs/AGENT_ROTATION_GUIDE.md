# Agent Token Rotation via Vault

This guide describes how a self-hosted Agent should integrate with Vault for secure token rotation, and how to authenticate/authorize requests to and from Stacker.

## Overview
- Source of truth: Vault KV entry at `{VAULT_AGENT_PATH_PREFIX}/{deployment_hash}/token`.
- Agent responsibilities:
  - Bootstrap token on registration
  - Periodically refresh token from Vault
  - Verify inbound HMAC-signed requests from Stacker
  - Use latest token when calling Stacker (wait/report)
  - Handle rotation gracefully (no secret leakage; in-flight requests allowed to complete)

## Configuration
- Env vars:
  - `VAULT_ADDRESS`: Base URL, e.g. `http://127.0.0.1:8200`
  - `VAULT_TOKEN`: Vault access token
  - `VAULT_AGENT_PATH_PREFIX`: KV mount/prefix, e.g. `status_panel` or `kv/status_panel`
- Paths:
  - Store/fetch/delete token: `GET/POST/DELETE {VAULT_ADDRESS}/v1/{VAULT_AGENT_PATH_PREFIX}/{deployment_hash}/token`
- TLS:
  - Use HTTPS with proper CA bundle or certificate pinning in production.

## Token Lifecycle
1. Register Agent:
   - `POST /api/v1/agent/register` returns `agent_id`, `agent_token`.
   - Cache `agent_token` in memory.
2. Verify with Vault:
   - Immediately fetch token from Vault and ensure it matches the registration token.
   - Prefer Vault-fetched token.
3. Background Refresh:
   - Every 60s (+ jitter 5–10s), `GET` the token from Vault.
   - If changed, atomically swap the in-memory token and note rotation time.

## Vault Client Interface (Skeleton)
```rust
struct VaultClient { base: String, token: String, prefix: String }

impl VaultClient {
    async fn fetch_agent_token(&self, dh: &str) -> Result<String, Error> {
        // GET {base}/v1/{prefix}/{dh}/token with X-Vault-Token
        // Parse JSON: {"data":{"data":{"token":"..."}}}
        Ok("token_from_vault".into())
    }
}
```

## Background Refresh Loop (Skeleton)
```rust
struct TokenCache { token: Arc<AtomicPtr<String>>, last_rotated: Arc<AtomicU64> }

async fn refresh_loop(vault: VaultClient, dh: String, cache: TokenCache) {
    loop {
        let jitter = rand::thread_rng().gen_range(5..10);
        tokio::time::sleep(Duration::from_secs(60 + jitter)).await;
        match vault.fetch_agent_token(&dh).await {
            Ok(new_token) => {
                if new_token != current_token() {
                    swap_token_atomic(&cache, new_token);
                    update_last_rotated(&cache);
                    tracing::info!(deployment_hash = %dh, "Agent token rotated");
                }
            }
            Err(err) => tracing::warn!(deployment_hash = %dh, error = %err, "Vault fetch failed"),
        }
    }
}
```

## Inbound HMAC Verification (Agent HTTP Server)
- Required headers on Stacker→Agent POSTs:
  - `X-Agent-Id`
  - `X-Timestamp` (UTC seconds)
  - `X-Request-Id` (UUID)
  - `X-Agent-Signature` = base64(HMAC_SHA256(current_token, raw_body_bytes))
- Verification:
  - Check clock skew (±120s)
  - Reject replay: keep a bounded LRU/set of recent `X-Request-Id`
  - Compute HMAC with current token; constant-time compare against `X-Agent-Signature`

```rust
fn verify_hmac(token: &str, body: &[u8], sig_b64: &str) -> Result<(), Error> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = Hmac::<Sha256>::new_from_slice(token.as_bytes())?;
    mac.update(body);
    let expected = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());
    if subtle::ConstantTimeEq::ct_eq(expected.as_bytes(), sig_b64.as_bytes()).into() {
        Ok(())
    } else {
        Err(Error::InvalidSignature)
    }
}
```

## Outbound Auth to Stacker
- Use latest token for:
  - `GET /api/v1/agent/commands/wait/{deployment_hash}`
  - `POST /api/v1/agent/commands/report`
- Headers:
  - `Authorization: Bearer {current_token}`
  - `X-Agent-Id: {agent_id}`
- On 401/403:
  - Immediately refresh from Vault; retry with exponential backoff.

## Graceful Rotation
- Allow in-flight requests to complete.
- New requests pick up the swapped token.
- Do not log token values; log rotation events and ages.
- Provide `/health` with fields: `token_age_seconds`, `last_refresh_ok`.

## Observability
- Tracing spans for Vault fetch, HMAC verify, and Stacker calls.
- Metrics:
  - `vault_fetch_errors_total`
  - `token_rotations_total`
  - `hmac_verification_failures_total`
  - `stacker_wait_errors_total`, `stacker_report_errors_total`

## Testing Checklist
- Unit tests:
  - Vault response parsing
  - HMAC verification (valid/invalid/missing headers)
- Integration:
  - Rotation mid-run (requests still succeed after swap)
  - Replay/timestamp rejection
  - 401/403 triggers refresh and backoff
  - End-to-end `wait` → `report` with updated token

## Example Startup Flow
```rust
// On agent start
let token = vault.fetch_agent_token(&deployment_hash).await?;
cache.store(token);
spawn(refresh_loop(vault.clone(), deployment_hash.clone(), cache.clone()));
// Start HTTP server with HMAC middleware using cache.current_token()
```

## Runbook
- Symptoms: 401/403 from Stacker
  - Action: force refresh token from Vault; confirm KV path
- Symptoms: HMAC verification failures
  - Action: check request headers, clock skew, and signature; ensure using current token
- Symptoms: Vault errors
  - Action: verify `VAULT_ADDRESS`, `VAULT_TOKEN`, network connectivity, and KV path prefix

---

## Auth Refresh on 401/403 — Implementation Details

### Problem

When the agent token expires or is rotated server-side, all outbound requests
(polling, reporting, notifications) receive 401/403 from Stacker. Previously
these were treated as generic errors with fixed backoff, causing prolonged
downtime until manual restart.

### Solution: `TokenProvider` + Retry Helpers

Two new modules handle automatic recovery:

| Module | Path | Purpose |
|--------|------|---------|
| `TokenProvider` | `src/security/token_provider.rs` | Shared mutable token with on-demand refresh |
| `RetryClient` | `src/transport/retry.rs` | HTTP helpers that detect 401/403 and retry |

### Request Flow

```
Daemon / Notification Poller
        │
        ▼
┌───────────────────┐
│  TokenProvider     │  .get() → current token
│  .get()           │
└────────┬──────────┘
         ▼
┌───────────────────┐
│  Build signed     │  build_signed_headers(agent_id, token, body)
│  HMAC headers     │  → Bearer + X-Agent-Signature + X-Timestamp
└────────┬──────────┘
         ▼
┌───────────────────┐
│  Send HTTP        │  signed_get_with_retry / signed_post_with_retry
│  request          │
└────────┬──────────┘
         ▼
┌────── Status code? ──────┐
│           │               │
200/204    401/403         5xx / network error
│           │               │
✅ Done    ▼               ▼
     ┌──────────────┐  Exponential backoff
     │ TokenProvider │  2s → 4s → 8s → … 60s cap
     │ .refresh()   │  retry up to 3×
     └──────┬───────┘
            │
            ├─ 1. Try Vault:
            │     vault_client.fetch_agent_token(deployment_hash)
            │
            ├─ 2. If Vault fails or returns same token:
            │     re-read AGENT_TOKEN from environment
            │
            ├─ 3. Cooldown: 10s between refresh attempts
            │     (prevents hammering Vault on repeated failures)
            │
            ▼
     Retry request once with new token
            │
       ┌────┴────┐
      200      401 again
       │         │
    ✅ Done   Propagate error
              (token truly invalid)
```

### TokenProvider API

```rust
use crate::security::token_provider::TokenProvider;

// Create (both daemon and serve mode)
let tp = TokenProvider::new(initial_token, Some(vault_client), deployment_hash);
// or
let tp = TokenProvider::from_env(Some(vault_client));

tp.get().await        // → current token (Arc<RwLock<String>>)
tp.refresh().await    // → Ok(true) if token changed, Ok(false) if unchanged
tp.swap(new).await    // → direct swap (used by background rotation task)
```

### Wired Consumers

| Consumer | File | Mechanism |
|----------|------|-----------|
| Daemon polling (`wait_for_command`) | `src/agent/daemon.rs` | `wait_for_command_with_retry` (auth-only retry) |
| Daemon reporting (`report_result`) | `src/agent/daemon.rs` | `report_result_with_retry` (full retry) |
| Daemon app status | `src/agent/daemon.rs` | `update_app_status_with_retry` (full retry) |
| Notification poller | `src/comms/notifications.rs` | Explicit 401/403 check → `refresh()` → 5s backoff |

### RetryConfig Presets

```rust
use crate::transport::retry::RetryConfig;

RetryConfig::default()     // 1 auth retry + 3 server retries (2–60s backoff)
RetryConfig::auth_only()   // 1 auth retry + 0 server retries (for long-poll)
```

### Refresh Strategy

1. **Vault first** — If `VaultClient` is configured, call
   `fetch_agent_token(deployment_hash)`. If it returns a different token,
   swap it in and retry.
2. **Environment fallback** — If Vault is unavailable or returns the same
   token, re-read `AGENT_TOKEN` from the process environment. This covers
   cases where an orchestrator (Docker, systemd) injects a new token via
   env without restarting the process.
3. **Cooldown** — A 10-second minimum gap between refresh attempts prevents
   hammering Vault during cascading failures.
4. **Single retry** — After refreshing, the request is retried exactly once.
   If it still gets 401/403, the error propagates (the token is truly invalid
   and requires operator intervention).

### Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `AGENT_TOKEN` | _(empty)_ | Bearer token for Stacker API auth |
| `DEPLOYMENT_HASH` | `"default"` | Vault path isolation key |
| `VAULT_ADDRESS` | _(none)_ | Vault server URL (enables Vault refresh) |
| `VAULT_TOKEN` | _(none)_ | Vault auth token |
| `VAULT_AGENT_PATH_PREFIX` | `"status_panel"` | Vault KV path prefix |
