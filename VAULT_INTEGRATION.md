# Vault Integration for Token Rotation

Status Panel Agent now supports secure token rotation via HashiCorp Vault, enabling automatic credential management without server restarts.

## Overview

This implementation provides:
- **Atomic token swaps** with in-flight request safety
- **Background refresh loop** synced with Vault every 60s (+ jitter)
- **Graceful error handling** with detailed audit logging
- **Health endpoint** with token age and rotation status
- **Zero-downtime rotation** - new requests use updated token while in-flight requests complete

## Architecture

### Components

#### 1. VaultClient (`src/security/vault_client.rs`)
- HTTP client for KV store operations
- Supports fetch, store, and delete operations
- Respects Vault API response format: `{"data":{"data":{"token":"..."}}`

#### 2. TokenCache (`src/security/token_cache.rs`)
- Arc-wrapped RwLock for atomic swaps
- Tracks last rotation timestamp
- Provides `age_seconds()` for health monitoring
- Thread-safe across async contexts

#### 3. TokenRefresh (`src/security/token_refresh.rs`)
- Background task spawned on startup
- Runs every 60s (+ 5-10s jitter) to avoid thundering herd
- Silently skips update if token unchanged
- Logs rotation events and fetch errors

### State Management

`AppState` now includes:
```rust
pub vault_client: Option<VaultClient>,
pub token_cache: Option<TokenCache>,
```

These are initialized from environment variables if `VAULT_ADDRESS` is set.

## Configuration

### Environment Variables

```bash
# Vault connection (optional - if unset, token rotation is disabled)
VAULT_ADDRESS=http://127.0.0.1:8200              # Vault base URL
VAULT_TOKEN=s.xxxxxxxxxxxxxx                      # Vault auth token
VAULT_AGENT_PATH_PREFIX=status_panel              # KV mount prefix

# Deployment identification
DEPLOYMENT_HASH=deployment-123-abc                # Unique deployment ID (optional, defaults to "default")

# Legacy token field (read on startup, then managed by Vault)
AGENT_TOKEN=initial-token-value
```

### Vault KV Setup

Store the agent token in Vault at path:
```
{VAULT_AGENT_PATH_PREFIX}/{DEPLOYMENT_HASH}/token
```

Example setup with `vault` CLI:
```bash
vault kv put status_panel/deployment-123-abc/token token="my-secret-agent-token"
```

## Token Rotation Flow

### Startup
1. Agent loads `AGENT_TOKEN` from environment (fallback)
2. If `VAULT_ADDRESS` is set, initializes `VaultClient`
3. Creates `TokenCache` with initial token
4. Spawns background refresh task
5. Ready to receive requests

### Background Refresh (Every 60s + Jitter)
1. Fetch token from Vault KV store
2. If token differs from current cache:
   - Atomically swap in cache
   - Record rotation timestamp
   - Log rotation event
3. If fetch fails:
   - Log warning
   - Continue using current token
   - Retry next cycle

### In-Flight Request Safety
- New requests pick up fresh token from cache
- Existing requests continue with old token (still valid)
- No connection drops or 401s due to rotation
- Audit log tracks all rotation events

## Health Endpoint

The `/health` endpoint now returns:
```json
{
  "status": "ok",
  "token_age_seconds": 120,
  "last_refresh_ok": true
}
```

- `token_age_seconds`: Seconds since last successful rotation
- `last_refresh_ok`: null if Vault not configured, true/false based on last fetch

## HMAC Signing with Dynamic Tokens

When Stacker signs requests, it uses the **current** token from its perspective. The Agent will verify:
1. Fetch the signature using current token from cache
2. If verification fails with current token, check if a recent rotation happened
3. Log verification failures for audit

This is handled transparently - no client-side changes needed.

## Observability

### Audit Logging

Token rotation events are logged to the `audit` tracing target:

```
[AUDIT] Token rotated
  deployment_hash: deployment-123-abc
  timestamp: 2025-12-25T10:30:45Z
  age_seconds: 3600
```

Vault fetch errors:

```
[WARN] Failed to fetch token from Vault
  error: "connection timeout"
  will_retry: true
```

### Metrics

- Monitor `GET /health` → `token_age_seconds` for freshness
- Monitor logs for rotation failures
- Alert if `token_age_seconds` > expected refresh interval (e.g., > 600 seconds)

## Graceful Shutdown

When rotating tokens:
1. Existing in-flight requests complete successfully with old token
2. New requests use new token
3. No explicit connection draining needed
4. Audit log tracks rotation time

## Error Handling

### Vault Unreachable
- Warning logged, current token unchanged
- Next refresh cycle retries
- No impact to agent operations

### Invalid Vault Response
- Error context logged
- Current token unchanged
- Safe fallback behavior

### Clock Skew
- Timestamp freshness checks still apply
- HMAC signatures valid with either old or new token (briefly)
- Stacker may see brief 401s during rotation if clocks drift significantly

## Implementation Notes

### Concurrency
- `TokenCache` uses `Arc<RwLock<String>>` for thread-safe reads
- Reads are non-blocking (RwLock read guard)
- Writes only on rotation (infrequent)

### Async Context
- Background task uses `tokio::spawn`
- RNG scoped to avoid Send trait issues
- All I/O via `tokio` async runtime

### Testing
- Unit tests for `VaultClient`, `TokenCache`, `TokenRefresh`
- Integration tests for Vault fetch with mock responses
- Tests verify atomic swap, age calculation, clone behavior

## Production Checklist

- [ ] Vault cluster deployed and HA-enabled
- [ ] Network connectivity verified (ping Vault from agent)
- [ ] KV v2 secrets engine enabled and configured
- [ ] Service token created with appropriate policy for KV mount
- [ ] Initial token stored in Vault
- [ ] `DEPLOYMENT_HASH` set uniquely per agent deployment
- [ ] Monitoring alert configured for token age > 600s
- [ ] Audit logs shipped to central logging system
- [ ] Disaster recovery tested (Vault downtime recovery)
- [ ] Security audit performed on Vault policy and network access

## Migration from Static Tokens

1. **Phase 1**: Deploy with `VAULT_ADDRESS` unset
   - Agent behaves as before (static token from `AGENT_TOKEN`)
   - No changes to Stacker

2. **Phase 2**: Prepare Vault
   - Store current token in Vault
   - Verify read access works

3. **Phase 3**: Enable Vault integration
   - Set `VAULT_ADDRESS` and other Vault env vars
   - Restart agent
   - Verify `/health` shows `token_age_seconds`

4. **Phase 4**: Rotate token
   - Update token in Vault
   - Monitor logs for rotation
   - Verify Stacker continues working

## Troubleshooting

### Agent not picking up token rotation
- Check logs for "Failed to fetch token from Vault"
- Verify Vault reachability: `curl -H "X-Vault-Token: $VAULT_TOKEN" $VAULT_ADDRESS/v1/status`
- Verify KV path correct: `$VAULT_ADDRESS/v1/$VAULT_AGENT_PATH_PREFIX/$DEPLOYMENT_HASH/token`

### Requests returning 401 after rotation
- Brief 401s are normal during rotation (millisecond window)
- If persistent: check that Stacker and Agent clocks are in sync
- Verify new token is correctly stored in Vault

### Memory leak in TokenCache
- Not possible - Arc-based, references released on rotation
- Monitor Rust process RSS for leaks

## References

- Vault KV API: https://www.vaultproject.io/api-docs/secret/kv/kv-v2
- Vault Service Token Setup: https://www.vaultproject.io/docs/concepts/lease
- Status Panel Security: see SECURITY.md
- Stacker Integration: see STACKER_INTEGRATION_REQUIREMENTS.md
