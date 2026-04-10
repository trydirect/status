# Security Policy
## Reporting a Vulnerability 
If you believe you've found something in "Status" which has security implications, 
please do not raise the issue in Github issue tracker or other public forums.

Send a description of the issue via email to *security@try.direct*. 
The project maintainers will then work with you to resolve any issues where required, prior to any public disclosure.

---

## Authentication Hardening (v0.1.7+)

### Credential Configuration

The agent has **no default credentials**. Authentication is disabled until you explicitly configure:

```bash
STATUS_PANEL_USERNAME=your-username
STATUS_PANEL_PASSWORD=your-strong-password
```

If these environment variables are not set:
- Login returns `503 Service Unavailable`
- A warning is logged on every login attempt
- Run `status init` to generate a `.env` template

### Agent ID Protection

The `AGENT_ID` environment variable must be set to protect API endpoints (`/api/self/*`, `/api/v1/*`). When unset, these endpoints return `401 Unauthorized`.

### Session Security

- Sessions are stored in-memory with creation timestamps
- `cleanup_expired(duration)` removes sessions older than the TTL
- Logout invalidates the session server-side and clears the cookie
- Cookies use `HttpOnly; Secure; SameSite=Strict` attributes
- `Max-Age=0` is set on logout to prevent stale cookies

### Bind Address

The API server defaults to `127.0.0.1` (localhost only). To expose on all interfaces, explicitly pass `--bind 0.0.0.0`. This prevents accidental exposure on public networks.

### Self-Update Integrity

- Update downloads require HTTPS — HTTP URLs are rejected
- SHA256 hash is computed on every download
- If `UPDATE_EXPECTED_SHA256` is set, hash must match or the update fails
- If not set, a warning is logged with the computed hash for manual verification

---

## Vault Integration Security

### Token Rotation Best Practices

The agent supports automatic token rotation via Vault KV store. When enabled:

1. **Service Token Security**
   - Vault service token (`VAULT_TOKEN`) should have minimal required permissions
   - Restrict to specific KV path: `status_panel/deployment-*/token`
   - Rotate service token independently from agent token
   - Never commit `VAULT_TOKEN` to version control

2. **Network Security**
   - Always use HTTPS to Vault with certificate pinning in production
   - Restrict Vault network access to authorized agent IPs
   - Use Vault VPC peering or private networks when available

3. **Token Storage**
   - Store agent tokens encrypted at rest in Vault
   - Use KV v2 for versioning capability
   - Audit all token access via Vault audit logs
   - Rotate agent tokens regularly (e.g., monthly)

4. **Monitoring**
   - Alert if agent token refresh fails for > 10 minutes
   - Monitor `/health` endpoint for `token_age_seconds` > 600
   - Log all token rotation events
   - Track Vault fetch errors in central logging

### Threat Model

**Threat:** Compromise of static token  
**Mitigation:** Vault-based rotation enables frequent token changes without restart  
**Residual Risk:** Compromised token valid for up to 60s before refresh

**Threat:** Vault unavailability  
**Mitigation:** Agent continues with current token; automatically retries fetch  
**Residual Risk:** Token staleness increases if Vault unreachable > 10 minutes

**Threat:** Network eavesdropping of Vault connection  
**Mitigation:** Enforce TLS with certificate pinning  
**Residual Risk:** Requires valid client cert for fetch requests

See [VAULT_INTEGRATION.md](VAULT_INTEGRATION.md) for complete setup and monitoring guidance.
