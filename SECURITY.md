# Security Policy
## Reporting a Vulnerability 
If you believe you've found something in "Status" which has security implications, 
please do not raise the issue in Github issue tracker or other public forums.

Send a description of the issue via email to *security@try.direct*. 
The project maintainers will then work with you to resolve any issues where required, prior to any public disclosure.

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
