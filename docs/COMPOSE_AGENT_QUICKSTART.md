# Compose Agent Quick Start

## What is Compose Agent?

A sidecar container that handles Docker Compose operations and provides an MCP Gateway, running alongside the Status Panel. It improves isolation, reliability, and allows independent restart of Docker operations.

## Quick Deploy

### 1. Update Environment Variables

Add to your `.env` file:
```bash
COMPOSE_AGENT_ENABLED=true
```

### 2. Build the Image

```bash
docker-compose -f docker-compose-compose-agent.yml build
```

### 3. Start Services

```bash
docker-compose up -d
```

This starts:
- `statuspanel` - Web UI on port 5001 (no Docker socket)
- `agent` - Monitoring daemon (has Docker socket)
- `compose-agent` - Operations sidecar (has Docker socket)

## Verify It's Working

### Check Container Status
```bash
docker ps | grep compose-agent
```

### View Logs
```bash
docker logs compose-agent
```

Expected log output:
```
INFO Starting compose-agent daemon mode
INFO control_plane=compose_agent Control plane identified
```

### Check Metrics
```bash
curl http://localhost:5001/api/v1/metrics
```

Look for `compose_agent_count` and `status_panel_count` fields.

## CLI Usage

### Run in Compose Mode
```bash
./status --compose-mode --config config.json
```

### Serve with UI (Status Panel)
```bash
./status serve --port 5000 --with-ui
```

## Configuration Options

### Config File (config.json)
```json
{
  "compose_agent_enabled": true,
  "control_plane": "compose_agent"
}
```

### Environment Variables
```bash
COMPOSE_AGENT_ENABLED=true
CONTROL_PLANE=compose_agent
VAULT_TOKEN_KEY=compose_agent_token
```

## Legacy Mode (Disable Compose Agent)

If you want to run without the compose-agent:

### Option 1: Environment Variable
```bash
COMPOSE_AGENT_ENABLED=false docker-compose up -d statuspanel
```

### Option 2: Config File
```json
{
  "compose_agent_enabled": false
}
```

You'll see this warning log:
```
WARN compose_agent=false - running in legacy mode
```

## Vault Token Setup

### Token Paths
```
secret/agent/{hash}/status_panel_token    # For statuspanel
secret/agent/{hash}/compose_agent_token   # For compose-agent
```

### Store Tokens
```bash
# Status Panel token
vault kv put secret/agent/abc123/status_panel_token token=sp_token_here

# Compose Agent token
vault kv put secret/agent/abc123/compose_agent_token token=ca_token_here
```

### Fetch in Code
```rust
let vault = VaultClient::from_env()?;

// Status Panel token
let sp_token = vault.fetch_agent_token("abc123", Some("status_panel_token")).await?;

// Compose Agent token
let ca_token = vault.fetch_agent_token("abc123", Some("compose_agent_token")).await?;
```

## Troubleshooting

### Compose Agent Not Starting

**Check Docker socket permissions:**
```bash
ls -la /var/run/docker.sock
```

**Verify mount in compose file:**
```yaml
volumes:
  - /var/run/docker.sock:/var/run/docker.sock
```

### GLIBC Errors

The watchdog automatically detects and restarts. If persistent:
```bash
docker logs compose-agent | grep GLIBC
```

The musl-based build should avoid these issues.

### No Metrics Showing

Ensure the compose-agent is running:
```bash
docker inspect compose-agent | jq '.[0].State.Status'
```

Check environment variable:
```bash
docker exec compose-agent env | grep CONTROL_PLANE
```

### Token Fetch Failures

Verify Vault connectivity:
```bash
curl -H "X-Vault-Token: $VAULT_TOKEN" \
  $VAULT_ADDRESS/v1/$VAULT_AGENT_PATH_PREFIX/$DEPLOYMENT_HASH/compose_agent_token
```

## Command Examples

### Build for Production
```bash
# Using musl for static linking (no GLIBC issues)
docker build -f Dockerfile.compose-agent -t trydirect/status:compose-agent-latest .
```

### Run Tests
```bash
# All tests
cargo test

# Watchdog tests only
cargo test watchdog

# With Docker integration tests
cargo test --features docker -- --ignored
```

### Docker Compose Commands
```bash
# Start only compose-agent
docker-compose up -d compose-agent

# Restart compose-agent
docker-compose restart compose-agent

# View compose-agent logs
docker-compose logs -f compose-agent

# Check all services
docker-compose ps
```

## Health Check

The watchdog monitors compose-agent health every 30 seconds:

- **Healthy**: Container running normally
- **Unhealthy**: Automatic restart initiated
- **GlibcMismatch**: Special handling for library errors

View watchdog status in logs:
```bash
docker logs agent | grep watchdog
```

## Monitoring Dashboard Integration

The compose-agent reports to the Stacker dashboard:

1. **Capabilities**: `/capabilities` endpoint includes `compose_agent=true`
2. **Metrics**: All command executions tagged with control plane
3. **Health**: Regular heartbeat with system metrics

## Security Features

✅ Docker socket isolated from web UI  
✅ Independent tokens for each container  
✅ Audit trail with control plane tracking  
✅ Rate limiting per container  
✅ Automatic restart with backoff  

## Next Steps

1. ✅ Deploy compose-agent to staging
2. Monitor metrics for 24-48 hours
3. Gradually roll out to production
4. Remove Docker socket from statuspanel
5. Configure Vault policies for dual tokens

## Resources

- Full Documentation: [docs/COMPOSE_AGENT_SIDECAR.md](docs/COMPOSE_AGENT_SIDECAR.md)
- Implementation Summary: [COMPOSE_AGENT_IMPLEMENTATION.md](COMPOSE_AGENT_IMPLEMENTATION.md)
- API Documentation: [docs/API_SPEC.md](docs/API_SPEC.md)
- Security Guide: [docs/SECURITY_ENHANCEMENT.md](docs/SECURITY_ENHANCEMENT.md)

## Support

For issues or questions:
- Check logs: `docker logs compose-agent`
- Review watchdog status: `docker logs agent | grep watchdog`
- Verify configuration: `docker-compose config`
- Run tests: `cargo test`
