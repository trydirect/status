# Kata Runtime Monitoring & Observability

## Tracing

The `Agent enqueue command` span now includes a `runtime` field (`runc` or `kata`) on every `deploy_app` command. Use structured log queries to filter:

```
runtime="kata" command_type="deploy_app"
```

## Prometheus Metrics

### Recommended Counter

Add to your metrics exporter (e.g., via actix-web-prom or custom middleware):

```
agent_deploy_runtime_total{runtime="kata"} 
agent_deploy_runtime_total{runtime="runc"}
```

**Labels:**
- `runtime` — `runc` or `kata`
- `deployment_hash` — target deployment
- `status` — `success` or `failed`

### Example PromQL Queries

```promql
# Kata adoption rate (last 24h)
sum(rate(agent_deploy_runtime_total{runtime="kata"}[24h])) 
/ sum(rate(agent_deploy_runtime_total[24h]))

# Kata deploys per hour
sum(rate(agent_deploy_runtime_total{runtime="kata"}[1h]))

# Compare Kata vs runc failure rates  
sum(rate(agent_deploy_runtime_total{runtime="kata",status="failed"}[1h]))
/ sum(rate(agent_deploy_runtime_total{runtime="kata"}[1h]))
```

## Audit Trail

Kata-related events are logged in the `audit_log` table:

| Action | Details | When |
|--------|---------|------|
| `deploy_app` | `{"runtime": "kata"}` | Every Kata deploy |
| `kata_fallback` | `{"reason": "kata unavailable", "fallback": "runc"}` | Agent falls back to runc |
| `kata_rejected` | `{"reason": "agent lacks kata capability"}` | Enqueue rejected |

### Query kata_fallback events:
```sql
SELECT * FROM audit_log 
WHERE action = 'kata_fallback' 
ORDER BY created_at DESC 
LIMIT 50;
```

## Dashboard Widgets

### 1. Kata vs runc Distribution (Pie Chart)
- Query: `sum by (runtime) (agent_deploy_runtime_total)`
- Refresh: 5m

### 2. Kata Adoption Trend (Time Series)
- Query: `sum(rate(agent_deploy_runtime_total{runtime="kata"}[1h]))`
- Period: 7d

### 3. Kata Fallback Rate (Stat Panel)
- Query: `sum(rate(audit_kata_fallback_total[24h]))`
- Threshold: >0 = warning

### 4. Agents with Kata Support (Table)
- Source: `SELECT deployment_hash, capabilities FROM agents WHERE capabilities::text LIKE '%kata%'`
