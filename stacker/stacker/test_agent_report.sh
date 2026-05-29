#!/bin/bash
# Test Agent Report - Simulate Health Check Result
# Run this on the agent server or from anywhere that can reach Stacker

# Usage: 
# 1. SSH to agent server
# 2. Run: bash test_agent_report.sh

# From the logs, these values were captured:
AGENT_ID="3ca84cd9-11af-48fc-be46-446be3eeb3e1"
BEARER_TOKEN="MEOAmiz-_FK3x84Nkk3Zde3ZrGeWbw-Zlx1NeOsPdlQMTGKHalycNhn0cBWS_C3T9WMihDk4T-XzIqZiqGp6jF"
COMMAND_ID="cmd_063860e1-3d06-44c7-beb2-649102a20ad9"
DEPLOYMENT_HASH="1j0hCOoYttCj-hMt654G-dNChLAfygp_L6rpEGLvFqr0V_lsEHRUSLd88a6dm9LILoxaMnyz30XTJXzBZKouIQ"

echo "Testing Agent Report Endpoint..."
echo "Command ID: $COMMAND_ID"
echo ""

curl -v -X POST https://stacker.try.direct/api/v1/agent/commands/report \
  -H "Content-Type: application/json" \
  -H "X-Agent-ID: $AGENT_ID" \
  -H "Authorization: Bearer $BEARER_TOKEN" \
  -d "{
    \"command_id\": \"$COMMAND_ID\",
    \"deployment_hash\": \"$DEPLOYMENT_HASH\",
    \"status\": \"ok\",
    \"command_status\": \"completed\",
    \"result\": {
      \"type\": \"health\",
      \"deployment_hash\": \"$DEPLOYMENT_HASH\",
      \"app_code\": \"fastapi\",
      \"status\": \"ok\",
      \"container_state\": \"running\",
      \"metrics\": {
        \"cpu_percent\": 2.5,
        \"memory_mb\": 128,
        \"uptime_seconds\": 3600
      },
      \"errors\": []
    },
    \"completed_at\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"
  }"

echo ""
echo ""
echo "If successful, you should see:"
echo "  {\"accepted\": true, \"message\": \"Command result recorded successfully\"}"
echo ""
echo "Then check Status Panel - logs should appear!"
