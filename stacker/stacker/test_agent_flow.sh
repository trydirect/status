#!/bin/bash
set -e

# Manual test script for agent/command flow
# Run this after starting the server with: make dev

BASE_URL="${BASE_URL:-http://localhost:8000}"
DEPLOYMENT_HASH="test_deployment_$(uuidgen | tr '[:upper:]' '[:lower:]')"

echo "=========================================="
echo "Testing Agent/Command Flow"
echo "Deployment Hash: $DEPLOYMENT_HASH"
echo "=========================================="

# Step 1: Register an agent
echo -e "\n=== Step 1: Register Agent ==="
REGISTER_RESPONSE=$(curl -s -X POST "$BASE_URL/api/v1/agent/register" \
  -H "Content-Type: application/json" \
  -d "{
    \"deployment_hash\": \"$DEPLOYMENT_HASH\",
    \"agent_version\": \"1.0.0\",
    \"capabilities\": [\"docker\", \"compose\", \"logs\"],
    \"system_info\": {
      \"os\": \"linux\",
      \"arch\": \"x86_64\",
      \"memory_gb\": 8
    }
  }")

echo "Register Response:"
echo "$REGISTER_RESPONSE" | jq '.'

# Extract agent_id and token
AGENT_ID=$(echo "$REGISTER_RESPONSE" | jq -r '.item.agent_id // .data.item.agent_id // empty')
AGENT_TOKEN=$(echo "$REGISTER_RESPONSE" | jq -r '.item.agent_token // .data.item.agent_token // empty')

if [ -z "$AGENT_ID" ] || [ -z "$AGENT_TOKEN" ]; then
  echo "ERROR: Failed to register agent or extract credentials"
  echo "Response was: $REGISTER_RESPONSE"
  exit 1
fi

echo "Agent ID: $AGENT_ID"
echo "Agent Token: ${AGENT_TOKEN:0:20}..."

# Step 2: Create a command (requires authentication - will likely fail without OAuth)
echo -e "\n=== Step 2: Create Command (may fail without auth) ==="
CREATE_CMD_RESPONSE=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X POST "$BASE_URL/api/v1/commands" \
  -H "Content-Type: application/json" \
  -d "{
    \"deployment_hash\": \"$DEPLOYMENT_HASH\",
    \"type\": \"restart_service\",
    \"priority\": \"high\",
    \"parameters\": {
      \"service\": \"web\",
      \"graceful\": true
    },
    \"timeout_seconds\": 300
  }" 2>&1)

HTTP_STATUS=$(echo "$CREATE_CMD_RESPONSE" | grep "HTTP_STATUS:" | cut -d: -f2)
BODY=$(echo "$CREATE_CMD_RESPONSE" | sed '/HTTP_STATUS:/d')

echo "Create Command Response (Status: $HTTP_STATUS):"
echo "$BODY" | jq '.' 2>/dev/null || echo "$BODY"

if [ "$HTTP_STATUS" != "200" ] && [ "$HTTP_STATUS" != "201" ]; then
  echo "WARNING: Command creation failed (expected - requires OAuth)"
  echo "You can manually create a command in the database to test the wait/report flow"
  echo ""
  echo "SQL to insert test command:"
  echo "INSERT INTO command (deployment_hash, type, priority, parameters, timeout_seconds, status)"
  echo "VALUES ('$DEPLOYMENT_HASH', 'restart_service', 'high', '{\"service\": \"web\"}'::jsonb, 300, 'pending');"
  echo ""
  read -p "Press Enter after inserting the command manually, or Ctrl+C to exit..."
fi

COMMAND_ID=$(echo "$BODY" | jq -r '.item.command_id // .data.item.command_id // empty')
echo "Command ID: $COMMAND_ID"

# Step 3: Agent polls for commands
echo -e "\n=== Step 3: Agent Polls for Commands ==="
echo "Waiting for commands (timeout: 35s)..."

WAIT_RESPONSE=$(curl -s -w "\nHTTP_STATUS:%{http_code}" \
  -X GET "$BASE_URL/api/v1/agent/commands/wait/$DEPLOYMENT_HASH" \
  -H "X-Agent-Id: $AGENT_ID" \
  -H "Authorization: Bearer $AGENT_TOKEN" \
  --max-time 35 2>&1)

HTTP_STATUS=$(echo "$WAIT_RESPONSE" | grep "HTTP_STATUS:" | cut -d: -f2)
BODY=$(echo "$WAIT_RESPONSE" | sed '/HTTP_STATUS:/d')

echo "Wait Response (Status: $HTTP_STATUS):"
echo "$BODY" | jq '.' 2>/dev/null || echo "$BODY"

RECEIVED_COMMAND_ID=$(echo "$BODY" | jq -r '.item.command_id // .data.item.command_id // empty')

if [ -z "$RECEIVED_COMMAND_ID" ]; then
  echo "No command received (timeout or no commands in queue)"
  exit 0
fi

echo "Received Command ID: $RECEIVED_COMMAND_ID"

# Step 4: Agent reports command result
echo -e "\n=== Step 4: Agent Reports Command Result ==="
REPORT_RESPONSE=$(curl -s -w "\nHTTP_STATUS:%{http_code}" \
  -X POST "$BASE_URL/api/v1/agent/commands/report" \
  -H "Content-Type: application/json" \
  -H "X-Agent-Id: $AGENT_ID" \
  -H "Authorization: Bearer $AGENT_TOKEN" \
  -d "{
    \"command_id\": \"$RECEIVED_COMMAND_ID\",
    \"deployment_hash\": \"$DEPLOYMENT_HASH\",
    \"status\": \"completed\",
    \"result\": {
      \"service_restarted\": true,
      \"restart_time_seconds\": 5.2,
      \"final_status\": \"running\"
    },
    \"metadata\": {
      \"execution_node\": \"worker-1\"
    }
  }" 2>&1)

HTTP_STATUS=$(echo "$REPORT_RESPONSE" | grep "HTTP_STATUS:" | cut -d: -f2)
BODY=$(echo "$REPORT_RESPONSE" | sed '/HTTP_STATUS:/d')

echo "Report Response (Status: $HTTP_STATUS):"
echo "$BODY" | jq '.' 2>/dev/null || echo "$BODY"

echo -e "\n=========================================="
echo "Test Flow Complete!"
echo "=========================================="
echo "Summary:"
echo "  - Agent registered: $AGENT_ID"
echo "  - Command created: ${COMMAND_ID:-N/A (auth required)}"
echo "  - Command received: ${RECEIVED_COMMAND_ID:-N/A}"
echo "  - Report status: $HTTP_STATUS"
