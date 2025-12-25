#!/usr/bin/env bash
# Demo script: Enqueue a command and long-poll for it with another process
# Usage: ./examples/long_poll_demo.sh

set -e

BASE_URL="http://localhost:8080"
AGENT_ID="${AGENT_ID:-test-agent}"

echo "=== Long-poll command queue demo ==="
echo "Ensure server is running: cargo r -- serve --port 8080"
echo ""

# Start long-poll in background
echo "[1] Starting long-poll wait in background..."
(
  echo "   Waiting for command (timeout=10s)..."
  RESPONSE=$(curl -s \
    -H "X-Agent-Id: $AGENT_ID" \
    "$BASE_URL/api/v1/commands/wait/demo-hash?timeout=10")
  
  if [ -n "$RESPONSE" ]; then
    echo "   Received command:"
    echo "$RESPONSE" | jq .
  else
    echo "   No commands (timeout)"
  fi
) &

POLLER_PID=$!
sleep 1

# Enqueue a command
echo "[2] Enqueuing a command..."
curl -s \
  -H 'Content-Type: application/json' \
  -X POST "$BASE_URL/api/v1/commands/enqueue" \
  -d '{
    "id": "cmd-demo-001",
    "name": "echo Hello from long-poll demo",
    "params": {}
  }' | jq .

echo ""
echo "[3] Waiting for poller to complete..."
wait $POLLER_PID

echo ""
echo "=== Demo complete ==="
echo "Next: execute the command via /api/v1/commands/execute and report result via /api/v1/commands/report"
