#!/bin/bash
# Test MCP WebSocket with proper timing

{
  sleep 0.5
  echo '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
  sleep 5
} | timeout 10 wscat -c "ws://127.0.0.1:8000/mcp" -H "Authorization: Bearer 52Hq6LCh16bIPjHkzQq7WyHz50SUQc" 2>&1
