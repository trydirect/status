#!/bin/bash
(
  sleep 1
  echo '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
  sleep 2
) | wscat -c "ws://127.0.0.1:8000/mcp" -H "Authorization: Bearer $BEARER_TOKEN"
