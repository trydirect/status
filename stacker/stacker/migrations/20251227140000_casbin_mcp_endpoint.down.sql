-- Remove Casbin rules for MCP WebSocket endpoint

DELETE FROM public.casbin_rule 
WHERE ptype = 'p' 
  AND v0 IN ('group_admin', 'group_user')
  AND v1 = '/mcp' 
  AND v2 = 'GET';
