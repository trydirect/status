-- Add Casbin rules for MCP WebSocket endpoint
-- Allow authenticated users and admins to access MCP

INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
VALUES 
  ('p', 'group_admin', '/mcp', 'GET', '', '', ''),
  ('p', 'group_user', '/mcp', 'GET', '', '', '')
ON CONFLICT ON CONSTRAINT unique_key_sqlx_adapter DO NOTHING;
