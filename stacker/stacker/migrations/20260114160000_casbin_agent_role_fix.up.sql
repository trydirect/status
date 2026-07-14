-- Ensure agent role has access to agent endpoints (idempotent fix)
-- This migration ensures agent role permissions are in place regardless of previous migration state
-- Addresses 403 error when Status Panel agent tries to report command results

-- Agent role should be able to report command results
INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
VALUES ('p', 'agent', '/api/v1/agent/commands/report', 'POST', '', '', '')
ON CONFLICT ON CONSTRAINT unique_key_sqlx_adapter DO NOTHING;

-- Agent role should be able to poll for commands
INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
VALUES ('p', 'agent', '/api/v1/agent/commands/wait/:deployment_hash', 'GET', '', '', '')
ON CONFLICT ON CONSTRAINT unique_key_sqlx_adapter DO NOTHING;

-- Ensure agent role group exists (inherits from group_anonymous for health checks)
INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
VALUES ('g', 'agent', 'group_anonymous', '', '', '', '')
ON CONFLICT DO NOTHING;
