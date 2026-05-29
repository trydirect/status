-- Add Casbin ACL rules for /api/v1/agent/commands/enqueue endpoint
-- This endpoint allows authenticated users to enqueue commands for their deployments

INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5) 
VALUES ('p', 'group_user', '/api/v1/agent/commands/enqueue', 'POST', '', '', '') 
ON CONFLICT ON CONSTRAINT unique_key_sqlx_adapter DO NOTHING;

INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5) 
VALUES ('p', 'group_admin', '/api/v1/agent/commands/enqueue', 'POST', '', '', '') 
ON CONFLICT ON CONSTRAINT unique_key_sqlx_adapter DO NOTHING;

INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5) 
VALUES ('p', 'client', '/api/v1/agent/commands/enqueue', 'POST', '', '', '') 
ON CONFLICT ON CONSTRAINT unique_key_sqlx_adapter DO NOTHING;
