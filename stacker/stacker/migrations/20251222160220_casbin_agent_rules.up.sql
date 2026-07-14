-- Add agent role group and permissions

-- Create agent role group (inherits from group_anonymous for health checks)
INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5) 
VALUES ('g', 'agent', 'group_anonymous', '', '', '', '')
ON CONFLICT DO NOTHING;

-- Agent registration (anonymous, users, and admin can register agents)
-- This allows agents to bootstrap themselves during deployment
INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5) 
VALUES ('p', 'group_anonymous', '/api/v1/agent/register', 'POST', '', '', '')
ON CONFLICT DO NOTHING;

INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5) 
VALUES ('p', 'group_user', '/api/v1/agent/register', 'POST', '', '', '')
ON CONFLICT DO NOTHING;

INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5) 
VALUES ('p', 'group_admin', '/api/v1/agent/register', 'POST', '', '', '')
ON CONFLICT DO NOTHING;

-- Agent long-poll for commands (only agents can do this)
INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5) 
VALUES ('p', 'agent', '/api/v1/agent/commands/wait/:deployment_hash', 'GET', '', '', '')
ON CONFLICT DO NOTHING;

-- Agent report command results (only agents can do this)
INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5) 
VALUES ('p', 'agent', '/api/v1/agent/commands/report', 'POST', '', '', '')
ON CONFLICT DO NOTHING;
