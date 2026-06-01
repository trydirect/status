-- Migration: Insert casbin_rule permissions for agent deployments GET

INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
VALUES 
    -- Server list and get
    ('p', 'group_user', '/api/v1/agent/deployments/*', 'GET', '', '', ''),
    ('p', 'agent', '/api/v1/agent/deployments/*', 'GET', '', '', ''),
    ('p', 'group_admin', '/api/v1/agent/deployments/*', 'GET', '', '', ''),
    ('p', 'root', '/api/v1/agent/deployments/*', 'GET', '', '', '')
ON CONFLICT DO NOTHING;

INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
VALUES 
    -- Server list and get
    ('p', 'group_user', '/api/v1/commands/*', 'GET', '', '', ''),
    ('p', 'agent', '/api/v1/commands/*', 'GET', '', '', ''),
    ('p', 'group_admin', '/api/v1/commands/*', 'GET', '', '', ''),
    ('p', 'root', '/api/v1/commands/*', 'GET', '', '', '')
ON CONFLICT DO NOTHING;