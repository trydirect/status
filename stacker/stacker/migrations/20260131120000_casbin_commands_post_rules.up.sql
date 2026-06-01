-- Add Casbin POST rules for commands API

INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
VALUES 
    -- Commands POST access
    ('p', 'group_user', '/api/v1/commands/*', 'POST', '', '', ''),
    ('p', 'agent', '/api/v1/commands/*', 'POST', '', '', ''),
    ('p', 'group_admin', '/api/v1/commands/*', 'POST', '', '', ''),
    ('p', 'root', '/api/v1/commands/*', 'POST', '', '', '')
ON CONFLICT DO NOTHING;

INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
VALUES 
    -- Server list and get
    ('p', 'group_user', '/api/v1/commands/*', 'PUT', '', '', ''),
    ('p', 'agent', '/api/v1/commands/*', 'PUT', '', '', ''),
    ('p', 'group_admin', '/api/v1/commands/*', 'PUT', '', '', ''),
    ('p', 'root', '/api/v1/commands/*', 'PUT', '', '', '')
ON CONFLICT DO NOTHING;
INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
VALUES 
    -- Server list and get
    ('p', 'group_user', '/api/v1/commands/*', 'DELETE', '', '', ''),
    ('p', 'agent', '/api/v1/commands/*', 'DELETE', '', '', ''),
    ('p', 'group_admin', '/api/v1/commands/*', 'DELETE', '', '', ''),
    ('p', 'root', '/api/v1/commands/*', 'DELETE', '', '', '')
ON CONFLICT DO NOTHING;



INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
VALUES 
    -- Server list and get
    ('p', 'group_user', '/api/v1/commands', 'POST', '', '', ''),
    ('p', 'agent', '/api/v1/commands', 'POST', '', '', ''),
    ('p', 'group_admin', '/api/v1/commands', 'POST', '', '', ''),
    ('p', 'root', '/api/v1/commands', 'POST', '', '', '')
ON CONFLICT DO NOTHING;

INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
VALUES 
    -- Server list and get
    ('p', 'group_user', '/api/v1/commands', 'PUT', '', '', ''),
    ('p', 'agent', '/api/v1/commands', 'PUT', '', '', ''),
    ('p', 'group_admin', '/api/v1/commands', 'PUT', '', '', ''),
    ('p', 'root', '/api/v1/commands', 'PUT', '', '', '')
ON CONFLICT DO NOTHING;
