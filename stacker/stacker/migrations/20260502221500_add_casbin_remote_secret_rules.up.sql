-- Add Casbin rules for remote secret endpoints

INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
VALUES
    -- Project app secret routes
    ('p', 'group_user', '/project/:id/apps/:code/secrets', 'GET', '', '', ''),
    ('p', 'group_user', '/project/:id/apps/:code/secrets/:name', 'GET', '', '', ''),
    ('p', 'group_user', '/project/:id/apps/:code/secrets/:name', 'PUT', '', '', ''),
    ('p', 'group_user', '/project/:id/apps/:code/secrets/:name', 'DELETE', '', '', ''),
    -- Server secret routes
    ('p', 'group_user', '/server/:id/secrets', 'GET', '', '', ''),
    ('p', 'group_user', '/server/:id/secrets/:name', 'GET', '', '', ''),
    ('p', 'group_user', '/server/:id/secrets/:name', 'PUT', '', '', ''),
    ('p', 'group_user', '/server/:id/secrets/:name', 'DELETE', '', '', ''),
    ('p', 'root', '/server/:id/secrets', 'GET', '', '', ''),
    ('p', 'root', '/server/:id/secrets/:name', 'GET', '', '', ''),
    ('p', 'root', '/server/:id/secrets/:name', 'PUT', '', '', ''),
    ('p', 'root', '/server/:id/secrets/:name', 'DELETE', '', '', '')
ON CONFLICT DO NOTHING;
