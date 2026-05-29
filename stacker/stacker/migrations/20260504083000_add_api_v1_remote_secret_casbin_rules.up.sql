-- Add Casbin rules for /api/v1 project-scoped remote secret endpoints

INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
VALUES
    ('p', 'group_user', '/api/v1/project/:id/apps/:code/secrets', 'GET', '', '', ''),
    ('p', 'group_user', '/api/v1/project/:id/apps/:code/secrets/:name', 'GET', '', '', ''),
    ('p', 'group_user', '/api/v1/project/:id/apps/:code/secrets/:name', 'PUT', '', '', ''),
    ('p', 'group_user', '/api/v1/project/:id/apps/:code/secrets/:name', 'DELETE', '', '', '')
ON CONFLICT DO NOTHING;
