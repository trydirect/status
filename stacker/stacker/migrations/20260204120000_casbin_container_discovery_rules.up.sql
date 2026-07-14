-- Add Casbin rules for container discovery and import endpoints

INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
VALUES 
    -- Discover containers - allow users and admins
    ('p', 'group_user', '/api/v1/project/:id/containers/discover', 'GET', '', '', ''),
    ('p', 'group_admin', '/api/v1/project/:id/containers/discover', 'GET', '', '', ''),
    ('p', 'root', '/api/v1/project/:id/containers/discover', 'GET', '', '', ''),
    -- Import containers - allow users and admins
    ('p', 'group_user', '/api/v1/project/:id/containers/import', 'POST', '', '', ''),
    ('p', 'group_admin', '/api/v1/project/:id/containers/import', 'POST', '', '', ''),
    ('p', 'root', '/api/v1/project/:id/containers/import', 'POST', '', '', '')
ON CONFLICT DO NOTHING;
