-- Add Casbin rules for server endpoints

-- Server list and get endpoints (group_user role - authenticated users)
INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
VALUES 
    -- Server list and get
    ('p', 'group_user', '/server', 'GET', '', '', ''),
    ('p', 'group_user', '/server/:id', 'GET', '', '', ''),
    ('p', 'group_user', '/server/project/:project_id', 'GET', '', '', ''),
    ('p', 'group_user', '/server/:id', 'PUT', '', '', ''),
    ('p', 'group_user', '/server/:id', 'DELETE', '', '', ''),
    -- SSH key management
    ('p', 'group_user', '/server/:id/ssh-key/generate', 'POST', '', '', ''),
    ('p', 'group_user', '/server/:id/ssh-key/upload', 'POST', '', '', ''),
    ('p', 'group_user', '/server/:id/ssh-key/public', 'GET', '', '', ''),
    ('p', 'group_user', '/server/:id/ssh-key', 'DELETE', '', '', ''),
    -- Root role (admin access)
    ('p', 'root', '/server', 'GET', '', '', ''),
    ('p', 'root', '/server/:id', 'GET', '', '', ''),
    ('p', 'root', '/server/project/:project_id', 'GET', '', '', ''),
    ('p', 'root', '/server/:id', 'PUT', '', '', ''),
    ('p', 'root', '/server/:id', 'DELETE', '', '', ''),
    ('p', 'root', '/server/:id/ssh-key/generate', 'POST', '', '', ''),
    ('p', 'root', '/server/:id/ssh-key/upload', 'POST', '', '', ''),
    ('p', 'root', '/server/:id/ssh-key/public', 'GET', '', '', ''),
    ('p', 'root', '/server/:id/ssh-key', 'DELETE', '', '', '')
ON CONFLICT DO NOTHING;
