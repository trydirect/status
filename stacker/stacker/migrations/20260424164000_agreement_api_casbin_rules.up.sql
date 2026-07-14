INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
VALUES
    ('p', 'group_user', '/api/agreement', 'GET', '', '', ''),
    ('p', 'group_user', '/api/agreement/:id', 'GET', '', '', ''),
    ('p', 'group_user', '/api/agreement', 'POST', '', '', ''),
    ('p', 'group_user', '/api/agreement/accepted/:id', 'GET', '', '', ''),
    ('p', 'group_admin', '/api/agreement', 'GET', '', '', ''),
    ('p', 'group_admin', '/api/agreement/:id', 'GET', '', '', '')
ON CONFLICT DO NOTHING;
