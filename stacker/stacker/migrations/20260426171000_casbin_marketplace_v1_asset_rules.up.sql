INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
VALUES
    ('p', 'group_anonymous', '/api/v1/templates/:slug', 'GET', '', '', ''),
    ('p', 'group_user', '/api/v1/templates/:id', 'PUT', '', '', ''),
    ('p', 'group_user', '/api/v1/templates/:id/submit', 'POST', '', '', ''),
    ('p', 'group_user', '/api/v1/templates/:id/resubmit', 'POST', '', '', ''),
    ('p', 'group_user', '/api/v1/templates/:id/assets/presign', 'POST', '', '', ''),
    ('p', 'group_user', '/api/v1/templates/:id/assets/finalize', 'POST', '', '', ''),
    ('p', 'group_user', '/api/v1/templates/:id/assets/presign-download', 'POST', '', '', '')
ON CONFLICT DO NOTHING;
