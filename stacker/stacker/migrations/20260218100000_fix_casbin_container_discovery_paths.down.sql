-- Revert fix: remove correct-path rules and restore the original (wrong) ones
DELETE FROM public.casbin_rule
WHERE ptype = 'p'
  AND v1 IN (
    '/project/:id/containers/discover',
    '/project/:id/containers/import'
  );

-- Re-insert the original (incorrect) rules so rolling back is clean
INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
VALUES
    ('p', 'group_user',  '/api/v1/project/:id/containers/discover', 'GET',  '', '', ''),
    ('p', 'group_admin', '/api/v1/project/:id/containers/discover', 'GET',  '', '', ''),
    ('p', 'root',        '/api/v1/project/:id/containers/discover', 'GET',  '', '', ''),
    ('p', 'group_user',  '/api/v1/project/:id/containers/import',   'POST', '', '', ''),
    ('p', 'group_admin', '/api/v1/project/:id/containers/import',   'POST', '', '', ''),
    ('p', 'root',        '/api/v1/project/:id/containers/import',   'POST', '', '', '')
ON CONFLICT DO NOTHING;
