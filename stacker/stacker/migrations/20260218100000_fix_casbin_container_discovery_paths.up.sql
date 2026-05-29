-- Fix Casbin rules for container discovery and import endpoints
-- The original migration used wrong path prefix '/api/v1/project/...'
-- Correct paths are '/project/:id/containers/discover' and '/project/:id/containers/import'

-- Remove incorrectly-prefixed rules
DELETE FROM public.casbin_rule
WHERE ptype = 'p'
  AND v1 IN (
    '/api/v1/project/:id/containers/discover',
    '/api/v1/project/:id/containers/import'
  );

-- Insert rules with correct paths
INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
VALUES
    ('p', 'group_user',  '/project/:id/containers/discover', 'GET',  '', '', ''),
    ('p', 'group_admin', '/project/:id/containers/discover', 'GET',  '', '', ''),
    ('p', 'root',        '/project/:id/containers/discover', 'GET',  '', '', ''),
    ('p', 'group_user',  '/project/:id/containers/import',   'POST', '', '', ''),
    ('p', 'group_admin', '/project/:id/containers/import',   'POST', '', '', ''),
    ('p', 'root',        '/project/:id/containers/import',   'POST', '', '', '')
ON CONFLICT DO NOTHING;
