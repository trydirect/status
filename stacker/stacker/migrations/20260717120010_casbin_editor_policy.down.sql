-- Revoke anonymous access to /editor static files
DELETE FROM public.casbin_rule WHERE ptype = 'p' AND v0 = 'group_anonymous' AND v1 IN ('/editor', '/editor/', '/editor/:path', '/editor/assets/:path');
