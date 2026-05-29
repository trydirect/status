-- Rollback: remove the group_admin GET /project rule
DELETE FROM public.casbin_rule
WHERE ptype = 'p' AND v0 = 'group_admin' AND v1 = '/project' AND v2 = 'GET' AND v3 = '' AND v4 = '' AND v5 = '';
