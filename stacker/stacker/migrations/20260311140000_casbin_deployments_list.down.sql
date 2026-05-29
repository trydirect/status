-- Rollback: remove deployments list ACL rule
DELETE FROM public.casbin_rule
WHERE ptype = 'p'
  AND v0 = 'group_user'
  AND v1 = '/api/v1/deployments'
  AND v2 = 'GET';
