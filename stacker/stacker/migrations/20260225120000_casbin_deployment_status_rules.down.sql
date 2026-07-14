-- Rollback: remove deployment status ACL rules
DELETE FROM public.casbin_rule
WHERE ptype = 'p'
  AND v0 = 'group_user'
  AND v1 IN ('/api/v1/deployments/:id', '/api/v1/deployments/project/:project_id')
  AND v2 = 'GET';
