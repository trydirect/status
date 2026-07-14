DELETE FROM public.casbin_rule
WHERE ptype = 'p'
  AND v0 = 'group_user'
  AND v1 = '/api/v1/deployments/:id/force-complete'
  AND v2 = 'POST';
