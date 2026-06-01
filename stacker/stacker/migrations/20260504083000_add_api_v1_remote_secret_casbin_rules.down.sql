-- Remove Casbin rules for /api/v1 project-scoped remote secret endpoints

DELETE FROM public.casbin_rule
WHERE ptype = 'p'
  AND v0 = 'group_user'
  AND v1 IN (
    '/api/v1/project/:id/apps/:code/secrets',
    '/api/v1/project/:id/apps/:code/secrets/:name'
  )
  AND v2 IN ('GET', 'PUT', 'DELETE');
