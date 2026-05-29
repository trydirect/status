-- Remove Casbin rules for deleting project apps

DELETE FROM public.casbin_rule
WHERE ptype = 'p'
  AND v0 = 'group_user'
  AND v1 IN (
    '/project/:id/apps/:code',
    '/api/v1/project/:id/apps/:code'
  )
  AND v2 = 'DELETE';
