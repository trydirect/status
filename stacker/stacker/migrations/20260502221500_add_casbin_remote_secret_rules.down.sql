-- Remove Casbin rules for remote secret endpoints

DELETE FROM public.casbin_rule
WHERE ptype = 'p'
  AND (
    (v0 = 'group_user' AND v1 IN (
      '/project/:id/apps/:code/secrets',
      '/project/:id/apps/:code/secrets/:name',
      '/server/:id/secrets',
      '/server/:id/secrets/:name'
    ))
    OR
    (v0 = 'root' AND v1 IN (
      '/server/:id/secrets',
      '/server/:id/secrets/:name'
    ))
  )
  AND v2 IN ('GET', 'PUT', 'DELETE');
