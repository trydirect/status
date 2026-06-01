DELETE FROM public.casbin_rule
WHERE ptype = 'p'
  AND v0 IN ('group_user', 'group_admin')
  AND (
    (v1 = '/api/agreement' AND v2 IN ('GET', 'POST'))
    OR (v1 = '/api/agreement/:id' AND v2 = 'GET')
    OR (v1 = '/api/agreement/accepted/:id' AND v2 = 'GET')
  );
