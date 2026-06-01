DELETE FROM public.casbin_rule
WHERE ptype = 'p'
  AND v0 = 'group_admin'
  AND v1 = '/admin/project/:id/compose'
  AND v2 = 'GET';
