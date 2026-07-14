DELETE FROM public.casbin_rule
WHERE ptype = 'p'
  AND v1 = '/server/:id/ssh-key/authorize-public-key'
  AND v2 = 'POST'
  AND v0 IN ('group_user', 'root')
  AND v3 = ''
  AND v4 = ''
  AND v5 = '';
