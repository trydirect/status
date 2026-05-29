DELETE FROM public.casbin_rule
WHERE ptype = 'p'
  AND v1 = '/server/:id/cloud-firewall'
  AND v2 = 'POST'
  AND v0 IN ('group_user', 'group_admin', 'root')
  AND v3 = ''
  AND v4 = ''
  AND v5 = '';
