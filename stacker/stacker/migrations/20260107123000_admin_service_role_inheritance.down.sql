-- Revoke admin_service inheritance from admin permissions
DELETE FROM public.casbin_rule
WHERE ptype = 'g'
  AND v0 = 'admin_service'
  AND v1 = 'group_admin'
  AND v2 = ''
  AND v3 = ''
  AND v4 = ''
  AND v5 = '';
