-- Revoke admin_service access to admin project compose endpoint
DELETE FROM public.casbin_rule
WHERE ptype = 'p'
  AND v0 = 'admin_service'
  AND v1 = '/admin/project/:id/compose'
  AND v2 = 'GET';
