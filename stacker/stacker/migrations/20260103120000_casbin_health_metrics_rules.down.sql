-- Remove Casbin rules for health check metrics endpoint

DELETE FROM public.casbin_rule 
WHERE ptype = 'p' 
  AND v0 IN ('group_anonymous', 'group_user', 'group_admin') 
  AND v1 = '/health_check/metrics' 
  AND v2 = 'GET';
