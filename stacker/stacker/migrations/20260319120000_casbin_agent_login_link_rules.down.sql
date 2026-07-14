-- Remove anonymous access rules for agent login and link endpoints
DELETE FROM public.casbin_rule
WHERE ptype = 'p'
  AND v0 = 'group_anonymous'
  AND v1 IN ('/api/v1/agent/login', '/api/v1/agent/link')
  AND v2 = 'POST';
