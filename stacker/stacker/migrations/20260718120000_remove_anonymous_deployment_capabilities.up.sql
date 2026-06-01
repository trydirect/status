-- Deployment capabilities expose agent state and must require authentication.
DELETE FROM public.casbin_rule
WHERE ptype = 'p'
  AND v0 = 'group_anonymous'
  AND v1 = '/api/v1/deployments/:deployment_hash/capabilities'
  AND v2 = 'GET';
