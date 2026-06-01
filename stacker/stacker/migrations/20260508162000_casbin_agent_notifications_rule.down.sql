-- Remove agent notifications Casbin rule

DELETE FROM public.casbin_rule
WHERE ptype = 'p'
  AND v0 = 'agent'
  AND v1 = '/api/v1/agent/notifications'
  AND v2 = 'GET';
