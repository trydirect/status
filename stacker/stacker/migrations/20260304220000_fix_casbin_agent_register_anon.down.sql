-- Revert: remove the anonymous agent registration Casbin rule
DELETE FROM public.casbin_rule
WHERE ptype = 'p'
  AND v0 = 'group_anonymous'
  AND v1 = '/api/v1/agent/register'
  AND v2 = 'POST';
