-- Remove the casbin rule for fetching a deployment by hash
DELETE FROM public.casbin_rule
WHERE ptype = 'p'
  AND v0 = 'group_user'
  AND v1 = '/api/v1/deployments/hash/:hash'
  AND v2 = 'GET';
