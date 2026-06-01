DELETE FROM public.casbin_rule
WHERE ptype = 'p'
  AND v0 = 'group_anonymous'
  AND v1 = '/api/v1/marketplace/deploy-complete'
  AND v2 = 'POST';
