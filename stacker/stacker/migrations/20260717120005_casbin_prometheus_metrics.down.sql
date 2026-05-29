DELETE FROM public.casbin_rule
WHERE ptype = 'p'
  AND v1 = '/metrics'
  AND v2 = 'GET';
