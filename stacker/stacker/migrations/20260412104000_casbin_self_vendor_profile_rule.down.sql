DELETE FROM public.casbin_rule
WHERE ptype = 'p'
  AND v1 = '/api/templates/mine/vendor-profile'
  AND v2 = 'GET';
