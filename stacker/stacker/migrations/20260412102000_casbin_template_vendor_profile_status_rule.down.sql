DELETE FROM public.casbin_rule
WHERE ptype = 'p'
  AND v1 = '/api/templates/:id/vendor-profile-status'
  AND v2 = 'GET';
