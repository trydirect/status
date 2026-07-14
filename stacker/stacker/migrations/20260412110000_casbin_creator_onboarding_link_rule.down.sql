DELETE FROM public.casbin_rule
WHERE ptype = 'p'
  AND v1 = '/api/templates/mine/vendor-profile/onboarding-link'
  AND v2 = 'POST';
