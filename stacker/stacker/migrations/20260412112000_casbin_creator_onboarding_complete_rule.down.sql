DELETE FROM public.casbin_rule
WHERE ptype = 'p'
  AND v1 = '/api/templates/mine/vendor-profile/onboarding-complete'
  AND v2 = 'POST';
