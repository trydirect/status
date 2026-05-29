DELETE FROM public.casbin_rule
WHERE ptype = 'p'
  AND (
    (v0 = 'group_anonymous' AND v1 = '/api/v1/templates/:slug' AND v2 = 'GET')
    OR (v0 = 'group_user' AND v1 = '/api/v1/templates/:id' AND v2 = 'PUT')
    OR (v0 = 'group_user' AND v1 = '/api/v1/templates/:id/submit' AND v2 = 'POST')
    OR (v0 = 'group_user' AND v1 = '/api/v1/templates/:id/resubmit' AND v2 = 'POST')
    OR (v0 = 'group_user' AND v1 = '/api/v1/templates/:id/assets/presign' AND v2 = 'POST')
    OR (v0 = 'group_user' AND v1 = '/api/v1/templates/:id/assets/finalize' AND v2 = 'POST')
    OR (v0 = 'group_user' AND v1 = '/api/v1/templates/:id/assets/presign-download' AND v2 = 'POST')
  );
