DELETE FROM public.casbin_rule
WHERE ptype = 'p'
  AND v1 = '/api/admin/templates/:id/needs-changes'
  AND v2 = 'POST';
