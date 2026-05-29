-- Rollback Casbin rules for admin pricing PATCH
DELETE FROM public.casbin_rule
WHERE v1 = '/api/admin/templates/:id/pricing' AND v2 = 'PATCH';
