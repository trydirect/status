-- Remove Casbin rules for admin template unapprove endpoint
DELETE FROM public.casbin_rule
WHERE ptype = 'p' AND v1 = '/api/admin/templates/:id/unapprove' AND v2 = 'POST';
