-- Remove Casbin rules for admin template security scan endpoint
DELETE FROM public.casbin_rule WHERE ptype = 'p' AND v1 = '/api/admin/templates/:id/security-scan' AND v2 = 'POST';
DELETE FROM public.casbin_rule WHERE ptype = 'p' AND v1 = '/stacker/admin/templates/:id/security-scan' AND v2 = 'POST';
