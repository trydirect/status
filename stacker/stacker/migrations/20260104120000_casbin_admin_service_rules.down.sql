-- Remove Casbin rules for admin_service role
DELETE FROM public.casbin_rule WHERE ptype = 'p' AND v0 = 'admin_service' AND v1 = '/stacker/admin/templates' AND v2 = 'GET';
DELETE FROM public.casbin_rule WHERE ptype = 'p' AND v0 = 'admin_service' AND v1 = '/stacker/admin/templates/:id/approve' AND v2 = 'POST';
DELETE FROM public.casbin_rule WHERE ptype = 'p' AND v0 = 'admin_service' AND v1 = '/stacker/admin/templates/:id/reject' AND v2 = 'POST';
DELETE FROM public.casbin_rule WHERE ptype = 'p' AND v0 = 'admin_service' AND v1 = '/api/admin/templates' AND v2 = 'GET';
DELETE FROM public.casbin_rule WHERE ptype = 'p' AND v0 = 'admin_service' AND v1 = '/api/admin/templates/:id/approve' AND v2 = 'POST';
DELETE FROM public.casbin_rule WHERE ptype = 'p' AND v0 = 'admin_service' AND v1 = '/api/admin/templates/:id/reject' AND v2 = 'POST';
