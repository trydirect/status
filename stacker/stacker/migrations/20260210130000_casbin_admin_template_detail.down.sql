-- Remove Casbin rules for admin template detail endpoint
DELETE FROM public.casbin_rule WHERE ptype = 'p' AND v0 = 'admin_service' AND v1 = '/api/admin/templates/:id' AND v2 = 'GET';
DELETE FROM public.casbin_rule WHERE ptype = 'p' AND v0 = 'group_admin' AND v1 = '/api/admin/templates/:id' AND v2 = 'GET';
DELETE FROM public.casbin_rule WHERE ptype = 'p' AND v0 = 'admin_service' AND v1 = '/stacker/admin/templates/:id' AND v2 = 'GET';
DELETE FROM public.casbin_rule WHERE ptype = 'p' AND v0 = 'group_admin' AND v1 = '/stacker/admin/templates/:id' AND v2 = 'GET';
