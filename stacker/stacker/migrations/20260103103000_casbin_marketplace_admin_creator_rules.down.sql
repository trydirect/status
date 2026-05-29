DELETE FROM public.casbin_rule WHERE ptype = 'p' AND v0 = 'group_admin' AND v1 = '/api/templates' AND v2 = 'POST';
DELETE FROM public.casbin_rule WHERE ptype = 'p' AND v0 = 'group_admin' AND v1 = '/api/templates/:id' AND v2 = 'PUT';
DELETE FROM public.casbin_rule WHERE ptype = 'p' AND v0 = 'group_admin' AND v1 = '/api/templates/:id/submit' AND v2 = 'POST';
DELETE FROM public.casbin_rule WHERE ptype = 'p' AND v0 = 'group_admin' AND v1 = '/api/templates/mine' AND v2 = 'GET';
