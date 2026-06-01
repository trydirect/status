-- Rollback Casbin rules for Marketplace endpoints
DELETE FROM public.casbin_rule WHERE ptype = 'p' AND v0 = 'group_anonymous' AND v1 = '/api/templates' AND v2 = 'GET';
DELETE FROM public.casbin_rule WHERE ptype = 'p' AND v0 = 'group_anonymous' AND v1 = '/api/templates/:slug' AND v2 = 'GET';

DELETE FROM public.casbin_rule WHERE ptype = 'p' AND v0 = 'group_user' AND v1 = '/api/templates' AND v2 = 'POST';
DELETE FROM public.casbin_rule WHERE ptype = 'p' AND v0 = 'group_user' AND v1 = '/api/templates/:id' AND v2 = 'PUT';
DELETE FROM public.casbin_rule WHERE ptype = 'p' AND v0 = 'group_user' AND v1 = '/api/templates/:id/submit' AND v2 = 'POST';
DELETE FROM public.casbin_rule WHERE ptype = 'p' AND v0 = 'group_user' AND v1 = '/api/templates/mine' AND v2 = 'GET';

DELETE FROM public.casbin_rule WHERE ptype = 'p' AND v0 = 'group_admin' AND v1 = '/api/admin/templates' AND v2 = 'GET';
DELETE FROM public.casbin_rule WHERE ptype = 'p' AND v0 = 'group_admin' AND v1 = '/api/admin/templates/:id/approve' AND v2 = 'POST';
DELETE FROM public.casbin_rule WHERE ptype = 'p' AND v0 = 'group_admin' AND v1 = '/api/admin/templates/:id/reject' AND v2 = 'POST';
