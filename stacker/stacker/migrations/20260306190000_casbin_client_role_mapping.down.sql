-- Revert client role Casbin mappings
DELETE FROM public.casbin_rule WHERE ptype = 'g' AND v0 = 'client' AND v1 = 'group_anonymous';
DELETE FROM public.casbin_rule WHERE ptype = 'p' AND v0 = 'client' AND v1 = '/api/v1/agent/register' AND v2 = 'POST';
DELETE FROM public.casbin_rule WHERE ptype = 'p' AND v0 = 'client' AND v1 = '/api/v1/agent/commands/wait/:deployment_hash' AND v2 = 'GET';
DELETE FROM public.casbin_rule WHERE ptype = 'p' AND v0 = 'client' AND v1 = '/api/v1/agent/commands/report' AND v2 = 'POST';
DELETE FROM public.casbin_rule WHERE ptype = 'p' AND v0 = 'client' AND v1 = '/project/:id/deploy' AND v2 = 'POST';
DELETE FROM public.casbin_rule WHERE ptype = 'p' AND v0 = 'client' AND v1 = '/project/:id/deploy/:cloud_id' AND v2 = 'POST';
DELETE FROM public.casbin_rule WHERE ptype = 'p' AND v0 = 'client' AND v1 = '/project/:id/compose' AND v2 = 'GET';
DELETE FROM public.casbin_rule WHERE ptype = 'p' AND v0 = 'client' AND v1 = '/project/:id/compose' AND v2 = 'POST';
