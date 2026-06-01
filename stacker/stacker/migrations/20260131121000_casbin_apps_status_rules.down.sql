-- Remove Casbin POST rule for app status updates reported by agents

DELETE FROM public.casbin_rule WHERE ptype = 'p' AND v0 = 'agent' AND v1 = '/api/v1/apps/status' AND v2 = 'POST';
DELETE FROM public.casbin_rule WHERE ptype = 'p' AND v0 = 'group_admin' AND v1 = '/api/v1/apps/status' AND v2 = 'POST';
DELETE FROM public.casbin_rule WHERE ptype = 'p' AND v0 = 'root' AND v1 = '/api/v1/apps/status' AND v2 = 'POST';
