-- Remove Casbin POST rules for commands API

DELETE FROM public.casbin_rule WHERE ptype = 'p' AND v0 = 'group_user' AND v1 = '/api/v1/commands/*' AND v2 = 'POST';
DELETE FROM public.casbin_rule WHERE ptype = 'p' AND v0 = 'agent' AND v1 = '/api/v1/commands/*' AND v2 = 'POST';
DELETE FROM public.casbin_rule WHERE ptype = 'p' AND v0 = 'group_admin' AND v1 = '/api/v1/commands/*' AND v2 = 'POST';
DELETE FROM public.casbin_rule WHERE ptype = 'p' AND v0 = 'root' AND v1 = '/api/v1/commands/*' AND v2 = 'POST';

DELETE FROM public.casbin_rule WHERE ptype = 'p' AND v0 = 'group_user' AND v1 = '/api/v1/commands/*' AND v2 = 'PUT';
DELETE FROM public.casbin_rule WHERE ptype = 'p' AND v0 = 'agent' AND v1 = '/api/v1/commands/*' AND v2 = 'PUT';
DELETE FROM public.casbin_rule WHERE ptype = 'p' AND v0 = 'group_admin' AND v1 = '/api/v1/commands/*' AND v2 = 'PUT';
DELETE FROM public.casbin_rule WHERE ptype = 'p' AND v0 = 'root' AND v1 = '/api/v1/commands/*' AND v2 = 'PUT';

DELETE FROM public.casbin_rule WHERE ptype = 'p' AND v0 = 'group_user' AND v1 = '/api/v1/commands/*' AND v2 = 'DELETE';
DELETE FROM public.casbin_rule WHERE ptype = 'p' AND v0 = 'agent' AND v1 = '/api/v1/commands/*' AND v2 = 'DELETE';
DELETE FROM public.casbin_rule WHERE ptype = 'p' AND v0 = 'group_admin' AND v1 = '/api/v1/commands/*' AND v2 = 'DELETE';
DELETE FROM public.casbin_rule WHERE ptype = 'p' AND v0 = 'root' AND v1 = '/api/v1/commands/*' AND v2 = 'DELETE';

DELETE FROM public.casbin_rule WHERE ptype = 'p' AND v0 = 'group_user' AND v1 = '/api/v1/commands' AND v2 = 'POST';
DELETE FROM public.casbin_rule WHERE ptype = 'p' AND v0 = 'agent' AND v1 = '/api/v1/commands' AND v2 = 'POST';
DELETE FROM public.casbin_rule WHERE ptype = 'p' AND v0 = 'group_admin' AND v1 = '/api/v1/commands' AND v2 = 'POST';
DELETE FROM public.casbin_rule WHERE ptype = 'p' AND v0 = 'root' AND v1 = '/api/v1/commands' AND v2 = 'POST';

DELETE FROM public.casbin_rule WHERE ptype = 'p' AND v0 = 'group_user' AND v1 = '/api/v1/commands' AND v2 = 'PUT';
DELETE FROM public.casbin_rule WHERE ptype = 'p' AND v0 = 'agent' AND v1 = '/api/v1/commands' AND v2 = 'PUT';
DELETE FROM public.casbin_rule WHERE ptype = 'p' AND v0 = 'group_admin' AND v1 = '/api/v1/commands' AND v2 = 'PUT';
DELETE FROM public.casbin_rule WHERE ptype = 'p' AND v0 = 'root' AND v1 = '/api/v1/commands' AND v2 = 'PUT';
