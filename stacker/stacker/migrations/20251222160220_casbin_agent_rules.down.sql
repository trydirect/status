-- Remove agent casbin rules
DELETE FROM public.casbin_rule 
WHERE ptype = 'p' AND v0 = 'agent' AND v1 = '/api/v1/agent/commands/report' AND v2 = 'POST';

DELETE FROM public.casbin_rule 
WHERE ptype = 'p' AND v0 = 'agent' AND v1 = '/api/v1/agent/commands/wait/:deployment_hash' AND v2 = 'GET';

DELETE FROM public.casbin_rule 
WHERE ptype = 'p' AND v0 = 'group_anonymous' AND v1 = '/api/v1/agent/register' AND v2 = 'POST';

DELETE FROM public.casbin_rule 
WHERE ptype = 'p' AND v0 = 'group_user' AND v1 = '/api/v1/agent/register' AND v2 = 'POST';

DELETE FROM public.casbin_rule 
WHERE ptype = 'p' AND v0 = 'group_admin' AND v1 = '/api/v1/agent/register' AND v2 = 'POST';

DELETE FROM public.casbin_rule 
WHERE ptype = 'g' AND v0 = 'agent' AND v1 = 'group_anonymous';
