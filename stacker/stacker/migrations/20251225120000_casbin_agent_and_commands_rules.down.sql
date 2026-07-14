-- Rollback Casbin rules for agent and commands endpoints
DELETE FROM public.casbin_rule WHERE ptype='p' AND v0='group_user' AND v1='/api/v1/agent/register' AND v2='POST' AND v3='' AND v4='' AND v5='';
DELETE FROM public.casbin_rule WHERE ptype='p' AND v0='group_admin' AND v1='/api/v1/agent/register' AND v2='POST' AND v3='' AND v4='' AND v5='';
DELETE FROM public.casbin_rule WHERE ptype='p' AND v0='client' AND v1='/api/v1/agent/register' AND v2='POST' AND v3='' AND v4='' AND v5='';

DELETE FROM public.casbin_rule WHERE ptype='p' AND v0='group_user' AND v1='/api/v1/agent/commands/report' AND v2='POST' AND v3='' AND v4='' AND v5='';
DELETE FROM public.casbin_rule WHERE ptype='p' AND v0='group_admin' AND v1='/api/v1/agent/commands/report' AND v2='POST' AND v3='' AND v4='' AND v5='';
DELETE FROM public.casbin_rule WHERE ptype='p' AND v0='client' AND v1='/api/v1/agent/commands/report' AND v2='POST' AND v3='' AND v4='' AND v5='';

DELETE FROM public.casbin_rule WHERE ptype='p' AND v0='group_user' AND v1='/api/v1/agent/commands/wait/:deployment_hash' AND v2='GET' AND v3='' AND v4='' AND v5='';
DELETE FROM public.casbin_rule WHERE ptype='p' AND v0='group_admin' AND v1='/api/v1/agent/commands/wait/:deployment_hash' AND v2='GET' AND v3='' AND v4='' AND v5='';
DELETE FROM public.casbin_rule WHERE ptype='p' AND v0='client' AND v1='/api/v1/agent/commands/wait/:deployment_hash' AND v2='GET' AND v3='' AND v4='' AND v5='';

DELETE FROM public.casbin_rule WHERE ptype='p' AND v0='group_user' AND v1='/api/v1/commands' AND v2='POST' AND v3='' AND v4='' AND v5='';
DELETE FROM public.casbin_rule WHERE ptype='p' AND v0='group_admin' AND v1='/api/v1/commands' AND v2='POST' AND v3='' AND v4='' AND v5='';

DELETE FROM public.casbin_rule WHERE ptype='p' AND v0='group_user' AND v1='/api/v1/commands/:deployment_hash' AND v2='GET' AND v3='' AND v4='' AND v5='';
DELETE FROM public.casbin_rule WHERE ptype='p' AND v0='group_admin' AND v1='/api/v1/commands/:deployment_hash' AND v2='GET' AND v3='' AND v4='' AND v5='';

DELETE FROM public.casbin_rule WHERE ptype='p' AND v0='group_user' AND v1='/api/v1/commands/:deployment_hash/:command_id' AND v2='GET' AND v3='' AND v4='' AND v5='';
DELETE FROM public.casbin_rule WHERE ptype='p' AND v0='group_admin' AND v1='/api/v1/commands/:deployment_hash/:command_id' AND v2='GET' AND v3='' AND v4='' AND v5='';

DELETE FROM public.casbin_rule WHERE ptype='p' AND v0='group_user' AND v1='/api/v1/commands/:deployment_hash/:command_id/cancel' AND v2='POST' AND v3='' AND v4='' AND v5='';
DELETE FROM public.casbin_rule WHERE ptype='p' AND v0='group_admin' AND v1='/api/v1/commands/:deployment_hash/:command_id/cancel' AND v2='POST' AND v3='' AND v4='' AND v5='';
