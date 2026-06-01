-- Revert Casbin rules for streaming endpoint
DELETE FROM public.casbin_rule WHERE ptype='p' AND v0='group_user' AND v1='/api/v1/pipes/instances/:instance_id/stream' AND v2='GET';
DELETE FROM public.casbin_rule WHERE ptype='p' AND v0='group_admin' AND v1='/api/v1/pipes/instances/:instance_id/stream' AND v2='GET';
