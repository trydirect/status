-- Allow user and admin access to pipe instance execution stream (SSE)
INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
VALUES ('p', 'group_user', '/api/v1/pipes/instances/:instance_id/stream', 'GET', '', '', '')
ON CONFLICT DO NOTHING;

INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
VALUES ('p', 'group_admin', '/api/v1/pipes/instances/:instance_id/stream', 'GET', '', '', '')
ON CONFLICT DO NOTHING;
