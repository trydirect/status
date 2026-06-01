-- Allow authenticated agents to fetch notifications

INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
VALUES ('p', 'agent', '/api/v1/agent/notifications', 'GET', '', '', '')
ON CONFLICT ON CONSTRAINT unique_key_sqlx_adapter DO NOTHING;
