-- Allow anonymous, user, and admin access to /metrics (Prometheus endpoint)
INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
VALUES ('p', 'group_anonymous', '/metrics', 'GET', '', '', '')
ON CONFLICT DO NOTHING;

INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
VALUES ('p', 'group_user', '/metrics', 'GET', '', '', '')
ON CONFLICT DO NOTHING;

INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
VALUES ('p', 'group_admin', '/metrics', 'GET', '', '', '')
ON CONFLICT DO NOTHING;
