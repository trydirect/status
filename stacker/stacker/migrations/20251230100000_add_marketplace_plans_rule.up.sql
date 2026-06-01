-- Casbin rule for admin marketplace plans endpoint
INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
VALUES ('p', 'group_admin', '/admin/marketplace/plans', 'GET', '', '', '')
ON CONFLICT DO NOTHING;
