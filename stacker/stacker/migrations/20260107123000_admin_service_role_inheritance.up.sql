-- Allow admin_service JWT role to inherit all admin permissions
INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
VALUES ('g', 'admin_service', 'group_admin', '', '', '', '')
ON CONFLICT DO NOTHING;
