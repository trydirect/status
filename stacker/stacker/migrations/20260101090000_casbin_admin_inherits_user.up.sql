-- Ensure group_admin inherits group_user so admin (and root) receive user permissions
INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
VALUES ('g', 'group_admin', 'group_user', '', '', '', '')
ON CONFLICT DO NOTHING;
