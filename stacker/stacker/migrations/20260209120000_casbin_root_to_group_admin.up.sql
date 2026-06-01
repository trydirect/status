-- Map User Service 'root' role to stacker 'group_admin' role group
-- User Service /me endpoint returns role="root" for admin users,
-- but stacker Casbin policies use 'group_admin' for admin-level access.
-- This grouping rule bridges the two role systems.
INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
VALUES ('g', 'root', 'group_admin', '', '', '', '')
ON CONFLICT DO NOTHING;
