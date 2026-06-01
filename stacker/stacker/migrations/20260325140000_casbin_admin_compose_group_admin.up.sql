-- Allow group_admin (and roles inheriting it, like root) to access the admin
-- project compose endpoint.  The existing rule only grants access to the
-- admin_service JWT role, but OAuth-based access (User Service client
-- credentials) authenticates as the client owner whose role is "root".
-- root inherits group_admin, so adding the policy here covers both paths.
INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
VALUES ('p', 'group_admin', '/admin/project/:id/compose', 'GET', '', '', '')
ON CONFLICT DO NOTHING;
