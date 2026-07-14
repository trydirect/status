-- Allow admin_service role to access the admin project compose endpoint.
-- This enables TryDirect User Service to fetch marketplace template compose
-- snapshots at sync time (for buyer protection when vendor removes a template).
INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
VALUES ('p', 'admin_service', '/admin/project/:id/compose', 'GET', '', '', '')
ON CONFLICT DO NOTHING;
