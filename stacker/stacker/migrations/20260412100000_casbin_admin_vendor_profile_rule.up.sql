-- Add Casbin rules for admin vendor profile patch endpoint
INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
VALUES ('p', 'admin_service', '/api/admin/templates/:id/vendor-profile', 'PATCH', '', '', '')
ON CONFLICT DO NOTHING;

INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
VALUES ('p', 'group_admin', '/api/admin/templates/:id/vendor-profile', 'PATCH', '', '', '')
ON CONFLICT DO NOTHING;

INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
VALUES ('p', 'admin_service', '/stacker/api/admin/templates/:id/vendor-profile', 'PATCH', '', '', '')
ON CONFLICT DO NOTHING;

INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
VALUES ('p', 'group_admin', '/stacker/api/admin/templates/:id/vendor-profile', 'PATCH', '', '', '')
ON CONFLICT DO NOTHING;
