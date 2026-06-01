-- Add Casbin rules for admin_service role (internal service authentication)
INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5) 
VALUES ('p', 'admin_service', '/stacker/admin/templates', 'GET', '', '', '')
ON CONFLICT DO NOTHING;

INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5) 
VALUES ('p', 'admin_service', '/stacker/admin/templates/:id/approve', 'POST', '', '', '')
ON CONFLICT DO NOTHING;

INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5) 
VALUES ('p', 'admin_service', '/stacker/admin/templates/:id/reject', 'POST', '', '', '')
ON CONFLICT DO NOTHING;

INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5) 
VALUES ('p', 'admin_service', '/api/admin/templates', 'GET', '', '', '')
ON CONFLICT DO NOTHING;

INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5) 
VALUES ('p', 'admin_service', '/api/admin/templates/:id/approve', 'POST', '', '', '')
ON CONFLICT DO NOTHING;

INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5) 
VALUES ('p', 'admin_service', '/api/admin/templates/:id/reject', 'POST', '', '', '')
ON CONFLICT DO NOTHING;
