-- Casbin rules for Marketplace endpoints

-- Public read rules
INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5) VALUES ('p', 'group_anonymous', '/api/templates', 'GET', '', '', '') ON CONFLICT DO NOTHING;
INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5) VALUES ('p', 'group_anonymous', '/api/templates/:slug', 'GET', '', '', '') ON CONFLICT DO NOTHING;

-- Creator rules
INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5) VALUES ('p', 'group_user', '/api/templates', 'POST', '', '', '') ON CONFLICT DO NOTHING;
INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5) VALUES ('p', 'group_user', '/api/templates/:id', 'PUT', '', '', '') ON CONFLICT DO NOTHING;
INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5) VALUES ('p', 'group_user', '/api/templates/:id/submit', 'POST', '', '', '') ON CONFLICT DO NOTHING;
INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5) VALUES ('p', 'group_user', '/api/templates/mine', 'GET', '', '', '') ON CONFLICT DO NOTHING;

-- Admin moderation rules
INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5) VALUES ('p', 'group_admin', '/api/admin/templates', 'GET', '', '', '') ON CONFLICT DO NOTHING;
INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5) VALUES ('p', 'group_admin', '/api/admin/templates/:id/approve', 'POST', '', '', '') ON CONFLICT DO NOTHING;
INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5) VALUES ('p', 'group_admin', '/api/admin/templates/:id/reject', 'POST', '', '', '') ON CONFLICT DO NOTHING;
