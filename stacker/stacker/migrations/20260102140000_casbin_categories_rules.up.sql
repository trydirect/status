-- Casbin rules for Categories endpoint
-- Categories are publicly readable for marketplace UI population

INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5) VALUES ('p', 'group_anonymous', '/api/categories', 'GET', '', '', '') ON CONFLICT DO NOTHING;
INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5) VALUES ('p', 'group_user', '/api/categories', 'GET', '', '', '') ON CONFLICT DO NOTHING;
INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5) VALUES ('p', 'group_admin', '/api/categories', 'GET', '', '', '') ON CONFLICT DO NOTHING;
