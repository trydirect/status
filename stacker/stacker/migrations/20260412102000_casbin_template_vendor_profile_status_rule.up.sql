INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
VALUES ('p', 'group_user', '/api/templates/:id/vendor-profile-status', 'GET', '', '', '')
ON CONFLICT DO NOTHING;

INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
VALUES ('p', 'group_admin', '/api/templates/:id/vendor-profile-status', 'GET', '', '', '')
ON CONFLICT DO NOTHING;
