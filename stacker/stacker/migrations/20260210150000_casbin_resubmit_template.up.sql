-- Allow users and admins to resubmit templates with new versions
INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
VALUES ('p', 'group_user', '/api/templates/:id/resubmit', 'POST', '', '', '')
ON CONFLICT DO NOTHING;

INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
VALUES ('p', 'group_admin', '/api/templates/:id/resubmit', 'POST', '', '', '')
ON CONFLICT DO NOTHING;

INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
VALUES ('p', 'admin_service', '/api/templates/:id/resubmit', 'POST', '', '', '')
ON CONFLICT DO NOTHING;

-- Also cover /stacker/ prefixed paths (nginx proxy)
INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
VALUES ('p', 'group_user', '/stacker/templates/:id/resubmit', 'POST', '', '', '')
ON CONFLICT DO NOTHING;

INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
VALUES ('p', 'group_admin', '/stacker/templates/:id/resubmit', 'POST', '', '', '')
ON CONFLICT DO NOTHING;

INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
VALUES ('p', 'admin_service', '/stacker/templates/:id/resubmit', 'POST', '', '', '')
ON CONFLICT DO NOTHING;
