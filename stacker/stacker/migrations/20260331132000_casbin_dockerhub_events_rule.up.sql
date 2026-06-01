-- Allow authenticated users to post DockerHub autocomplete analytics events
INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
VALUES ('p', 'group_user', '/dockerhub/events', 'POST', '', '', '')
ON CONFLICT DO NOTHING;

INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
VALUES ('p', 'group_admin', '/dockerhub/events', 'POST', '', '', '')
ON CONFLICT DO NOTHING;
