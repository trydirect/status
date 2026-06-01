-- Allow authenticated users to force-complete a stuck (paused/error) deployment
INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
VALUES
    ('p', 'group_user', '/api/v1/deployments/:id/force-complete', 'POST', '', '', '')
ON CONFLICT DO NOTHING;
