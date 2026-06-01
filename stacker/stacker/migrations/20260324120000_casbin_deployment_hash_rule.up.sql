-- Allow authenticated users to fetch a deployment by its hash string
INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
VALUES
    ('p', 'group_user', '/api/v1/deployments/hash/:hash', 'GET', '', '', '')
ON CONFLICT DO NOTHING;
