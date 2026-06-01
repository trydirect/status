-- Allow authenticated users to fetch deployment status by ID and by project ID
INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
VALUES
    ('p', 'group_user', '/api/v1/deployments/:id', 'GET', '', '', ''),
    ('p', 'group_user', '/api/v1/deployments/project/:project_id', 'GET', '', '', '')
ON CONFLICT DO NOTHING;
