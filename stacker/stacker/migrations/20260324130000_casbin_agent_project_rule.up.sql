-- Allow authenticated users to fetch the active agent snapshot for a project
INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
VALUES
    ('p', 'group_user', '/api/v1/agent/project/:project_id', 'GET', '', '', '')
ON CONFLICT DO NOTHING;
