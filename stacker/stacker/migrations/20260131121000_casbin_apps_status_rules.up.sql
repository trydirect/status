-- Add Casbin POST rule for app status updates reported by agents

INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
VALUES 
    ('p', 'agent', '/api/v1/apps/status', 'POST', '', '', ''),
    ('p', 'group_admin', '/api/v1/apps/status', 'POST', '', '', ''),
    ('p', 'root', '/api/v1/apps/status', 'POST', '', '', '')
ON CONFLICT DO NOTHING;
