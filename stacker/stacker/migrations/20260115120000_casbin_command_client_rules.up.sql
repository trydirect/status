-- Add Casbin rules for command endpoints for client role

INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
VALUES 
    ('p', 'client', '/api/v1/commands', 'GET', '', '', ''),
    ('p', 'client', '/api/v1/commands/:deployment_hash', 'GET', '', '', ''),
    ('p', 'client', '/api/v1/commands/:deployment_hash/:command_id', 'GET', '', '', ''),
    ('p', 'client', '/api/v1/commands/:deployment_hash/:command_id/cancel', 'POST', '', '', ''),
    ('p', 'group_user', '/api/v1/commands', 'GET', '', '', ''),
    ('p', 'root', '/api/v1/commands', 'GET', '', '', ''),
    ('p', 'root', '/api/v1/commands/:deployment_hash', 'GET', '', '', ''),
    ('p', 'root', '/api/v1/commands/:deployment_hash/:command_id', 'GET', '', '', ''),
    ('p', 'root', '/api/v1/commands/:deployment_hash/:command_id/cancel', 'POST', '', '', '')
ON CONFLICT DO NOTHING;
