-- Add Casbin rules for command management endpoints
-- Users and admins can create, list, get, and cancel commands

-- User permissions: manage commands for their own deployments
INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
VALUES 
    ('p', 'group_user', '/api/v1/commands', 'POST', '', '', ''),                          -- Create command
    ('p', 'group_user', '/api/v1/commands/:deployment_hash', 'GET', '', '', ''),          -- List commands for deployment
    ('p', 'group_user', '/api/v1/commands/:deployment_hash/:command_id', 'GET', '', '', ''), -- Get specific command
    ('p', 'group_user', '/api/v1/commands/:deployment_hash/:command_id/cancel', 'POST', '', '', '') -- Cancel command
ON CONFLICT DO NOTHING;

-- Admin permissions: inherit all user permissions + full access
INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
VALUES 
    ('p', 'group_admin', '/api/v1/commands', 'POST', '', '', ''),
    ('p', 'group_admin', '/api/v1/commands/:deployment_hash', 'GET', '', '', ''),
    ('p', 'group_admin', '/api/v1/commands/:deployment_hash/:command_id', 'GET', '', '', ''),
    ('p', 'group_admin', '/api/v1/commands/:deployment_hash/:command_id/cancel', 'POST', '', '', '')
ON CONFLICT DO NOTHING;
