-- Add Casbin rules for pipe template, instance, and execution endpoints
-- Routes are under /v1/pipes/ scope

INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
VALUES
    -- Pipe templates
    ('p', 'group_user', '/api/v1/pipes/templates', 'GET', '', '', ''),
    ('p', 'group_user', '/api/v1/pipes/templates', 'POST', '', '', ''),
    ('p', 'group_user', '/api/v1/pipes/templates/:template_id', 'GET', '', '', ''),
    ('p', 'group_user', '/api/v1/pipes/templates/:template_id', 'DELETE', '', '', ''),
    -- Pipe instances
    ('p', 'group_user', '/api/v1/pipes/instances', 'POST', '', '', ''),
    ('p', 'group_user', '/api/v1/pipes/instances/:deployment_hash', 'GET', '', '', ''),
    ('p', 'group_user', '/api/v1/pipes/instances/detail/:instance_id', 'GET', '', '', ''),
    ('p', 'group_user', '/api/v1/pipes/instances/:instance_id', 'DELETE', '', '', ''),
    ('p', 'group_user', '/api/v1/pipes/instances/:instance_id/status', 'PUT', '', '', ''),
    -- Pipe executions
    ('p', 'group_user', '/api/v1/pipes/instances/:instance_id/executions', 'GET', '', '', ''),
    ('p', 'group_user', '/api/v1/pipes/executions/:execution_id', 'GET', '', '', ''),
    ('p', 'group_user', '/api/v1/pipes/executions/:execution_id/replay', 'POST', '', '', '')
ON CONFLICT DO NOTHING;
