-- Add Casbin ACL rules for audit, capabilities, and server delete-preview endpoints
-- Audit uses X-Internal-Key header for actual auth, but needs Casbin to pass middleware
-- Capabilities is a public-ish endpoint

INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
VALUES
    -- /api/v1/agent/audit POST (ingest) - needs all roles to pass Casbin
    ('p', 'group_user', '/api/v1/agent/audit', 'POST', '', '', ''),
    ('p', 'group_admin', '/api/v1/agent/audit', 'POST', '', '', ''),
    ('p', 'agent', '/api/v1/agent/audit', 'POST', '', '', ''),
    ('p', 'group_anonymous', '/api/v1/agent/audit', 'POST', '', '', ''),
    -- /api/v1/agent/audit GET (query)
    ('p', 'group_user', '/api/v1/agent/audit', 'GET', '', '', ''),
    ('p', 'group_admin', '/api/v1/agent/audit', 'GET', '', '', ''),
    ('p', 'agent', '/api/v1/agent/audit', 'GET', '', '', ''),
    -- /api/v1/deployments/:hash/capabilities GET
    ('p', 'group_user', '/api/v1/deployments/:deployment_hash/capabilities', 'GET', '', '', ''),
    ('p', 'group_admin', '/api/v1/deployments/:deployment_hash/capabilities', 'GET', '', '', ''),
    ('p', 'group_anonymous', '/api/v1/deployments/:deployment_hash/capabilities', 'GET', '', '', ''),
    ('p', 'agent', '/api/v1/deployments/:deployment_hash/capabilities', 'GET', '', '', ''),
    -- /server/:id/delete-preview GET
    ('p', 'group_user', '/server/:id/delete-preview', 'GET', '', '', ''),
    ('p', 'root', '/server/:id/delete-preview', 'GET', '', '', '')
ON CONFLICT ON CONSTRAINT unique_key_sqlx_adapter DO NOTHING;
