-- Add Casbin ACL for AI deployment/explain MCP tools introduced after the
-- initial per-tool MCP policy migration.

WITH tool_policy(subject, tool) AS (
    VALUES
        ('group_user', 'get_deployment_state'),
        ('group_user', 'get_deployment_plan'),
        ('group_user', 'get_deployment_events'),
        ('group_user', 'apply_deployment_plan'),
        ('group_user', 'explain_env'),
        ('group_user', 'explain_topology')
)
INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
SELECT 'p', subject, '/mcp/tools/' || tool, 'CALL', '', '', ''
FROM tool_policy
ON CONFLICT DO NOTHING;

WITH route_policy(subject, route, action) AS (
    VALUES
        ('group_user', '/api/v1/deployments/:deployment_hash/state', 'GET'),
        ('group_user', '/api/v1/deployments/:deployment_hash/plan', 'GET'),
        ('group_user', '/api/v1/deployments/:deployment_hash/events', 'GET')
)
INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
SELECT 'p', subject, route, action, '', '', ''
FROM route_policy
ON CONFLICT DO NOTHING;
