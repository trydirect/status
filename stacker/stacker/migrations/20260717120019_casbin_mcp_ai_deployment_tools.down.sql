WITH tool_policy(subject, tool) AS (
    VALUES
        ('group_user', 'get_deployment_state'),
        ('group_user', 'get_deployment_plan'),
        ('group_user', 'get_deployment_events'),
        ('group_user', 'apply_deployment_plan'),
        ('group_user', 'explain_env'),
        ('group_user', 'explain_topology')
)
DELETE FROM public.casbin_rule cr
USING tool_policy tp
WHERE cr.ptype = 'p'
  AND cr.v0 = tp.subject
  AND cr.v1 = '/mcp/tools/' || tp.tool
  AND cr.v2 = 'CALL'
  AND cr.v3 = ''
  AND cr.v4 = ''
  AND cr.v5 = '';

WITH route_policy(subject, route, action) AS (
    VALUES
        ('group_user', '/api/v1/deployments/:deployment_hash/state', 'GET'),
        ('group_user', '/api/v1/deployments/:deployment_hash/plan', 'GET'),
        ('group_user', '/api/v1/deployments/:deployment_hash/events', 'GET')
)
DELETE FROM public.casbin_rule cr
USING route_policy rp
WHERE cr.ptype = 'p'
  AND cr.v0 = rp.subject
  AND cr.v1 = rp.route
  AND cr.v2 = rp.action
  AND cr.v3 = ''
  AND cr.v4 = ''
  AND cr.v5 = '';
