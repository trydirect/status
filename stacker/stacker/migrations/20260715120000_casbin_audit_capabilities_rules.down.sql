-- Rollback Casbin rules for audit, capabilities, and server delete-preview endpoints
DELETE FROM public.casbin_rule
WHERE (v1 = '/api/v1/agent/audit' AND v2 IN ('POST', 'GET'))
   OR (v1 = '/api/v1/deployments/:deployment_hash/capabilities' AND v2 = 'GET')
   OR (v1 = '/server/:id/delete-preview' AND v2 = 'GET');
