-- Remove Casbin rules for command endpoints for client role

DELETE FROM public.casbin_rule
WHERE ptype = 'p'
  AND v0 = 'client'
  AND v1 IN (
    '/api/v1/commands',
    '/api/v1/commands/:deployment_hash',
    '/api/v1/commands/:deployment_hash/:command_id',
    '/api/v1/commands/:deployment_hash/:command_id/cancel'
  )
  AND v2 IN ('GET', 'POST');
