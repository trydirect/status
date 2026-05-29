-- Casbin rules for DLQ and circuit breaker routes
INSERT INTO casbin_rule (ptype, v0, v1, v2, v3, v4, v5) VALUES
  -- DLQ routes (admin)
  ('p', 'group_admin', '/api/v1/pipes/instances/*/dlq', 'GET', '', '', ''),
  ('p', 'group_admin', '/api/v1/pipes/instances/*/dlq', 'POST', '', '', ''),
  ('p', 'group_admin', '/api/v1/pipes/dlq/*', 'GET', '', '', ''),
  ('p', 'group_admin', '/api/v1/pipes/dlq/*/retry', 'POST', '', '', ''),
  ('p', 'group_admin', '/api/v1/pipes/dlq/*', 'DELETE', '', '', ''),
  -- Circuit breaker routes (admin)
  ('p', 'group_admin', '/api/v1/pipes/instances/*/circuit-breaker', 'GET', '', '', ''),
  ('p', 'group_admin', '/api/v1/pipes/instances/*/circuit-breaker', 'PUT', '', '', ''),
  ('p', 'group_admin', '/api/v1/pipes/instances/*/circuit-breaker/reset', 'POST', '', '', ''),
  ('p', 'group_admin', '/api/v1/pipes/instances/*/circuit-breaker/failure', 'POST', '', '', ''),
  ('p', 'group_admin', '/api/v1/pipes/instances/*/circuit-breaker/success', 'POST', '', '', ''),
  -- DLQ routes (user)
  ('p', 'group_user', '/api/v1/pipes/instances/*/dlq', 'GET', '', '', ''),
  ('p', 'group_user', '/api/v1/pipes/instances/*/dlq', 'POST', '', '', ''),
  ('p', 'group_user', '/api/v1/pipes/dlq/*', 'GET', '', '', ''),
  ('p', 'group_user', '/api/v1/pipes/dlq/*/retry', 'POST', '', '', ''),
  ('p', 'group_user', '/api/v1/pipes/dlq/*', 'DELETE', '', '', ''),
  -- Circuit breaker routes (user)
  ('p', 'group_user', '/api/v1/pipes/instances/*/circuit-breaker', 'GET', '', '', ''),
  ('p', 'group_user', '/api/v1/pipes/instances/*/circuit-breaker', 'PUT', '', '', ''),
  ('p', 'group_user', '/api/v1/pipes/instances/*/circuit-breaker/reset', 'POST', '', '', ''),
  ('p', 'group_user', '/api/v1/pipes/instances/*/circuit-breaker/failure', 'POST', '', '', ''),
  ('p', 'group_user', '/api/v1/pipes/instances/*/circuit-breaker/success', 'POST', '', '', '')
ON CONFLICT DO NOTHING;
