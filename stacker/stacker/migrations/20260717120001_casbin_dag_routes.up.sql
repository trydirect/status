-- Casbin rules for DAG step/edge/validate routes under /api/v1/pipes/{id}/dag/*
INSERT INTO casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
VALUES
  -- Steps CRUD
  ('p', 'group_admin', '/api/v1/pipes/*/dag/steps', 'GET', '', '', ''),
  ('p', 'group_admin', '/api/v1/pipes/*/dag/steps', 'POST', '', '', ''),
  ('p', 'group_admin', '/api/v1/pipes/*/dag/steps/*', 'GET', '', '', ''),
  ('p', 'group_admin', '/api/v1/pipes/*/dag/steps/*', 'PUT', '', '', ''),
  ('p', 'group_admin', '/api/v1/pipes/*/dag/steps/*', 'DELETE', '', '', ''),
  ('p', 'group_user', '/api/v1/pipes/*/dag/steps', 'GET', '', '', ''),
  ('p', 'group_user', '/api/v1/pipes/*/dag/steps', 'POST', '', '', ''),
  ('p', 'group_user', '/api/v1/pipes/*/dag/steps/*', 'GET', '', '', ''),
  ('p', 'group_user', '/api/v1/pipes/*/dag/steps/*', 'PUT', '', '', ''),
  ('p', 'group_user', '/api/v1/pipes/*/dag/steps/*', 'DELETE', '', '', ''),
  -- Edges CRUD
  ('p', 'group_admin', '/api/v1/pipes/*/dag/edges', 'GET', '', '', ''),
  ('p', 'group_admin', '/api/v1/pipes/*/dag/edges', 'POST', '', '', ''),
  ('p', 'group_admin', '/api/v1/pipes/*/dag/edges/*', 'DELETE', '', '', ''),
  ('p', 'group_user', '/api/v1/pipes/*/dag/edges', 'GET', '', '', ''),
  ('p', 'group_user', '/api/v1/pipes/*/dag/edges', 'POST', '', '', ''),
  ('p', 'group_user', '/api/v1/pipes/*/dag/edges/*', 'DELETE', '', '', ''),
  -- Validate
  ('p', 'group_admin', '/api/v1/pipes/*/dag/validate', 'POST', '', '', ''),
  ('p', 'group_user', '/api/v1/pipes/*/dag/validate', 'POST', '', '', '')
ON CONFLICT DO NOTHING;
