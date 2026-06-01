-- Casbin rules for DAG execution routes
INSERT INTO casbin_rule (ptype, v0, v1, v2, v3, v4, v5) VALUES
  -- DAG execute (admin)
  ('p', 'group_admin', '/api/v1/pipes/instances/*/dag/execute', 'POST', '', '', ''),
  -- DAG step executions list (admin)
  ('p', 'group_admin', '/api/v1/pipes/*/dag/executions/*/steps', 'GET', '', '', ''),
  -- DAG execute (user)
  ('p', 'group_user', '/api/v1/pipes/instances/*/dag/execute', 'POST', '', '', ''),
  -- DAG step executions list (user)
  ('p', 'group_user', '/api/v1/pipes/*/dag/executions/*/steps', 'GET', '', '', ''),
  -- DAG execute (client)
  ('p', 'group_client', '/api/v1/pipes/instances/*/dag/execute', 'POST', '', '', ''),
  -- DAG step executions list (client)
  ('p', 'group_client', '/api/v1/pipes/*/dag/executions/*/steps', 'GET', '', '', '')
ON CONFLICT DO NOTHING;
