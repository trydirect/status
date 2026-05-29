DELETE FROM casbin_rule WHERE v1 IN (
  '/api/v1/pipes/instances/*/dag/execute',
  '/api/v1/pipes/*/dag/executions/*/steps'
);
