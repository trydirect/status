DELETE FROM casbin_rule WHERE v1 LIKE '/api/v1/pipes/%/dlq%'
   OR v1 LIKE '/api/v1/pipes/dlq/%'
   OR v1 LIKE '/api/v1/pipes/%/circuit-breaker%';
