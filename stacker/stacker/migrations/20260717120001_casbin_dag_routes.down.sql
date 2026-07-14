DELETE FROM casbin_rule
WHERE ptype = 'p'
  AND v1 LIKE '/api/v1/pipes/*/dag/%';
