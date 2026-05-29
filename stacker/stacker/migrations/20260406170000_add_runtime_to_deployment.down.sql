DROP INDEX IF EXISTS idx_deployment_runtime;
ALTER TABLE deployment DROP CONSTRAINT IF EXISTS chk_deployment_runtime;
ALTER TABLE deployment DROP COLUMN IF EXISTS runtime;
