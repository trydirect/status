DROP INDEX IF EXISTS idx_pipe_instances_local;

ALTER TABLE pipe_executions DROP COLUMN IF EXISTS is_local;
ALTER TABLE pipe_instances DROP COLUMN IF EXISTS is_local;

-- Restore NOT NULL (backfill NULLs first to avoid constraint violation)
UPDATE pipe_instances SET deployment_hash = '' WHERE deployment_hash IS NULL;
UPDATE pipe_executions SET deployment_hash = '' WHERE deployment_hash IS NULL;
ALTER TABLE pipe_instances ALTER COLUMN deployment_hash SET NOT NULL;
ALTER TABLE pipe_executions ALTER COLUMN deployment_hash SET NOT NULL;
