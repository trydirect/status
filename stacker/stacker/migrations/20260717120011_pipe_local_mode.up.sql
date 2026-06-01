-- Make deployment_hash nullable for local pipe mode
ALTER TABLE pipe_instances ALTER COLUMN deployment_hash DROP NOT NULL;
ALTER TABLE pipe_executions ALTER COLUMN deployment_hash DROP NOT NULL;

-- Track whether a pipe was created in local mode
ALTER TABLE pipe_instances ADD COLUMN is_local BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE pipe_executions ADD COLUMN is_local BOOLEAN NOT NULL DEFAULT FALSE;

-- Index for listing user's local pipes efficiently
CREATE INDEX idx_pipe_instances_local ON pipe_instances(created_by, is_local) WHERE is_local = true;
