CREATE TABLE pipe_executions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    pipe_instance_id UUID NOT NULL REFERENCES pipe_instances(id) ON DELETE CASCADE,
    deployment_hash VARCHAR(128) NOT NULL,
    trigger_type VARCHAR(32) NOT NULL DEFAULT 'manual',
    status VARCHAR(32) NOT NULL DEFAULT 'running',
    source_data JSONB,
    mapped_data JSONB,
    target_response JSONB,
    error TEXT,
    duration_ms BIGINT,
    replay_of UUID REFERENCES pipe_executions(id) ON DELETE SET NULL,
    created_by VARCHAR(128) NOT NULL,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);

CREATE INDEX idx_pipe_executions_instance ON pipe_executions(pipe_instance_id);
CREATE INDEX idx_pipe_executions_deployment ON pipe_executions(deployment_hash);
CREATE INDEX idx_pipe_executions_started ON pipe_executions(started_at DESC);
