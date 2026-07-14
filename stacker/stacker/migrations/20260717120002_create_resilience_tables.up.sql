-- Dead Letter Queue for failed pipe executions
CREATE TABLE IF NOT EXISTS dead_letter_queue (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    pipe_instance_id UUID NOT NULL REFERENCES pipe_instances(id) ON DELETE CASCADE,
    pipe_execution_id UUID REFERENCES pipe_executions(id) ON DELETE SET NULL,
    dag_step_id UUID REFERENCES pipe_dag_steps(id) ON DELETE SET NULL,
    payload JSONB,
    error TEXT NOT NULL DEFAULT '',
    retry_count INTEGER NOT NULL DEFAULT 0,
    max_retries INTEGER NOT NULL DEFAULT 3,
    next_retry_at TIMESTAMPTZ,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'retrying', 'exhausted', 'resolved', 'discarded')),
    created_by TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_dlq_instance_id ON dead_letter_queue(pipe_instance_id);
CREATE INDEX idx_dlq_status ON dead_letter_queue(status);

-- Circuit breaker state per pipe instance
CREATE TABLE IF NOT EXISTS circuit_breakers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    pipe_instance_id UUID NOT NULL UNIQUE REFERENCES pipe_instances(id) ON DELETE CASCADE,
    state TEXT NOT NULL DEFAULT 'closed'
        CHECK (state IN ('closed', 'open', 'half_open')),
    failure_count INTEGER NOT NULL DEFAULT 0,
    success_count INTEGER NOT NULL DEFAULT 0,
    failure_threshold INTEGER NOT NULL DEFAULT 5,
    recovery_timeout_seconds INTEGER NOT NULL DEFAULT 60,
    half_open_max_requests INTEGER NOT NULL DEFAULT 3,
    last_failure_at TIMESTAMPTZ,
    opened_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_cb_instance_id ON circuit_breakers(pipe_instance_id);
