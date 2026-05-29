-- Add cdc_source step type to pipe_dag_steps constraint
ALTER TABLE pipe_dag_steps DROP CONSTRAINT IF EXISTS pipe_dag_steps_step_type_check;

ALTER TABLE pipe_dag_steps ADD CONSTRAINT pipe_dag_steps_step_type_check
    CHECK (step_type IN (
        'source', 'transform', 'condition', 'target',
        'parallel_split', 'parallel_join',
        'ws_source', 'ws_target', 'http_stream_source',
        'grpc_source', 'grpc_target',
        'cdc_source'
    ));

-- CDC source configuration table
CREATE TABLE IF NOT EXISTS cdc_sources (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    deployment_hash VARCHAR(255) NOT NULL,
    connection_url TEXT NOT NULL,
    replication_slot VARCHAR(255) NOT NULL,
    publication_name VARCHAR(255) NOT NULL,
    monitored_tables JSONB NOT NULL DEFAULT '[]'::jsonb,
    capture_operations JSONB NOT NULL DEFAULT '["INSERT","UPDATE","DELETE"]'::jsonb,
    status VARCHAR(50) NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'paused', 'error', 'deleted')),
    last_lsn VARCHAR(64),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cdc_sources_deployment ON cdc_sources(deployment_hash);
CREATE INDEX IF NOT EXISTS idx_cdc_sources_status ON cdc_sources(status);

-- CDC trigger bindings (which CDC source triggers which pipe)
CREATE TABLE IF NOT EXISTS cdc_triggers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cdc_source_id UUID NOT NULL REFERENCES cdc_sources(id) ON DELETE CASCADE,
    pipe_template_id UUID NOT NULL REFERENCES pipe_templates(id) ON DELETE CASCADE,
    table_filter VARCHAR(255),
    operation_filter JSONB,
    condition JSONB,
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cdc_triggers_source ON cdc_triggers(cdc_source_id);
CREATE INDEX IF NOT EXISTS idx_cdc_triggers_pipe ON cdc_triggers(pipe_template_id);

-- CDC event log for audit/replay
CREATE TABLE IF NOT EXISTS cdc_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_id UUID NOT NULL REFERENCES cdc_sources(id) ON DELETE CASCADE,
    schema_name VARCHAR(255) NOT NULL DEFAULT 'public',
    table_name VARCHAR(255) NOT NULL,
    operation VARCHAR(10) NOT NULL CHECK (operation IN ('INSERT', 'UPDATE', 'DELETE')),
    before_data JSONB,
    after_data JSONB,
    xid BIGINT NOT NULL,
    lsn VARCHAR(64) NOT NULL,
    captured_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cdc_events_source ON cdc_events(source_id);
CREATE INDEX IF NOT EXISTS idx_cdc_events_table ON cdc_events(table_name);
CREATE INDEX IF NOT EXISTS idx_cdc_events_captured ON cdc_events(captured_at);

-- Casbin policies for CDC routes
INSERT INTO casbin_rule (ptype, v0, v1, v2, v3, v4, v5) VALUES
    ('p', 'group_user', '/api/v1/cdc/sources', 'GET', '', '', ''),
    ('p', 'group_user', '/api/v1/cdc/sources', 'POST', '', '', ''),
    ('p', 'group_user', '/api/v1/cdc/sources/*', 'GET', '', '', ''),
    ('p', 'group_user', '/api/v1/cdc/sources/*', 'PUT', '', '', ''),
    ('p', 'group_user', '/api/v1/cdc/sources/*', 'DELETE', '', '', ''),
    ('p', 'group_user', '/api/v1/cdc/triggers', 'GET', '', '', ''),
    ('p', 'group_user', '/api/v1/cdc/triggers', 'POST', '', '', ''),
    ('p', 'group_user', '/api/v1/cdc/triggers/*', 'DELETE', '', '', ''),
    ('p', 'group_user', '/api/v1/cdc/events', 'GET', '', '', '')
ON CONFLICT DO NOTHING;
