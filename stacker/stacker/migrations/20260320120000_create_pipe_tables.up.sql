-- Reusable pipe definitions (no deployment_hash — shared across deployments)
CREATE TABLE pipe_templates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(256) NOT NULL UNIQUE,
    description TEXT,
    source_app_type VARCHAR(128) NOT NULL,
    source_endpoint JSONB NOT NULL,
    target_app_type VARCHAR(128) NOT NULL,
    target_endpoint JSONB NOT NULL,
    target_external_url VARCHAR(512),
    field_mapping JSONB NOT NULL,
    config JSONB DEFAULT '{}',
    is_public BOOLEAN DEFAULT false,
    created_by VARCHAR(128) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_pipe_templates_source ON pipe_templates(source_app_type);
CREATE INDEX idx_pipe_templates_target ON pipe_templates(target_app_type);
CREATE INDEX idx_pipe_templates_public ON pipe_templates(is_public) WHERE is_public = true;

-- Deployment-specific pipe activations
CREATE TABLE pipe_instances (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    template_id UUID REFERENCES pipe_templates(id) ON DELETE SET NULL,
    deployment_hash VARCHAR(128) NOT NULL,
    source_container VARCHAR(128) NOT NULL,
    target_container VARCHAR(128),
    target_url VARCHAR(512),
    field_mapping_override JSONB,
    config_override JSONB,
    status VARCHAR(32) NOT NULL DEFAULT 'draft',
    last_triggered_at TIMESTAMPTZ,
    trigger_count BIGINT NOT NULL DEFAULT 0,
    error_count BIGINT NOT NULL DEFAULT 0,
    created_by VARCHAR(128) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_pipe_instances_deployment ON pipe_instances(deployment_hash);
CREATE INDEX idx_pipe_instances_template ON pipe_instances(template_id);
CREATE INDEX idx_pipe_instances_status ON pipe_instances(status);
