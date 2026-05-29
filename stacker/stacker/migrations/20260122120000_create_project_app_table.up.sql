-- Create project_app table for storing app configurations
-- Each project can have multiple apps with their own configuration

CREATE TABLE IF NOT EXISTS project_app (
    id SERIAL PRIMARY KEY,
    project_id INTEGER NOT NULL REFERENCES project(id) ON DELETE CASCADE,
    code VARCHAR(100) NOT NULL,
    name VARCHAR(255) NOT NULL,
    image VARCHAR(500) NOT NULL,
    environment JSONB DEFAULT '{}'::jsonb,
    ports JSONB DEFAULT '[]'::jsonb,
    volumes JSONB DEFAULT '[]'::jsonb,
    domain VARCHAR(255),
    ssl_enabled BOOLEAN DEFAULT FALSE,
    resources JSONB DEFAULT '{}'::jsonb,
    restart_policy VARCHAR(50) DEFAULT 'unless-stopped',
    command TEXT,
    entrypoint TEXT,
    networks JSONB DEFAULT '[]'::jsonb,
    depends_on JSONB DEFAULT '[]'::jsonb,
    healthcheck JSONB,
    labels JSONB DEFAULT '{}'::jsonb,
    enabled BOOLEAN DEFAULT TRUE,
    deploy_order INTEGER,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT unique_project_app_code UNIQUE (project_id, code)
);

-- Index for fast lookup by project
CREATE INDEX IF NOT EXISTS idx_project_app_project_id ON project_app(project_id);

-- Index for code lookup
CREATE INDEX IF NOT EXISTS idx_project_app_code ON project_app(code);

-- Index for deploy order
CREATE INDEX IF NOT EXISTS idx_project_app_deploy_order ON project_app(project_id, deploy_order);

-- Trigger to update updated_at on changes
CREATE OR REPLACE FUNCTION update_project_app_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS project_app_updated_at_trigger ON project_app;
CREATE TRIGGER project_app_updated_at_trigger
    BEFORE UPDATE ON project_app
    FOR EACH ROW
    EXECUTE FUNCTION update_project_app_updated_at();

-- Add comment for documentation
COMMENT ON TABLE project_app IS 'App configurations within projects. Each app is a container with its own env vars, ports, volumes, etc.';
COMMENT ON COLUMN project_app.code IS 'Unique identifier within project (e.g., nginx, postgres, redis)';
COMMENT ON COLUMN project_app.environment IS 'Environment variables as JSON object {"VAR": "value"}';
COMMENT ON COLUMN project_app.ports IS 'Port mappings as JSON array [{"host": 80, "container": 80, "protocol": "tcp"}]';
COMMENT ON COLUMN project_app.deploy_order IS 'Order in which apps are deployed (lower = first)';
