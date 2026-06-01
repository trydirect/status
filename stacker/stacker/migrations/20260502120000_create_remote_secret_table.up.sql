CREATE TABLE IF NOT EXISTS remote_secret (
    id SERIAL PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    project_id INTEGER REFERENCES project(id) ON DELETE CASCADE,
    app_code VARCHAR(100),
    server_id INTEGER REFERENCES server(id) ON DELETE CASCADE,
    scope VARCHAR(20) NOT NULL,
    name VARCHAR(255) NOT NULL,
    vault_path TEXT NOT NULL,
    updated_by VARCHAR(255) NOT NULL,
    last_sync_status VARCHAR(50) NOT NULL DEFAULT 'synced',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT remote_secret_scope_check CHECK (scope IN ('service', 'server')),
    CONSTRAINT remote_secret_target_check CHECK (
        (scope = 'service' AND project_id IS NOT NULL AND app_code IS NOT NULL AND server_id IS NULL)
        OR
        (scope = 'server' AND server_id IS NOT NULL AND project_id IS NULL AND app_code IS NULL)
    )
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_remote_secret_service_unique
    ON remote_secret (user_id, project_id, app_code, name)
    WHERE scope = 'service';

CREATE UNIQUE INDEX IF NOT EXISTS idx_remote_secret_server_unique
    ON remote_secret (user_id, server_id, name)
    WHERE scope = 'server';

CREATE INDEX IF NOT EXISTS idx_remote_secret_user_scope
    ON remote_secret (user_id, scope);

CREATE INDEX IF NOT EXISTS idx_remote_secret_project_app
    ON remote_secret (project_id, app_code)
    WHERE scope = 'service';

CREATE INDEX IF NOT EXISTS idx_remote_secret_server
    ON remote_secret (server_id)
    WHERE scope = 'server';

CREATE OR REPLACE FUNCTION update_remote_secret_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS remote_secret_updated_at_trigger ON remote_secret;
CREATE TRIGGER remote_secret_updated_at_trigger
    BEFORE UPDATE ON remote_secret
    FOR EACH ROW
    EXECUTE FUNCTION update_remote_secret_updated_at();
