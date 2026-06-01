-- Add config versioning columns to project_app table
-- This enables tracking of configuration changes and Vault sync status

ALTER TABLE project_app ADD COLUMN IF NOT EXISTS config_version INTEGER NOT NULL DEFAULT 1;
ALTER TABLE project_app ADD COLUMN IF NOT EXISTS vault_synced_at TIMESTAMPTZ;
ALTER TABLE project_app ADD COLUMN IF NOT EXISTS vault_sync_version INTEGER;
ALTER TABLE project_app ADD COLUMN IF NOT EXISTS config_hash VARCHAR(64);

-- Add index for quick config version lookups
CREATE INDEX IF NOT EXISTS idx_project_app_config_version ON project_app(project_id, config_version);

-- Comment on new columns
COMMENT ON COLUMN project_app.config_version IS 'Incrementing version number for config changes';
COMMENT ON COLUMN project_app.vault_synced_at IS 'Last time config was synced to Vault';
COMMENT ON COLUMN project_app.vault_sync_version IS 'Config version that was last synced to Vault';
COMMENT ON COLUMN project_app.config_hash IS 'SHA256 hash of rendered config for drift detection';
