-- Remove config versioning columns from project_app table

DROP INDEX IF EXISTS idx_project_app_config_version;

ALTER TABLE project_app DROP COLUMN IF EXISTS config_hash;
ALTER TABLE project_app DROP COLUMN IF EXISTS vault_sync_version;
ALTER TABLE project_app DROP COLUMN IF EXISTS vault_synced_at;
ALTER TABLE project_app DROP COLUMN IF EXISTS config_version;
