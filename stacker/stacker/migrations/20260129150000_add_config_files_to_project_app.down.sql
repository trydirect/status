-- Rollback config_files additions

ALTER TABLE project_app DROP COLUMN IF EXISTS config_files;
ALTER TABLE project_app DROP COLUMN IF EXISTS template_source;
