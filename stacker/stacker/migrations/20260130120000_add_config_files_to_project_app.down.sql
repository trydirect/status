-- Rollback: remove config_files column from project_app

ALTER TABLE project_app
DROP COLUMN IF EXISTS config_files;
