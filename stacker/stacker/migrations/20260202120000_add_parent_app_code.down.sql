-- Rollback: Remove parent_app_code column from project_app

DROP INDEX IF EXISTS idx_project_app_parent;
ALTER TABLE project_app DROP COLUMN IF EXISTS parent_app_code;
