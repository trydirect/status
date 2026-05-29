-- Drop project_app table and related objects

DROP TRIGGER IF EXISTS project_app_updated_at_trigger ON project_app;
DROP FUNCTION IF EXISTS update_project_app_updated_at();
DROP INDEX IF EXISTS idx_project_app_deploy_order;
DROP INDEX IF EXISTS idx_project_app_code;
DROP INDEX IF EXISTS idx_project_app_project_id;
DROP TABLE IF EXISTS project_app;
