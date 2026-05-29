-- Revert deployment_id addition from project_app

DROP INDEX IF EXISTS unique_project_app_deployment_code;
DROP INDEX IF EXISTS unique_project_app_code_legacy;
DROP INDEX IF EXISTS idx_project_app_deployment_code;
DROP INDEX IF EXISTS idx_project_app_deployment_id;

ALTER TABLE project_app DROP COLUMN IF EXISTS deployment_id;

-- Restore original unique constraint
ALTER TABLE project_app ADD CONSTRAINT unique_project_app_code UNIQUE (project_id, code);
