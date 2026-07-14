-- Add deployment_id to project_app to scope apps per deployment
-- This fixes the bug where all deployments of the same project share the same apps/containers

ALTER TABLE project_app ADD COLUMN IF NOT EXISTS deployment_id INTEGER;

-- Add index for fast lookup by deployment
CREATE INDEX IF NOT EXISTS idx_project_app_deployment_id ON project_app(deployment_id);

-- Composite index for deployment + code lookups
CREATE INDEX IF NOT EXISTS idx_project_app_deployment_code ON project_app(deployment_id, code);

-- Backfill: for existing project_apps, try to set deployment_id from the latest deployment for their project
UPDATE project_app pa
SET deployment_id = d.id
FROM (
    SELECT DISTINCT ON (project_id) id, project_id
    FROM deployment
    WHERE deleted = false
    ORDER BY project_id, created_at DESC
) d
WHERE pa.project_id = d.project_id
  AND pa.deployment_id IS NULL;

-- Update the unique constraint to be per deployment instead of per project
-- First drop the old constraint
ALTER TABLE project_app DROP CONSTRAINT IF EXISTS unique_project_app_code;

-- Add new constraint: unique per (project_id, deployment_id, code)
-- Use a partial unique index to handle NULL deployment_id (legacy rows)
CREATE UNIQUE INDEX IF NOT EXISTS unique_project_app_deployment_code
    ON project_app (project_id, deployment_id, code)
    WHERE deployment_id IS NOT NULL;

-- Keep backward compatibility: unique per (project_id, code) when deployment_id IS NULL
CREATE UNIQUE INDEX IF NOT EXISTS unique_project_app_code_legacy
    ON project_app (project_id, code)
    WHERE deployment_id IS NULL;

COMMENT ON COLUMN project_app.deployment_id IS 'Deployment this app belongs to. NULL for legacy apps created before deployment scoping.';
