-- Add parent_app_code column to project_app for hierarchical service linking
-- This allows multi-service compose stacks (e.g., Komodo with core, ferretdb, periphery)
-- to link child services back to the parent stack

ALTER TABLE project_app ADD COLUMN IF NOT EXISTS parent_app_code VARCHAR(255) DEFAULT NULL;

-- Create index for efficient queries on parent apps
CREATE INDEX IF NOT EXISTS idx_project_app_parent ON project_app(project_id, parent_app_code) WHERE parent_app_code IS NOT NULL;

-- Add comment for documentation
COMMENT ON COLUMN project_app.parent_app_code IS 'Parent app code for child services in multi-service stacks (e.g., "komodo" for komodo-core, komodo-ferretdb)';
