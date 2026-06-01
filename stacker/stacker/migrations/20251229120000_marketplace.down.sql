-- Rollback TryDirect Marketplace Schema

DROP TRIGGER IF EXISTS auto_create_product_on_approval ON stack_template;
DROP FUNCTION IF EXISTS create_product_for_approved_template();

DROP TRIGGER IF EXISTS update_stack_template_updated_at ON stack_template;

-- Drop indexes
DROP INDEX IF EXISTS idx_project_source_template;
DROP INDEX IF EXISTS idx_review_decision;
DROP INDEX IF EXISTS idx_review_template;
DROP INDEX IF EXISTS idx_template_version_latest;
DROP INDEX IF EXISTS idx_template_version_template;
DROP INDEX IF EXISTS idx_stack_template_product;
DROP INDEX IF EXISTS idx_stack_template_category;
DROP INDEX IF EXISTS idx_stack_template_slug;
DROP INDEX IF EXISTS idx_stack_template_status;
DROP INDEX IF EXISTS idx_stack_template_creator;

-- Remove columns from existing tables
ALTER TABLE IF EXISTS project DROP COLUMN IF EXISTS template_version;
ALTER TABLE IF EXISTS project DROP COLUMN IF EXISTS source_template_id;

-- Drop marketplace tables (CASCADE to handle dependencies)
DROP TABLE IF EXISTS stack_template_review CASCADE;
DROP TABLE IF EXISTS stack_template_version CASCADE;
DROP TABLE IF EXISTS stack_template CASCADE;
DROP TABLE IF EXISTS stack_category CASCADE;

-- Drop functions last
DROP FUNCTION IF EXISTS update_updated_at_column() CASCADE;
