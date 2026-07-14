ALTER TABLE stack_template_version
DROP CONSTRAINT IF EXISTS chk_stack_template_version_assets_is_array,
DROP COLUMN IF EXISTS assets;
