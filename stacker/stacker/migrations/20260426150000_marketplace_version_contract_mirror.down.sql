ALTER TABLE stack_template_version
DROP COLUMN IF EXISTS update_mode_capabilities,
DROP COLUMN IF EXISTS post_deploy_hooks,
DROP COLUMN IF EXISTS seed_jobs,
DROP COLUMN IF EXISTS config_files;
