ALTER TABLE stack_template_version
ADD COLUMN IF NOT EXISTS config_files JSONB NOT NULL DEFAULT '[]'::jsonb,
ADD COLUMN IF NOT EXISTS seed_jobs JSONB NOT NULL DEFAULT '[]'::jsonb,
ADD COLUMN IF NOT EXISTS post_deploy_hooks JSONB NOT NULL DEFAULT '[]'::jsonb,
ADD COLUMN IF NOT EXISTS update_mode_capabilities JSONB;
