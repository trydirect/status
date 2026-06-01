-- Add config_files column to project_app for storing configuration file templates
-- This supports apps like Telegraf that require config files beyond env vars

-- Add config_files column
ALTER TABLE project_app
ADD COLUMN IF NOT EXISTS config_files JSONB DEFAULT '[]'::jsonb;

-- Add comment for documentation
COMMENT ON COLUMN project_app.config_files IS 'Configuration file templates as JSON array [{"filename": "telegraf.conf", "path": "/etc/telegraf/telegraf.conf", "content": "template content...", "is_template": true}]';

-- Example structure:
-- [
--   {
--     "filename": "telegraf.conf",
--     "path": "/etc/telegraf/telegraf.conf",
--     "content": "[agent]\n  interval = \"{{ interval | default(\"10s\") }}\"\n...",
--     "is_template": true,
--     "description": "Telegraf agent configuration"
--   },
--   {
--     "filename": "custom.conf",
--     "path": "/etc/myapp/custom.conf",
--     "content": "static content...",
--     "is_template": false
--   }
-- ]
