-- Add config_files column to project_app for template configuration files
-- This stores config file templates (like telegraf.conf, nginx.conf) that need rendering

ALTER TABLE project_app ADD COLUMN IF NOT EXISTS config_files JSONB DEFAULT '[]'::jsonb;

-- Example structure:
-- [
--   {
--     "name": "telegraf.conf",
--     "path": "/etc/telegraf/telegraf.conf",
--     "content": "# Telegraf config\n[agent]\ninterval = \"{{ interval }}\"\n...",
--     "template_type": "jinja2",
--     "variables": {
--       "interval": "10s",
--       "flush_interval": "10s",
--       "influx_url": "http://influxdb:8086"
--     }
--   }
-- ]

COMMENT ON COLUMN project_app.config_files IS 'Configuration file templates as JSON array. Each entry has name, path, content (template), template_type (jinja2/tera), and variables object';

-- Also add a template_source field to reference external templates from stacks repo
ALTER TABLE project_app ADD COLUMN IF NOT EXISTS template_source VARCHAR(500);

COMMENT ON COLUMN project_app.template_source IS 'Reference to external template source (e.g., tfa/roles/telegraf/templates/telegraf.conf.j2)';
