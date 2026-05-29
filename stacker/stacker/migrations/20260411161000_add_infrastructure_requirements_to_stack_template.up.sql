ALTER TABLE stack_template
ADD COLUMN IF NOT EXISTS infrastructure_requirements JSONB NOT NULL DEFAULT '{}'::jsonb;
