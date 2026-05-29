-- Add verifications JSONB column to stack_template.
-- This stores admin-configurable verification flags for marketplace templates.
-- Example: {"security_reviewed": true, "https_ready": false, "open_source": true}
ALTER TABLE stack_template
    ADD COLUMN IF NOT EXISTS verifications JSONB NOT NULL DEFAULT '{}'::jsonb;
