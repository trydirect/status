ALTER TABLE stack_template_version
ADD COLUMN IF NOT EXISTS assets JSONB NOT NULL DEFAULT '[]'::jsonb
    CONSTRAINT chk_stack_template_version_assets_is_array
    CHECK (jsonb_typeof(assets) = 'array');

COMMENT ON COLUMN stack_template_version.assets IS
    'Finalized marketplace asset metadata for this template version.';
