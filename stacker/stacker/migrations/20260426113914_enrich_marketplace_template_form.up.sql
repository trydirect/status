-- Enrich marketplace template form with missing fields
-- Adds: public_ports (JSONB), vendor_url (TEXT), and updates category handling

ALTER TABLE stack_template
ADD COLUMN IF NOT EXISTS public_ports JSONB DEFAULT NULL CONSTRAINT chk_public_ports_is_array
  CHECK (public_ports IS NULL OR jsonb_typeof(public_ports) = 'array'),
ADD COLUMN IF NOT EXISTS vendor_url TEXT DEFAULT NULL;

-- Create index on vendor_url for lookups
CREATE INDEX IF NOT EXISTS idx_stack_template_vendor_url ON stack_template(vendor_url) WHERE vendor_url IS NOT NULL;

-- Create comment for documentation
COMMENT ON COLUMN stack_template.public_ports IS 'Array of port objects: [{"name": "web", "port": 8080}, ...]';
COMMENT ON COLUMN stack_template.vendor_url IS 'Single vendor URL (e.g., product page, documentation)';
