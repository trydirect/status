-- Rollback: Remove marketplace template enrichment columns

DROP INDEX IF EXISTS idx_stack_template_vendor_url;

ALTER TABLE stack_template
DROP COLUMN IF EXISTS public_ports,
DROP COLUMN IF EXISTS vendor_url;
