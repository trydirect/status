-- Remove title and metadata fields from stack_category
ALTER TABLE stack_category 
DROP COLUMN IF EXISTS metadata,
DROP COLUMN IF EXISTS title;

-- Drop the index
DROP INDEX IF EXISTS idx_stack_category_title;
