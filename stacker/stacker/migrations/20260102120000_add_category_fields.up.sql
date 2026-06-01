-- Add title and metadata fields to stack_category for User Service sync
ALTER TABLE stack_category 
ADD COLUMN IF NOT EXISTS title VARCHAR(255),
ADD COLUMN IF NOT EXISTS metadata JSONB DEFAULT '{}'::jsonb;

-- Create index on title for display queries
CREATE INDEX IF NOT EXISTS idx_stack_category_title ON stack_category(title);
