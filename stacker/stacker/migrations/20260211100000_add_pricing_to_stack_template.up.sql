-- Add pricing columns to stack_template
-- Creator sets price during template submission; webhook sends it to User Service products table
ALTER TABLE stack_template ADD COLUMN IF NOT EXISTS price DOUBLE PRECISION DEFAULT 0;
ALTER TABLE stack_template ADD COLUMN IF NOT EXISTS billing_cycle VARCHAR(50) DEFAULT 'free';
ALTER TABLE stack_template ADD COLUMN IF NOT EXISTS currency VARCHAR(3) DEFAULT 'USD';
