-- Add up migration script here
ALTER TABLE stack_template ADD COLUMN IF NOT EXISTS required_plan_name VARCHAR(50);