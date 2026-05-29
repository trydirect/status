-- Add down migration script here
ALTER TABLE stack_template DROP COLUMN IF EXISTS required_plan_name;