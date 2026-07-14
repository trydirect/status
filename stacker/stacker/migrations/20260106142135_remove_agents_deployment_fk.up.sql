-- Remove foreign key constraint from agents table to allow agents without deployments in Stacker
-- Deployments may exist in User Service "installations" table instead
ALTER TABLE agents DROP CONSTRAINT IF EXISTS agents_deployment_hash_fkey;

-- Keep the deployment_hash column indexed for queries
-- Index already exists: idx_agents_deployment_hash
