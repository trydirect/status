-- Restore foreign key constraint (only if deployment table has matching records)
-- Note: This will fail if orphaned agents exist. Clean up orphans before rollback.
ALTER TABLE agents 
ADD CONSTRAINT agents_deployment_hash_fkey 
FOREIGN KEY (deployment_hash) 
REFERENCES deployment(deployment_hash) 
ON DELETE CASCADE;
