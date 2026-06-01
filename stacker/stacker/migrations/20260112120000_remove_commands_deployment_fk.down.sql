-- Restore FK constraint on commands.deployment_hash back to deployment(deployment_hash)
ALTER TABLE commands ADD CONSTRAINT commands_deployment_hash_fkey
    FOREIGN KEY (deployment_hash) REFERENCES deployment(deployment_hash) ON DELETE CASCADE;
