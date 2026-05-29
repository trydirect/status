-- Revert deployment_hash column length to the previous limit
ALTER TABLE commands DROP CONSTRAINT IF EXISTS commands_deployment_hash_fkey;

ALTER TABLE deployment
    ALTER COLUMN deployment_hash TYPE VARCHAR(64);

ALTER TABLE agents
    ALTER COLUMN deployment_hash TYPE VARCHAR(64);

ALTER TABLE audit_log
    ALTER COLUMN deployment_hash TYPE VARCHAR(64);

ALTER TABLE commands
    ALTER COLUMN deployment_hash TYPE VARCHAR(64);

ALTER TABLE command_queue
    ALTER COLUMN deployment_hash TYPE VARCHAR(64);

ALTER TABLE commands
    ADD CONSTRAINT commands_deployment_hash_fkey
        FOREIGN KEY (deployment_hash) REFERENCES deployment(deployment_hash) ON DELETE CASCADE;
