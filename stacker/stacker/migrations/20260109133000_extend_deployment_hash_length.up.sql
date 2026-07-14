-- Increase deployment_hash column length to accommodate longer identifiers
ALTER TABLE commands DROP CONSTRAINT IF EXISTS commands_deployment_hash_fkey;

ALTER TABLE deployment
    ALTER COLUMN deployment_hash TYPE VARCHAR(128);

ALTER TABLE agents
    ALTER COLUMN deployment_hash TYPE VARCHAR(128);

ALTER TABLE audit_log
    ALTER COLUMN deployment_hash TYPE VARCHAR(128);

ALTER TABLE commands
    ALTER COLUMN deployment_hash TYPE VARCHAR(128);

ALTER TABLE command_queue
    ALTER COLUMN deployment_hash TYPE VARCHAR(128);

ALTER TABLE commands
    ADD CONSTRAINT commands_deployment_hash_fkey
        FOREIGN KEY (deployment_hash) REFERENCES deployment(deployment_hash) ON DELETE CASCADE;
