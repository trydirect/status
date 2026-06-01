-- Add deployment_hash, last_seen_at, and rename body to metadata in deployment table
ALTER TABLE deployment 
ADD COLUMN deployment_hash VARCHAR(64) UNIQUE,
ADD COLUMN last_seen_at TIMESTAMP,
ADD COLUMN user_id VARCHAR(255);

-- Rename body to metadata
ALTER TABLE deployment RENAME COLUMN body TO metadata;

-- Generate deployment_hash for existing deployments (simple hash based on id)
UPDATE deployment 
SET deployment_hash = md5(CONCAT('deployment_', id::text))
WHERE deployment_hash IS NULL;

-- Make deployment_hash NOT NULL after populating
ALTER TABLE deployment ALTER COLUMN deployment_hash SET NOT NULL;

CREATE INDEX idx_deployment_hash ON deployment(deployment_hash);
CREATE INDEX idx_deployment_user_id ON deployment(user_id);
