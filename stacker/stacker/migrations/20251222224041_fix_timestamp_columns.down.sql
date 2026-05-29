-- Revert timestamp conversions
ALTER TABLE deployment
    ALTER COLUMN last_seen_at TYPE timestamp;

ALTER TABLE agents
    ALTER COLUMN last_heartbeat TYPE timestamp,
    ALTER COLUMN created_at TYPE timestamp,
    ALTER COLUMN updated_at TYPE timestamp;
