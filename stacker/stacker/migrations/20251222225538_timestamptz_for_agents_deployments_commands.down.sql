-- Revert timestamptz changes back to timestamp (non-tz)

-- command_queue
ALTER TABLE command_queue
    ALTER COLUMN created_at TYPE timestamp;

-- commands
ALTER TABLE commands
    ALTER COLUMN completed_at TYPE timestamp,
    ALTER COLUMN started_at TYPE timestamp,
    ALTER COLUMN sent_at TYPE timestamp,
    ALTER COLUMN scheduled_for TYPE timestamp,
    ALTER COLUMN updated_at TYPE timestamp,
    ALTER COLUMN created_at TYPE timestamp;

-- agents
ALTER TABLE agents
    ALTER COLUMN last_heartbeat TYPE timestamp,
    ALTER COLUMN updated_at TYPE timestamp,
    ALTER COLUMN created_at TYPE timestamp;

-- deployment
ALTER TABLE deployment
    ALTER COLUMN last_seen_at TYPE timestamp,
    ALTER COLUMN updated_at TYPE timestamp,
    ALTER COLUMN created_at TYPE timestamp;
