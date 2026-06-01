-- Convert key timestamp columns to timestamptz so Rust can use DateTime<Utc>

-- deployment
ALTER TABLE deployment
    ALTER COLUMN created_at TYPE timestamptz,
    ALTER COLUMN updated_at TYPE timestamptz,
    ALTER COLUMN last_seen_at TYPE timestamptz;

-- agents
ALTER TABLE agents
    ALTER COLUMN created_at TYPE timestamptz,
    ALTER COLUMN updated_at TYPE timestamptz,
    ALTER COLUMN last_heartbeat TYPE timestamptz;

-- commands
ALTER TABLE commands
    ALTER COLUMN created_at TYPE timestamptz,
    ALTER COLUMN updated_at TYPE timestamptz,
    ALTER COLUMN scheduled_for TYPE timestamptz,
    ALTER COLUMN sent_at TYPE timestamptz,
    ALTER COLUMN started_at TYPE timestamptz,
    ALTER COLUMN completed_at TYPE timestamptz;

-- command_queue
ALTER TABLE command_queue
    ALTER COLUMN created_at TYPE timestamptz;
