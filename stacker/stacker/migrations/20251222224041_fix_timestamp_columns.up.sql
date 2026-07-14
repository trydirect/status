-- Convert deployment.last_seen_at to timestamptz and agents timestamps to timestamptz
ALTER TABLE deployment
    ALTER COLUMN last_seen_at TYPE timestamptz;

ALTER TABLE agents
    ALTER COLUMN last_heartbeat TYPE timestamptz,
    ALTER COLUMN created_at TYPE timestamptz,
    ALTER COLUMN updated_at TYPE timestamptz;
