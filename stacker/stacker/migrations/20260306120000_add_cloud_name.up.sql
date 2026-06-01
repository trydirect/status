-- Add a human-friendly name to cloud credentials so users can reference them
-- by name (e.g. `stacker deploy --key my-hetzner`) instead of by provider.
ALTER TABLE cloud ADD COLUMN name VARCHAR(100);

-- Backfill existing rows: default name = "{provider}-{id}" (e.g. "htz-4")
UPDATE cloud SET name = provider || '-' || id WHERE name IS NULL;

-- Make name NOT NULL after backfill
ALTER TABLE cloud ALTER COLUMN name SET NOT NULL;

-- Unique per user: a user can't have two cloud keys with the same name
CREATE UNIQUE INDEX idx_cloud_user_name ON cloud (user_id, name);
