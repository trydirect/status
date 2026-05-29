-- Revert deployment table changes
ALTER TABLE deployment DROP COLUMN IF EXISTS user_id;
ALTER TABLE deployment DROP COLUMN IF EXISTS last_seen_at;
ALTER TABLE deployment DROP COLUMN IF EXISTS deployment_hash;
ALTER TABLE deployment RENAME COLUMN metadata TO body;
