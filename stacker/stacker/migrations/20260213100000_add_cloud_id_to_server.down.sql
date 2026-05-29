-- Remove cloud_id from server table
DROP INDEX IF EXISTS idx_server_cloud_id;
ALTER TABLE server DROP COLUMN IF EXISTS cloud_id;
