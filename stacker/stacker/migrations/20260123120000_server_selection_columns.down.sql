-- Remove server selection columns

ALTER TABLE server DROP COLUMN IF EXISTS name;
ALTER TABLE server DROP COLUMN IF EXISTS key_status;
ALTER TABLE server DROP COLUMN IF EXISTS connection_mode;
ALTER TABLE server DROP COLUMN IF EXISTS vault_key_path;
