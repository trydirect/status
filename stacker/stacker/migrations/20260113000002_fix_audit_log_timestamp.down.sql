-- Revert: Fix audit_log.created_at type from TIMESTAMP to TIMESTAMPTZ

ALTER TABLE audit_log ALTER COLUMN created_at TYPE TIMESTAMP;
