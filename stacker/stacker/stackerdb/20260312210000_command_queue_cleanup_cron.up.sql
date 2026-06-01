-- Enable pg_cron extension (requires shared_preload_libraries)
CREATE EXTENSION IF NOT EXISTS pg_cron;

-- Cleanup function for stale command_queue entries
CREATE OR REPLACE FUNCTION stacker_command_queue_cleanup(
    queue_ttl INTERVAL DEFAULT INTERVAL '48 hours'
)
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
    -- Cancel stale queued commands (skip future scheduled commands)
    UPDATE commands
    SET status = 'cancelled', updated_at = NOW()
    WHERE status = 'queued'
      AND COALESCE(scheduled_for, created_at) < NOW() - queue_ttl;

    -- Remove queue entries for commands that are no longer queued
    DELETE FROM command_queue q
    USING commands c
    WHERE q.command_id = c.command_id
      AND c.status <> 'queued';

    -- Remove orphaned queue entries (commands deleted)
    DELETE FROM command_queue q
    WHERE NOT EXISTS (
        SELECT 1 FROM commands c WHERE c.command_id = q.command_id
    );

    -- Remove very old queue entries
    DELETE FROM command_queue
    WHERE created_at < NOW() - queue_ttl;
END;
$$;

-- Schedule hourly cleanup job (idempotent)
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM cron.job WHERE jobname = 'stacker_command_queue_cleanup'
    ) THEN
        PERFORM cron.schedule(
            'stacker_command_queue_cleanup',
            '0 * * * *',
            $$SELECT stacker_command_queue_cleanup();$$
        );
    END IF;
END;
$$;
