-- Enable pg_cron extension if available (requires pg_cron in shared_preload_libraries).
-- Wrapped in DO block so migration doesn't fail on servers without pg_cron.
DO $$
BEGIN
    CREATE EXTENSION IF NOT EXISTS pg_cron;
EXCEPTION WHEN OTHERS THEN
    RAISE WARNING 'pg_cron extension not available, skipping: %', SQLERRM;
END;
$$;

-- Cleanup function for stale command_queue entries (always created, pg_cron optional)
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

-- Schedule hourly cleanup job if pg_cron is available (idempotent).
-- Uses $cron$ quoting to avoid collision with the outer DO $$ block.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_cron') THEN
        IF NOT EXISTS (
            SELECT 1 FROM cron.job WHERE jobname = 'stacker_command_queue_cleanup'
        ) THEN
            PERFORM cron.schedule(
                'stacker_command_queue_cleanup',
                '0 * * * *',
                $cron$SELECT stacker_command_queue_cleanup();$cron$
            );
        END IF;
    END IF;
END;
$$;
