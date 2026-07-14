-- Unschedule cleanup job if pg_cron is available
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_cron') THEN
        PERFORM cron.unschedule('stacker_command_queue_cleanup');
    END IF;
END;
$$;

DROP FUNCTION IF EXISTS stacker_command_queue_cleanup(INTERVAL);
