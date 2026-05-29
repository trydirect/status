ALTER TABLE pipe_instances
    DROP COLUMN IF EXISTS target_adapter,
    DROP COLUMN IF EXISTS source_adapter;
