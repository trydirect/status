ALTER TABLE pipe_instances
    ADD COLUMN source_adapter JSONB,
    ADD COLUMN target_adapter JSONB;
