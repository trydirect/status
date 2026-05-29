-- Revert CDC step type constraint
ALTER TABLE pipe_dag_steps DROP CONSTRAINT IF EXISTS pipe_dag_steps_step_type_check;

ALTER TABLE pipe_dag_steps ADD CONSTRAINT pipe_dag_steps_step_type_check
    CHECK (step_type IN (
        'source', 'transform', 'condition', 'target',
        'parallel_split', 'parallel_join',
        'ws_source', 'ws_target', 'http_stream_source',
        'grpc_source', 'grpc_target'
    ));

-- Remove Casbin policies for CDC routes
DELETE FROM casbin_rule WHERE v1 LIKE '/api/v1/cdc/%';

-- Drop CDC tables
DROP TABLE IF EXISTS cdc_events;
DROP TABLE IF EXISTS cdc_triggers;
DROP TABLE IF EXISTS cdc_sources;
