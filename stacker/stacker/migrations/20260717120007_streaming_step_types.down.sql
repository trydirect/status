-- Revert to original step_type constraint
ALTER TABLE pipe_dag_steps DROP CONSTRAINT IF EXISTS pipe_dag_steps_step_type_check;

ALTER TABLE pipe_dag_steps ADD CONSTRAINT pipe_dag_steps_step_type_check
    CHECK (step_type IN (
        'source', 'transform', 'condition', 'target',
        'parallel_split', 'parallel_join'
    ));

-- Remove any rows with streaming types (if any)
DELETE FROM pipe_dag_steps WHERE step_type IN (
    'ws_source', 'ws_target', 'http_stream_source',
    'grpc_source', 'grpc_target'
);
