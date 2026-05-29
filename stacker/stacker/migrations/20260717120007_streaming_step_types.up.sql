-- Extend step_type check constraint to include streaming types
ALTER TABLE pipe_dag_steps DROP CONSTRAINT IF EXISTS pipe_dag_steps_step_type_check;

ALTER TABLE pipe_dag_steps ADD CONSTRAINT pipe_dag_steps_step_type_check
    CHECK (step_type IN (
        'source', 'transform', 'condition', 'target',
        'parallel_split', 'parallel_join',
        'ws_source', 'ws_target', 'http_stream_source',
        'grpc_source', 'grpc_target'
    ));
