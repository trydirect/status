-- DAG Steps: individual steps within a pipe template's DAG
CREATE TABLE pipe_dag_steps (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    pipe_template_id UUID NOT NULL REFERENCES pipe_templates(id) ON DELETE CASCADE,
    name VARCHAR(256) NOT NULL,
    step_type VARCHAR(32) NOT NULL CHECK (step_type IN (
        'source', 'transform', 'condition', 'target',
        'parallel_split', 'parallel_join'
    )),
    step_order INT NOT NULL DEFAULT 0,
    config JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_dag_steps_template ON pipe_dag_steps(pipe_template_id);
CREATE INDEX idx_dag_steps_order ON pipe_dag_steps(pipe_template_id, step_order);

-- DAG Edges: directed connections between steps
CREATE TABLE pipe_dag_edges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    pipe_template_id UUID NOT NULL REFERENCES pipe_templates(id) ON DELETE CASCADE,
    from_step_id UUID NOT NULL REFERENCES pipe_dag_steps(id) ON DELETE CASCADE,
    to_step_id UUID NOT NULL REFERENCES pipe_dag_steps(id) ON DELETE CASCADE,
    condition JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (from_step_id, to_step_id)
);

CREATE INDEX idx_dag_edges_template ON pipe_dag_edges(pipe_template_id);
CREATE INDEX idx_dag_edges_from ON pipe_dag_edges(from_step_id);
CREATE INDEX idx_dag_edges_to ON pipe_dag_edges(to_step_id);

-- DAG Step Executions: per-step execution tracking within a pipe execution
CREATE TABLE pipe_dag_step_executions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    pipe_execution_id UUID NOT NULL REFERENCES pipe_executions(id) ON DELETE CASCADE,
    step_id UUID NOT NULL REFERENCES pipe_dag_steps(id) ON DELETE CASCADE,
    status VARCHAR(32) NOT NULL DEFAULT 'pending' CHECK (status IN (
        'pending', 'running', 'completed', 'failed', 'skipped'
    )),
    input_data JSONB,
    output_data JSONB,
    error TEXT,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_dag_step_exec_pipe ON pipe_dag_step_executions(pipe_execution_id);
CREATE INDEX idx_dag_step_exec_step ON pipe_dag_step_executions(step_id);
CREATE INDEX idx_dag_step_exec_status ON pipe_dag_step_executions(status);

-- Extend pipe_templates with DAG flag
ALTER TABLE pipe_templates ADD COLUMN is_dag BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE pipe_templates ADD COLUMN dag_config JSONB;
