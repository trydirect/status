ALTER TABLE pipe_templates DROP COLUMN IF EXISTS dag_config;
ALTER TABLE pipe_templates DROP COLUMN IF EXISTS is_dag;

DROP TABLE IF EXISTS pipe_dag_step_executions;
DROP TABLE IF EXISTS pipe_dag_edges;
DROP TABLE IF EXISTS pipe_dag_steps;
