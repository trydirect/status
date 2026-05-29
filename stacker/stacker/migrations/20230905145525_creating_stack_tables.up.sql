CREATE TABLE project (
    id serial4 NOT NULL,
    stack_id uuid NOT NULL,
    user_id VARCHAR(50) NOT NULL,
    name TEXT NOT NULL,
    body JSON NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT project_pkey PRIMARY KEY (id)
);

CREATE INDEX idx_project_stack_id ON project(stack_id);
CREATE INDEX idx_project_user_id ON project(user_id);
CREATE INDEX idx_project_name ON project(name);
