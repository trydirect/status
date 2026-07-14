-- Add up migration script here
CREATE TABLE deployment (
        id serial4 NOT NULL,
        project_id integer NOT NULL,
        body JSON NOT NULL,
        deleted BOOLEAN DEFAULT FALSE,
        status VARCHAR(32) NOT NULL,
        created_at timestamptz NOT NULL,
        updated_at timestamptz NOT NULL,
        CONSTRAINT fk_project FOREIGN KEY(project_id) REFERENCES project(id),
        CONSTRAINT deployment_pkey PRIMARY KEY (id)
);

CREATE INDEX idx_deployment_project_id ON deployment(project_id);
