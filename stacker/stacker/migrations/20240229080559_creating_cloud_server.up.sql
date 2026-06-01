-- Add up migration script here

CREATE TABLE server (
       id serial4 NOT NULL,
       user_id VARCHAR(50) NOT NULL,
       cloud_id integer NOT NULL,
       project_id integer NOT NULL,
       region VARCHAR(50) NOT NULL,
       zone VARCHAR(50),
       server VARCHAR(255) NOT NULL,
       os VARCHAR(100) NOT NULL,
       disk_type VARCHAR(100),
       created_at timestamptz NOT NULL,
       updated_at timestamptz NOT NULL,
       CONSTRAINT user_server_pkey PRIMARY KEY (id),
       CONSTRAINT fk_server FOREIGN KEY(cloud_id) REFERENCES cloud(id),
       CONSTRAINT fk_server_project FOREIGN KEY(project_id) REFERENCES project(id)  ON UPDATE CASCADE ON DELETE CASCADE
);

CREATE INDEX idx_server_user_id ON server(user_id);
CREATE INDEX idx_server_cloud_id ON server(cloud_id);
CREATE INDEX idx_server_project_id ON server(project_id);
