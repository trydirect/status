-- Add down migration script here
ALTER table cloud ADD COLUMN project_id INT CONSTRAINT cloud_project_id REFERENCES project(id) ON UPDATE CASCADE ON DELETE CASCADE;
