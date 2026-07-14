-- Add up migration script here
ALTER table project ADD COLUMN cloud_id INT CONSTRAINT project_cloud_id REFERENCES cloud(id) ON UPDATE CASCADE ON DELETE CASCADE;

