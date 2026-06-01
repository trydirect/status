-- Add down migration script here
DROP INDEX idx_server_cloud_id;
alter table server ADD column cloud_id integer NOT NULL;
