-- Add up migration script here

ALTER table server ADD COLUMN srv_ip VARCHAR(50) DEFAULT NULL;
ALTER table server ADD COLUMN ssh_user VARCHAR(50) DEFAULT NULL;
ALTER table server ADD COLUMN ssh_port INT DEFAULT NULL;
