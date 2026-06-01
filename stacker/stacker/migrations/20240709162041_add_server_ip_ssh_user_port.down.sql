 -- Add up migration script here

 ALTER table server DROP COLUMN srv_ip;
 ALTER table server DROP COLUMN ssh_user;
 ALTER table server DROP COLUMN ssh_port;
