-- Add up migration script here
CREATE TABLE client (
  id serial4 NOT NULL,
  user_id varchar(50) NOT NULL,
  secret varchar(255),
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  CONSTRAINT client_pkey PRIMARY KEY (id),
	CONSTRAINT client_secret_unique UNIQUE (secret)
);
