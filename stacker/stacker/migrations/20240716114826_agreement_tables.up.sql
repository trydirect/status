-- Add up migration script here

CREATE TABLE agreement (
       id serial4 NOT NULL,
       name VARCHAR(255) NOT NULL,
       text TEXT NOT NULL,
       created_at timestamptz NOT NULL,
       updated_at timestamptz NOT NULL,
       CONSTRAINT agreement_pkey PRIMARY KEY (id)
);

CREATE INDEX idx_agreement_name ON agreement(name);

CREATE TABLE user_agreement (
       id serial4 NOT NULL,
       agrt_id integer NOT NULL,
       user_id VARCHAR(50) NOT NULL,
       created_at timestamptz NOT NULL,
       updated_at timestamptz NOT NULL,
       CONSTRAINT user_agreement_pkey PRIMARY KEY (id),
       CONSTRAINT fk_agreement FOREIGN KEY(agrt_id) REFERENCES agreement(id)
);

CREATE INDEX idx_user_agreement_user_id ON user_agreement(user_id);