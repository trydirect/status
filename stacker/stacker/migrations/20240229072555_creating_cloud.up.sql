CREATE TABLE cloud (
        id serial4 NOT NULL,
        user_id VARCHAR(50) NOT NULL,
        provider VARCHAR(50) NOT NULL,
        cloud_token VARCHAR(255) ,
        cloud_key VARCHAR(255),
        cloud_secret VARCHAR(255),
        save_token BOOLEAN DEFAULT FALSE,
        created_at timestamptz NOT NULL,
        updated_at timestamptz NOT NULL,
        CONSTRAINT user_cloud_pkey PRIMARY KEY (id)
);

CREATE INDEX idx_deployment_user_cloud_user_id ON cloud(user_id);