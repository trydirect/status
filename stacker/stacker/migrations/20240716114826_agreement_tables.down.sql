-- Add down migration script here

-- Add up migration script here

DROP INDEX idx_agreement_name;
CREATE INDEX idx_user_agreement_user_id;
DROP TABLE agreement;
DROP TABLE user_agreement;