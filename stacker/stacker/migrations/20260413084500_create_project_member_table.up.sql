CREATE TABLE IF NOT EXISTS project_member (
    project_id INTEGER NOT NULL REFERENCES project(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL,
    role VARCHAR(32) NOT NULL,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (project_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_project_member_user_id ON project_member(user_id);
