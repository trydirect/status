-- Chat conversations: persists AI chat history per user per project
CREATE TABLE chat_conversations (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     VARCHAR(255) NOT NULL,
    project_id  INTEGER,                                  -- NULL = canvas / onboarding mode
    messages    JSONB       NOT NULL DEFAULT '[]'::jsonb,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- One row per (user, project) pair; partial indexes allow NULL project_id
CREATE UNIQUE INDEX idx_chat_conv_user_project
    ON chat_conversations(user_id, project_id)
    WHERE project_id IS NOT NULL;

CREATE UNIQUE INDEX idx_chat_conv_user_no_project
    ON chat_conversations(user_id)
    WHERE project_id IS NULL;
