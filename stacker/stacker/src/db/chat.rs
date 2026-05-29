use crate::models::ChatConversation;
use serde_json::Value;
use sqlx::PgPool;

pub async fn fetch(
    pool: &PgPool,
    user_id: &str,
    project_id: Option<i32>,
) -> Result<Option<ChatConversation>, sqlx::Error> {
    match project_id {
        Some(pid) => {
            sqlx::query_as!(
                ChatConversation,
                r#"SELECT id, user_id, project_id, messages, created_at, updated_at
                   FROM chat_conversations
                   WHERE user_id = $1 AND project_id = $2"#,
                user_id,
                pid
            )
            .fetch_optional(pool)
            .await
        }
        None => {
            sqlx::query_as!(
                ChatConversation,
                r#"SELECT id, user_id, project_id, messages, created_at, updated_at
                   FROM chat_conversations
                   WHERE user_id = $1 AND project_id IS NULL"#,
                user_id
            )
            .fetch_optional(pool)
            .await
        }
    }
}

pub async fn upsert(
    pool: &PgPool,
    user_id: &str,
    project_id: Option<i32>,
    messages: Value,
) -> Result<ChatConversation, sqlx::Error> {
    match project_id {
        Some(pid) => {
            sqlx::query_as!(
                ChatConversation,
                r#"INSERT INTO chat_conversations (user_id, project_id, messages)
                   VALUES ($1, $2, $3)
                   ON CONFLICT (user_id, project_id) WHERE project_id IS NOT NULL
                   DO UPDATE SET messages = EXCLUDED.messages, updated_at = NOW()
                   RETURNING id, user_id, project_id, messages, created_at, updated_at"#,
                user_id,
                pid,
                messages
            )
            .fetch_one(pool)
            .await
        }
        None => {
            sqlx::query_as!(
                ChatConversation,
                r#"INSERT INTO chat_conversations (user_id, project_id, messages)
                   VALUES ($1, NULL, $2)
                   ON CONFLICT (user_id) WHERE project_id IS NULL
                   DO UPDATE SET messages = EXCLUDED.messages, updated_at = NOW()
                   RETURNING id, user_id, project_id, messages, created_at, updated_at"#,
                user_id,
                messages
            )
            .fetch_one(pool)
            .await
        }
    }
}

pub async fn delete(
    pool: &PgPool,
    user_id: &str,
    project_id: Option<i32>,
) -> Result<u64, sqlx::Error> {
    let result = match project_id {
        Some(pid) => {
            sqlx::query!(
                r#"DELETE FROM chat_conversations WHERE user_id = $1 AND project_id = $2"#,
                user_id,
                pid
            )
            .execute(pool)
            .await?
        }
        None => {
            sqlx::query!(
                r#"DELETE FROM chat_conversations WHERE user_id = $1 AND project_id IS NULL"#,
                user_id
            )
            .execute(pool)
            .await?
        }
    };
    Ok(result.rows_affected())
}
