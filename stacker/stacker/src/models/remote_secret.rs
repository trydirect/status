use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct RemoteSecret {
    pub id: i32,
    pub user_id: String,
    pub project_id: Option<i32>,
    pub app_code: Option<String>,
    pub server_id: Option<i32>,
    pub scope: String,
    pub name: String,
    pub vault_path: String,
    pub updated_by: String,
    pub last_sync_status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
