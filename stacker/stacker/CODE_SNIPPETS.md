# Complete Code Snippets for Implementation

## 1. src/routes/auth/login.rs

```rust
use crate::db;
use crate::helpers::JsonResponse;
use crate::models::{self, User};
use actix_web::{post, web, HttpResponse, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub session_token: String,
    pub user: UserInfo,
    pub deployments: Vec<DeploymentInfo>,
}

#[derive(Debug, Serialize)]
pub struct UserInfo {
    pub id: String,
    pub email: String,
    pub first_name: String,
    pub last_name: String,
    pub role: String,
}

#[derive(Debug, Serialize)]
pub struct DeploymentInfo {
    pub id: i32,
    pub project_id: i32,
    pub deployment_hash: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
}

fn generate_session_token() -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut rng = rand::thread_rng();
    (0..86)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

fn verify_password(password: &str, hash: &str) -> Result<bool, String> {
    // Use bcrypt crate: password_hash = bcrypt::hash(password, 12)?
    bcrypt::verify(password, hash).map_err(|e| format!("Password verification failed: {}", e))
}

#[tracing::instrument(name = "User login", skip(req, pool, vault_client))]
#[post("/login")]
pub async fn login_handler(
    req: web::Json<LoginRequest>,
    pool: web::Data<PgPool>,
    vault_client: web::Data<crate::helpers::VaultClient>,
) -> Result<impl Responder> {
    // 1. Validate input
    if req.email.trim().is_empty() {
        return Err(JsonResponse::<LoginResponse>::build().bad_request("email is required"));
    }
    if req.password.trim().is_empty() {
        return Err(JsonResponse::<LoginResponse>::build().bad_request("password is required"));
    }

    // 2. Query user by email
    let user = db::user::fetch_by_email(pool.get_ref(), &req.email)
        .await
        .map_err(|err| JsonResponse::<LoginResponse>::build().internal_server_error(err))?;

    let user = match user {
        Some(u) => u,
        None => {
            tracing::warn!("Login attempt with non-existent email: {}", req.email);
            return Err(JsonResponse::<LoginResponse>::build().forbidden("Invalid credentials"));
        }
    };

    // 3. Verify password
    if !verify_password(&req.password, &user.password_hash)
        .map_err(|err| JsonResponse::<LoginResponse>::build().internal_server_error(err))?
    {
        tracing::warn!("Failed login attempt for: {}", req.email);
        return Err(JsonResponse::<LoginResponse>::build().forbidden("Invalid credentials"));
    }

    // 4. Generate session token
    let session_token = generate_session_token();

    // 5. Store session token in Vault asynchronously
    let vault = vault_client.clone();
    let user_id = user.id.clone();
    let token = session_token.clone();
    actix_web::rt::spawn(async move {
        for retry in 0..3 {
            if vault.store_session_token(&user_id, &token).await.is_ok() {
                tracing::info!("Session token stored in Vault for user {}", user_id);
                break;
            }
            tokio::time::sleep(tokio::time::Duration::from_secs(2_u64.pow(retry))).await;
        }
    });

    // 6. Fetch user deployments
    let deployments = db::deployment::fetch_by_user(pool.get_ref(), &user.id, 100)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|d| DeploymentInfo {
            id: d.id,
            project_id: d.project_id,
            deployment_hash: d.deployment_hash,
            status: d.status,
            created_at: d.created_at,
        })
        .collect();

    // 7. Log audit event
    let audit_log = models::AuditLog::new(
        None,
        None,
        "user.login".to_string(),
        Some("success".to_string()),
    )
    .with_details(serde_json::json!({
        "user_id": user.id,
        "email": user.email,
    }));

    let _ = db::agent::log_audit(pool.get_ref(), audit_log).await;

    // 8. Return response
    Ok(HttpResponse::Ok().json(JsonResponse::build()
        .set_item(LoginResponse {
            session_token,
            user: UserInfo {
                id: user.id,
                email: user.email,
                first_name: user.first_name,
                last_name: user.last_name,
                role: user.role,
            },
            deployments,
        })
        .to_json_response()))
}
```

---

## 2. src/routes/auth/mod.rs

```rust
pub mod login;

pub use login::*;
```

---

## 3. src/routes/agent/link.rs

```rust
use crate::db;
use crate::helpers::JsonResponse;
use crate::models;
use actix_web::{post, web, HttpResponse, Result};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct LinkAgentRequest {
    pub session_token: String,
    pub deployment_id: i32,
    pub fingerprint: String,
}

#[derive(Debug, Serialize)]
pub struct LinkAgentResponse {
    pub agent_id: String,
    pub deployment_id: i32,
    pub credentials: AgentCredentials,
}

#[derive(Debug, Serialize)]
pub struct AgentCredentials {
    pub token: String,
    pub deployment_hash: String,
    pub server_url: String,
}

fn generate_agent_token() -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut rng = rand::thread_rng();
    (0..86)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

#[tracing::instrument(name = "Link agent to deployment", skip(pool, vault_client, settings))]
#[post("/link")]
pub async fn link_handler(
    req: web::Json<LinkAgentRequest>,
    pool: web::Data<PgPool>,
    vault_client: web::Data<crate::helpers::VaultClient>,
    settings: web::Data<crate::configuration::Settings>,
) -> Result<impl Responder> {
    // 1. Validate input
    if req.session_token.trim().is_empty() {
        return Err(JsonResponse::<LinkAgentResponse>::build().bad_request("session_token is required"));
    }
    if req.fingerprint.trim().is_empty() {
        return Err(JsonResponse::<LinkAgentResponse>::build().bad_request("fingerprint is required"));
    }

    // 2. Fetch session user_id from Vault
    let user_id = vault_client
        .fetch_session_user_id(&req.session_token)
        .await
        .map_err(|_err| {
            tracing::warn!("Invalid or expired session token");
            JsonResponse::<LinkAgentResponse>::build().forbidden("Invalid or expired session")
        })?;

    // 3. Fetch deployment and verify user owns it
    let deployment = db::deployment::fetch(pool.get_ref(), req.deployment_id)
        .await
        .map_err(|err| JsonResponse::<LinkAgentResponse>::build().internal_server_error(err))?;

    let deployment = match deployment {
        Some(d) => d,
        None => {
            return Err(JsonResponse::<LinkAgentResponse>::build()
                .not_found("Deployment not found"));
        }
    };

    // Verify user owns this deployment
    if deployment.user_id.as_deref() != Some(&user_id) {
        tracing::warn!(
            "Unauthorized link attempt by user {} for deployment {}",
            user_id,
            req.deployment_id
        );
        return Err(JsonResponse::<LinkAgentResponse>::build()
            .forbidden("You do not own this deployment"));
    }

    // 4. Check if agent already linked
    let existing_agent = db::agent::fetch_by_deployment_hash(
        pool.get_ref(),
        &deployment.deployment_hash,
    )
    .await
    .map_err(|err| JsonResponse::<LinkAgentResponse>::build().internal_server_error(err))?;

    let (agent_id, agent_token) = if let Some(agent) = existing_agent {
        // Reuse existing agent
        let token = vault_client
            .fetch_agent_token(&deployment.deployment_hash)
            .await
            .map_err(|_| {
                JsonResponse::<LinkAgentResponse>::build()
                    .internal_server_error("Failed to fetch agent token")
            })?;

        (agent.id.to_string(), token)
    } else {
        // Create new agent
        let mut agent = models::Agent::new(deployment.deployment_hash.clone());
        agent.system_info = Some(serde_json::json!({
            "linked_at": chrono::Utc::now(),
            "fingerprint": req.fingerprint,
        }));

        let saved_agent = db::agent::insert(pool.get_ref(), agent)
            .await
            .map_err(|err| JsonResponse::<LinkAgentResponse>::build().internal_server_error(err))?;

        let token = generate_agent_token();

        // Store token in Vault asynchronously
        let vault = vault_client.clone();
        let hash = deployment.deployment_hash.clone();
        let token_copy = token.clone();
        actix_web::rt::spawn(async move {
            for retry in 0..3 {
                if vault.store_agent_token(&hash, &token_copy).await.is_ok() {
                    tracing::info!("Agent token stored in Vault for {}", hash);
                    break;
                }
                tokio::time::sleep(tokio::time::Duration::from_secs(2_u64.pow(retry))).await;
            }
        });

        (saved_agent.id.to_string(), token)
    };

    // 5. Log audit event
    let audit_log = models::AuditLog::new(
        None,
        Some(deployment.deployment_hash.clone()),
        "agent.linked".to_string(),
        Some("success".to_string()),
    )
    .with_details(serde_json::json!({
        "user_id": user_id,
        "deployment_id": req.deployment_id,
        "agent_id": agent_id,
        "fingerprint": req.fingerprint,
    }));

    let _ = db::agent::log_audit(pool.get_ref(), audit_log).await;

    // 6. Return credentials
    Ok(HttpResponse::Ok().json(JsonResponse::build()
        .set_item(LinkAgentResponse {
            agent_id,
            deployment_id: req.deployment_id,
            credentials: AgentCredentials {
                token: agent_token,
                deployment_hash: deployment.deployment_hash,
                server_url: settings.server.base_url.clone(),
            },
        })
        .to_json_response()))
}
```

---

## 4. src/routes/agent/mod.rs (Updated)

```rust
mod enqueue;
mod link;
mod register;
mod report;
mod snapshot;
mod wait;

pub use enqueue::*;
pub use link::*;
pub use register::*;
pub use report::*;
pub use snapshot::*;
pub use wait::*;
```

---

## 5. src/routes/mod.rs (Updated)

Add this line after existing module declarations:

```rust
pub(crate) mod auth;  // Add this
pub(crate) mod agent;
// ... rest of modules
```

---

## 6. src/db/user.rs

```rust
use crate::models::User;
use sqlx::PgPool;

pub async fn fetch_by_email(pool: &PgPool, email: &str) -> Result<Option<User>, String> {
    let query_span = tracing::info_span!("Fetching user by email");
    sqlx::query_as::<_, (String, String, String, String, String, String, bool)>(
        r#"
        SELECT id, email, password_hash, first_name, last_name, role, email_confirmed
        FROM users
        WHERE email = $1
        LIMIT 1
        "#,
    )
    .bind(email)
    .fetch_optional(pool)
    .await
    .map_err(|err| {
        tracing::error!("Failed to fetch user by email: {:?}", err);
        "Database error".to_string()
    })?
    .map(|(id, email, password_hash, first_name, last_name, role, email_confirmed)| User {
        id,
        email,
        first_name,
        last_name,
        role,
        email_confirmed,
        access_token: None,
    })
    .map(Some)
    .or_else(|| Ok(None))
    .map_err(|_| "Database error".to_string())
    .ok()
    .flatten()
}
```

Note: This requires the existing `User` model to have a `password_hash` field. Update `src/models/user.rs` if needed:

```rust
#[derive(Debug, Deserialize, Clone)]
pub struct User {
    pub id: String,
    pub first_name: String,
    pub last_name: String,
    pub email: String,
    pub role: String,
    pub email_confirmed: bool,
    #[serde(skip)]
    pub password_hash: String,  // ADD THIS
    #[serde(skip)]
    pub access_token: Option<String>,
}
```

---

## 7. src/startup.rs (Updated)

Add this in the `.service()` chain around line 191-210:

```rust
.service(
    web::scope("/api")
        .service(crate::routes::marketplace::categories::list_handler)
        // ... existing template services ...
        .service(
            web::scope("/v1/auth")
                .service(routes::auth::login_handler),
        )
        .service(
            web::scope("/v1/agent")
                .service(routes::agent::register_handler)
                .service(routes::agent::enqueue_handler)
                .service(routes::agent::wait_handler)
                .service(routes::agent::report_handler)
                .service(routes::agent::snapshot_handler)
                .service(routes::agent::link_handler),  // ADD THIS
        )
        // ... rest of services ...
)
```

---

## 8. VaultClient Extensions (src/helpers/vault.rs)

Add these methods to the `impl VaultClient` block:

```rust
/// Store session token in Vault at sessions/{user_id}/token
#[tracing::instrument(name = "Store session token in Vault", skip(self, token))]
pub async fn store_session_token(
    &self,
    user_id: &str,
    token: &str,
) -> Result<(), String> {
    let base = self.address.trim_end_matches('/');
    let prefix = self.api_prefix.trim_matches('/');
    let path = if prefix.is_empty() {
        format!("{}/sessions/{}/token", base, user_id)
    } else {
        format!("{}/{}/sessions/{}/token", base, prefix, user_id)
    };

    let payload = serde_json::json!({
        "data": {
            "token": token,
            "user_id": user_id,
            "created_at": chrono::Utc::now().to_rfc3339(),
        }
    });

    self.client
        .post(&path)
        .header("X-Vault-Token", &self.token)
        .json(&payload)
        .send()
        .await
        .map_err(|e| {
            tracing::error!("Failed to store session token in Vault: {:?}", e);
            format!("Vault store error: {}", e)
        })?
        .error_for_status()
        .map_err(|e| {
            tracing::error!("Vault returned error status: {:?}", e);
            format!("Vault error: {}", e)
        })?;

    tracing::info!("Stored session token in Vault for user: {}", user_id);
    Ok(())
}

/// Fetch session user_id from Vault by session token
#[tracing::instrument(name = "Fetch session user_id from Vault", skip(self))]
pub async fn fetch_session_user_id(&self, token: &str) -> Result<String, String> {
    let base = self.address.trim_end_matches('/');
    let prefix = self.api_prefix.trim_matches('/');
    
    // Try to find session by token (may require a special endpoint or lookup table in Vault)
    // For now, assume Vault stores sessions in a specific path
    // You might need to implement a custom Vault endpoint or use a lookup service
    
    // Alternative: Store sessions in DB with expiration instead of Vault
    // This is simpler and recommended for session management
    
    Err("Session lookup not yet implemented - use DB instead of Vault for sessions".to_string())
}
```

---

## 9. Database Migration SQL

Create a new migration file in `migrations/`:

```sql
-- Create users table
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    email_confirmed BOOLEAN DEFAULT false,
    created_at TIMESTAMPTZ DEFAULT NOW() AT TIME ZONE 'utc',
    updated_at TIMESTAMPTZ DEFAULT NOW() AT TIME ZONE 'utc'
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

-- Create sessions table (better for temporary tokens than Vault)
CREATE TABLE IF NOT EXISTS sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token TEXT UNIQUE NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW() AT TIME ZONE 'utc'
);

CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);
```

---

## 10. Recommended: Use Database for Sessions Instead of Vault

Update `src/routes/auth/login.rs`:

```rust
// Store in DB instead of Vault
let session = models::Session::new(
    user.id.clone(),
    session_token.clone(),
    chrono::Duration::hours(24),  // 24-hour expiration
);

db::session::insert(pool.get_ref(), session)
    .await
    .map_err(|err| JsonResponse::<LoginResponse>::build().internal_server_error(err))?;
```

And `src/routes/agent/link.rs`:

```rust
// Fetch from DB instead of Vault
let session = db::session::fetch_by_token(pool.get_ref(), &req.session_token)
    .await
    .map_err(|err| JsonResponse::<LinkAgentResponse>::build().internal_server_error(err))?;

let session = match session {
    Some(s) if s.is_valid() => s,
    _ => {
        return Err(JsonResponse::<LinkAgentResponse>::build()
            .forbidden("Invalid or expired session"));
    }
};

let user_id = session.user_id;
```

