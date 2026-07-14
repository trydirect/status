# Quick Reference: Adding Two New Endpoints

## Summary of Stacker Patterns

### 1. ROUTE STRUCTURE
- Routes defined in `src/routes/` with subdirectories by domain
- Each route has `#[post]`, `#[get]` macros + `#[tracing::instrument]`
- Registered in `src/startup.rs` using `web::scope()` pattern
- **For your endpoints**: Create `src/routes/auth/login.rs` and extend `src/routes/agent/link.rs`

### 2. AUTHENTICATION/USER EXTRACTION
```rust
// User is auto-extracted from JWT/OAuth/Cookie/Agent tokens
#[post("/endpoint")]
pub async fn handler(
    user: web::ReqData<Arc<models::User>>,  // Middleware injects this
) -> Result<impl Responder> {
    let user_id = &user.id;  // User from auth headers
}
```

- Session tokens = 86-char random string (generated + stored in Vault)
- User stored in `Arc<models::User>` with id, email, role, first_name, last_name
- Verify ownership: `if d.user_id.as_deref() != Some(&user_id) { forbidden }`

### 3. DATABASE QUERIES
```rust
// Pattern: All DB functions return Result<T, String>
let deployment = db::deployment::fetch(pool.get_ref(), id)
    .await
    .map_err(|err| JsonResponse::build().internal_server_error(err))?;

// Fetch user deployments
let deployments = db::deployment::fetch_by_user(pool.get_ref(), &user_id, 100)
    .await
    .unwrap_or_default();
```

**Available queries:**
- `fetch_by_user(pool, user_id, limit)` → Vec<Deployment>
- `fetch_by_user_and_project(pool, user_id, project_id, limit)` → Vec<Deployment>
- `fetch_by_deployment_hash(pool, hash)` → Option<Deployment>
- Agent: `fetch_by_deployment_hash(pool, hash)` → Option<Agent>

### 4. RESPONSE HANDLING
```rust
// Success
Ok(JsonResponse::build()
    .set_item(response_data)
    .ok("Message"))

// Error
Err(JsonResponse::build().bad_request("msg"))
Err(JsonResponse::build().not_found("msg"))
Err(JsonResponse::build().forbidden("msg"))
Err(JsonResponse::build().internal_server_error("msg"))
```

**Response wrapper format:**
```json
{
  "message": "Operation successful",
  "item": { /* response data */ }
}
```

### 5. VAULT CLIENT (Token Storage)
```rust
// Store token (86-char random)
vault_client.store_agent_token(&deployment_hash, &token).await?;

// With async retry (3x on exponential backoff)
let vault = vault_client.clone();
let hash = deployment_hash.clone();
let token_copy = token.clone();
actix_web::rt::spawn(async move {
    for retry in 0..3 {
        if vault.store_agent_token(&hash, &token_copy).await.is_ok() {
            break;
        }
        tokio::time::sleep(tokio::time::Duration::from_secs(2_u64.pow(retry))).await;
    }
});
```

### 6. AUDIT LOGGING
```rust
let audit_log = models::AuditLog::new(
    Some(agent_id),
    Some(deployment_hash.clone()),
    "agent.registered".to_string(),
    Some("success".to_string()),
)
.with_details(serde_json::json!({
    "key": value,
}))
.with_ip(req.peer_addr().map(|a| a.ip().to_string()).unwrap_or_default());

db::agent::log_audit(pool.get_ref(), audit_log).await;
```

### 7. KEY MIDDLEWARE STACK
```
CORS → Tracing → Authorization (Casbin) → Authentication (JWT/OAuth/Cookie/Agent/HMAC) → Compression
```

Auth tries these in order: Agent → JWT → OAuth → Cookie → HMAC → Anonymous

### 8. DEPENDENCY INJECTION (Available in Handlers)
```rust
web::Data<Pool<Postgres>>              // API database
web::Data<AgentPgPool>                 // Agent database
web::Data<Settings>                    // App config
web::Data<VaultClient>                 // Vault for tokens
web::Data<Arc<dyn UserServiceConnector>> // External user service
Arc<models::User>                       // Authenticated user
```

---

## Implementation Checklist for POST /api/v1/auth/login

- [ ] Create `src/routes/auth/mod.rs` with `pub mod login` + `pub use login::*`
- [ ] Create `src/routes/auth/login.rs` with handler
- [ ] Define `LoginRequest` struct (email, password)
- [ ] Define `LoginResponse` struct (session_token, user info, deployments list)
- [ ] Add to `src/routes/mod.rs`: `pub(crate) mod auth`
- [ ] Add to `src/startup.rs`: register scope `/api/v1/auth`
- [ ] DB: Need user table with columns: id, email, password_hash, first_name, last_name, role
- [ ] DB: Add function `db::user::fetch_by_email(pool, email)` → Result<Option<User>, String>
- [ ] Generate 86-char session token (use generate_agent_token pattern)
- [ ] Store session token in Vault at `sessions/{user_id}/token`
- [ ] Query: `db::deployment::fetch_by_user(pool, user_id, 100)`
- [ ] Validate email + password
- [ ] Log audit: "user.login" action
- [ ] Return with user info + deployments list
- [ ] Error: 400 for missing fields, 404 for non-existent user, 403 for wrong password, 500 for DB

---

## Implementation Checklist for POST /api/v1/agents/link

- [ ] Add to `src/routes/agent/link.rs` handler
- [ ] Add to `src/routes/agent/mod.rs`: `pub use link::*`
- [ ] Add to `src/startup.rs`: register handler in `/api/v1/agents` scope
- [ ] Define `LinkAgentRequest` (session_token, deployment_id, fingerprint)
- [ ] Define `LinkAgentResponse` (agent_id, deployment_id, credentials)
- [ ] Fetch session user_id from Vault using session_token
- [ ] Fetch deployment by deployment_id
- [ ] Verify user owns deployment: `if d.user_id.as_deref() != Some(&user_id) { forbidden }`
- [ ] Check if agent exists by deployment_hash
- [ ] If exists: fetch token from Vault, return existing agent
- [ ] If new: create agent, generate token, store in Vault (async with retry)
- [ ] Log audit: "agent.linked" action
- [ ] Return agent_id + credentials (token, deployment_hash, server_url)
- [ ] Error: 400 for missing fields, 403 for session invalid/expired, 404 for deployment not found, 403 for ownership

---

## Database Models Needed

### User (if not exists)
```sql
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    email_confirmed BOOLEAN DEFAULT false,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- DB function to add
pub async fn fetch_by_email(pool: &PgPool, email: &str) -> Result<Option<User>, String>
```

### Session Vault Keys (in Vault)
```
POST   /v1/sessions/{user_id}/token     → Store: {"data": {"token": "...", "user_id": "..."}}
GET    /v1/sessions/{user_id}/token     → Retrieve token + validate not expired
DELETE /v1/sessions/{user_id}/token     → Logout
```

---

## File Changes Summary

### New Files
- `src/routes/auth/mod.rs` - Auth route module
- `src/routes/auth/login.rs` - Login handler
- `src/db/user.rs` - User DB queries

### Modified Files
- `src/routes/mod.rs` - Add `pub(crate) mod auth`
- `src/routes/agent/mod.rs` - Add `pub use link::*` and link.rs
- `src/startup.rs` - Register `/api/v1/auth` and `/api/v1/agents` scopes
- `src/models/mod.rs` - Add user model if not exists

---

## Error Response Format

All errors use this structure:
```json
{
  "message": "descriptive error message"
}
```

HTTP Status Codes:
- 200 OK - Success
- 201 Created - New resource
- 204 No Content - Success with no data
- 400 Bad Request - Invalid input
- 403 Forbidden - No permission / Invalid credentials
- 404 Not Found - Resource doesn't exist
- 409 Conflict - Resource already exists
- 500 Internal Server Error - Database/Vault error

---

## Testing Your Endpoints

### Login
```bash
POST /api/v1/auth/login
{
  "email": "user@example.com",
  "password": "password123"
}

Response (200):
{
  "message": "Login successful",
  "item": {
    "session_token": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
    "user": {
      "id": "user-uuid",
      "email": "user@example.com",
      "first_name": "John",
      "last_name": "Doe",
      "role": "user"
    },
    "deployments": [
      {
        "id": 1,
        "project_id": 100,
        "deployment_hash": "abc123...",
        "status": "active",
        "created_at": "2024-01-15T10:30:00Z"
      }
    ]
  }
}
```

### Link Agent
```bash
POST /api/v1/agents/link
{
  "session_token": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
  "deployment_id": 1,
  "fingerprint": "agent-fingerprint-hash"
}

Response (200):
{
  "message": "Agent linked successfully",
  "item": {
    "agent_id": "agent-uuid",
    "deployment_id": 1,
    "credentials": {
      "token": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
      "deployment_hash": "abc123...",
      "server_url": "https://stacker.example.com"
    }
  }
}
```

