# Stacker Server Patterns & Architecture Guide

## 1. ROUTE STRUCTURE & REGISTRATION

### Route Organization (src/routes/mod.rs)
Routes are organized by domain and registered as scoped web services in `src/startup.rs`:

```
Routes structure:
├── /health_check → routes::health_check, routes::health_metrics
├── /client → client handlers
├── /test → test deployment
├── /rating → rating handlers (anonymous & user & admin)
├── /project → project CRUD, app config, container discovery
├── /dockerhub → search/list repositories & tags
├── /admin → admin-only endpoints
├── /api
│   ├── /v1/agent → register, enqueue, wait, report, snapshot
│   ├── /v1/deployments → capabilities, list, status
│   ├── /v1/commands → create, list, get, cancel
│   └── /admin → templates, marketplace management
├── /cloud → cloud provider CRUD
├── /server → server CRUD & SSH key management
├── /agreement → agreement handlers
├── /chat → chat history
└── /mcp → WebSocket for MCP tool calls
```

### Route Registration Pattern (src/startup.rs)
```rust
.service(
    web::scope("/api/v1/agent")
        .service(routes::agent::register_handler)
        .service(routes::agent::enqueue_handler)
        .service(routes::agent::wait_handler)
        .service(routes::agent::report_handler)
        .service(routes::agent::snapshot_handler),
)
```

**Key Points:**
- Routes use `#[post]`, `#[get]`, etc. macros from actix-web
- Each route is declared with `#[tracing::instrument]` for observability
- Routes are wrapped with middleware (auth, CORS, compression)
- Middleware stack is applied in order: CORS → Tracing → Authorization → Authentication → Compress

---

## 2. AGENT REGISTRATION PATTERN (src/routes/agent/register.rs)

### Request Structure
```rust
#[derive(Debug, Deserialize)]
pub struct RegisterAgentRequest {
    pub deployment_hash: String,           // Unique identifier for deployment
    pub public_key: Option<String>,        // For secure communication
    pub capabilities: Vec<String>,         // What agent can do (docker, logs, etc.)
    pub system_info: serde_json::Value,    // System details
    pub agent_version: String,             // Agent version
}
```

### Response Structure
```rust
#[derive(Debug, Serialize, Default)]
pub struct RegisterAgentResponse {
    pub agent_id: String,
    pub agent_token: String,              // 86-char random token
    pub dashboard_version: String,
    pub supported_api_versions: Vec<String>,
}

// Wrapped in data container
#[derive(Debug, Serialize)]
pub struct RegisterAgentResponseWrapper {
    pub data: RegisterAgentResponseData,
}

#[derive(Debug, Serialize)]
pub struct RegisterAgentResponseData {
    pub item: RegisterAgentResponse,
}
```

### Registration Flow
1. **Idempotency Check**: Fetch existing agent by `deployment_hash`
2. **If Agent Exists**:
   - Update metadata (capabilities, version, system_info)
   - Fetch existing token from Vault
   - Return existing agent + token (idempotent)
3. **If New Agent**:
   - Generate 86-char random token
   - Save agent to DB (agents table)
   - **Async Vault Storage** (best-effort with 3 retries on exponential backoff)
   - Log audit event
   - Return new agent + token

### Key Implementation Details
```rust
// Token generation (86-char alphanumeric + dash/underscore)
fn generate_agent_token() -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut rng = rand::thread_rng();
    (0..86).map(|_| {
        let idx = rng.gen_range(0..CHARSET.len());
        CHARSET[idx] as char
    }).collect()
}

// Async token storage with retry
actix_web::rt::spawn(async move {
    for retry in 0..3 {
        if vault.store_agent_token(&hash, &token).await.is_ok() {
            tracing::info!("Token stored in Vault for {}", hash);
            break;
        }
        tokio::time::sleep(tokio::time::Duration::from_secs(2_u64.pow(retry))).await;
    }
});
```

### Audit Logging
```rust
let audit_log = models::AuditLog::new(
    Some(saved_agent.id),
    Some(payload.deployment_hash.clone()),
    "agent.registered".to_string(),
    Some("success".to_string()),
)
.with_details(serde_json::json!({
    "version": payload.agent_version,
    "capabilities": payload.capabilities,
}))
.with_ip(req.peer_addr().map(|addr| addr.ip().to_string()).unwrap_or_default());

db::agent::log_audit(agent_pool.as_ref(), audit_log).await;
```

---

## 3. AUTHENTICATION & MIDDLEWARE

### Middleware Stack (src/startup.rs)
```rust
App::new()
    .wrap(Cors::default()...)           // 1. CORS
    .wrap(TracingLogger::default())     // 2. Request tracing
    .wrap(authorization.clone())        // 3. Authorization (Casbin)
    .wrap(authentication::Manager::new()) // 4. Authentication (token/JWT/OAuth/HMAC/Cookie/Agent)
    .wrap(Compress::default())          // 5. Response compression
```

### Authentication Methods (src/middleware/authentication/method/)

The middleware tries auth methods in order:
1. **Agent Auth** (f_agent.rs) - Agent token from header
2. **JWT** (f_jwt.rs) - Bearer token from Authorization header
3. **OAuth** (f_oauth.rs) - OAuth callback tokens
4. **Cookie** (f_cookie.rs) - Session cookies
5. **HMAC** (f_hmac.rs) - HMAC signature verification
6. **Anonymous** (f_anonym.rs) - Public access

### JWT Authentication Pattern
```rust
pub async fn try_jwt(req: &mut ServiceRequest) -> Result<bool, String> {
    let authorization = get_header::<String>(req, "authorization")?;
    if authorization.is_none() {
        return Ok(false);
    }

    let token = extract_bearer_token(&authorization.unwrap())?;
    let claims = parse_jwt_claims(token)?;
    
    // Validate expiration
    validate_jwt_expiration(&claims)?;
    
    // Create User from JWT claims
    let user = user_from_jwt_claims(&claims);
    
    // Insert into request extensions for handler access
    if req.extensions_mut().insert(Arc::new(user)).is_some() {
        return Err("user already logged".to_string());
    }

    Ok(true)
}
```

### User Extraction in Handlers
```rust
#[get("/{id}")]
pub async fn status_handler(
    path: web::Path<i32>,
    user: web::ReqData<Arc<models::User>>,  // Auto-extracted from extensions
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder> {
    let deployment_id = path.into_inner();
    let user_id = &user.id;  // Use authenticated user
    
    // Verify ownership
    if d.user_id.as_deref() != Some(&user_id) {
        return Err(JsonResponse::<DeploymentStatusResponse>::build()
            .not_found("Deployment not found"));
    }
    
    Ok(JsonResponse::build()
        .set_item(resp)
        .ok("Success"))
}
```

### User Model
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
    pub access_token: Option<String>,  // For proxying to other services
}

impl User {
    pub fn with_token(mut self, token: String) -> Self {
        self.access_token = Some(token);
        self
    }
}
```

### Authorization (Casbin - src/middleware/authorization.rs)
- **Model**: Loaded from `access_control.conf`
- **Policies**: Stored in database (casbin_rules table)
- **Pattern Matching**: Supports `key_match2` for role-based patterns
- **Reload Strategy**: Reloads on policy change (configurable interval, default 10s)

```rust
pub async fn try_new(db_connection_address: String) -> Result<CasbinService, Error> {
    let m = DefaultModel::from_file("access_control.conf").await?;
    let a = SqlxAdapter::new(db_connection_address.clone(), 8).await?;
    
    let casbin_service = CasbinService::new(m, a).await?;
    casbin_service.write().await
        .get_role_manager()
        .write()
        .matching_fn(Some(key_match2), None);
    
    Ok(casbin_service)
}
```

---

## 4. DATABASE LAYER (src/db/)

### Connection Pools
```rust
// In startup.rs
pub async fn run(
    listener: TcpListener,
    api_pool: Pool<Postgres>,      // Main API database
    agent_pool: AgentPgPool,       // Agent database (separate)
    settings: Settings,
) -> Result<Server, std::io::Error> {
    let api_pool = web::Data::new(api_pool);
    let agent_pool = web::Data::new(agent_pool);
    
    // Inject into routes
    .app_data(api_pool.clone())
    .app_data(agent_pool.clone())
}
```

### Query Pattern with Error Handling
```rust
pub async fn fetch_by_deployment_hash(
    pool: &PgPool,
    deployment_hash: &str,
) -> Result<Option<models::Deployment>, String> {
    let query_span = tracing::info_span!("Fetching agent by deployment_hash");
    sqlx::query_as::<_, models::Agent>(
        r#"
        SELECT id, deployment_hash, capabilities, version, system_info, 
               last_heartbeat, status, created_at, updated_at
        FROM agents 
        WHERE deployment_hash = $1
        "#,
    )
    .bind(deployment_hash)
    .fetch_optional(pool)
    .instrument(query_span)
    .await
    .map_err(|err| {
        tracing::error!("Failed to fetch agent by deployment_hash: {:?}", err);
        "Database error".to_string()
    })
}
```

### Key Query Functions

**Deployment Queries:**
```rust
pub async fn fetch(pool: &PgPool, id: i32) -> Result<Option<models::Deployment>, String>
pub async fn fetch_by_deployment_hash(pool: &PgPool, hash: &str) -> Result<Option<...>, String>
pub async fn fetch_by_project_id(pool: &PgPool, project_id: i32) -> Result<Option<...>, String>
pub async fn fetch_by_user(pool: &PgPool, user_id: &str, limit: i64) -> Result<Vec<...>, String>
pub async fn insert(pool: &PgPool, deployment: models::Deployment) -> Result<models::Deployment, String>
pub async fn update(pool: &PgPool, deployment: models::Deployment) -> Result<models::Deployment, String>
```

**Agent Queries:**
```rust
pub async fn insert(pool: &PgPool, agent: models::Agent) -> Result<models::Agent, String>
pub async fn fetch_by_id(pool: &PgPool, agent_id: Uuid) -> Result<Option<models::Agent>, String>
pub async fn fetch_by_deployment_hash(pool: &PgPool, hash: &str) -> Result<Option<models::Agent>, String>
pub async fn update_heartbeat(pool: &PgPool, agent_id: Uuid, status: &str) -> Result<(), String>
pub async fn update(pool: &PgPool, agent: models::Agent) -> Result<models::Agent, String>
pub async fn log_audit(pool: &PgPool, audit_log: models::AuditLog) -> Result<(), String>
```

### Error Handling Pattern
- Return `Result<T, String>` from db functions
- Map SQL errors to user-friendly strings
- Log errors with `tracing::error!` for debugging
- Handle `RowNotFound` separately for optional queries

---

## 5. RESPONSE/ERROR HANDLING (src/helpers/json.rs)

### JsonResponse Builder Pattern
```rust
#[derive(Serialize)]
pub struct JsonResponse<T> {
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub item: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub list: Option<Vec<T>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<serde_json::Value>,
}

pub struct JsonResponseBuilder<T: serde::Serialize> {
    message: String,
    id: Option<i32>,
    item: Option<T>,
    list: Option<Vec<T>>,
    meta: Option<serde_json::Value>,
}
```

### Usage Examples
```rust
// Success with single item
Ok(JsonResponse::build()
    .set_item(response_data)
    .ok("Operation successful"))

// Success with list
Ok(JsonResponse::build()
    .set_list(vec![item1, item2])
    .ok("Items fetched"))

// Error responses
Err(JsonResponse::<DeploymentStatusResponse>::build()
    .internal_server_error("Database connection failed"))

Err(JsonResponse::<DeploymentStatusResponse>::build()
    .not_found("Deployment not found"))

Err(JsonResponse::<()>::build()
    .bad_request("Invalid deployment_hash"))

// With ID
Ok(HttpResponse::Created().json(
    JsonResponse::build()
        .set_id(new_id)
        .ok("Created successfully")))

// No content
JsonResponse::build().no_content()
```

### Error Methods
- `.ok(msg)` → 200 OK with Json wrapper
- `.created(msg)` → 201 Created
- `.no_content()` → 204 No Content
- `.bad_request(msg)` → 400 Bad Request (Error)
- `.not_found(msg)` → 404 Not Found (Error)
- `.forbidden(msg)` → 403 Forbidden (Error)
- `.conflict(msg)` → 409 Conflict (Error)
- `.internal_server_error(msg)` → 500 Internal Server Error (Error)

### Generic Shortcuts
```rust
JsonResponse::<String>::bad_request("Invalid input")
JsonResponse::<String>::internal_server_error("DB error")
JsonResponse::<String>::not_found("Resource not found")
JsonResponse::<String>::forbidden("Access denied")
```

---

## 6. DEPLOYMENT MODEL

### Deployment Table Structure
```rust
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Deployment {
    pub id: i32,                          // Primary key
    pub project_id: i32,                  // Foreign key to projects
    pub deployment_hash: String,          // Unique identifier for agent
    pub user_id: Option<String>,          // User who created (nullable)
    pub deleted: Option<bool>,            // Soft delete flag
    pub status: String,                   // pending, active, failed, etc.
    pub metadata: Value,                  // JSON arbitrary data
    pub last_seen_at: Option<DateTime<Utc>>,  // Last agent heartbeat
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Deployment {
    pub fn new(
        project_id: i32,
        user_id: Option<String>,
        deployment_hash: String,
        status: String,
        metadata: Value,
    ) -> Self { ... }
}
```

### Typical Deployment Response
```rust
#[derive(Debug, Clone, Serialize, Default)]
pub struct DeploymentStatusResponse {
    pub id: i32,
    pub project_id: i32,
    pub deployment_hash: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_message: Option<String>,  // From metadata
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<models::Deployment> for DeploymentStatusResponse {
    fn from(d: models::Deployment) -> Self {
        let status_message = d.metadata
            .get("status_message")
            .and_then(|v| v.as_str())
            .map(String::from);
        
        Self { ... }
    }
}
```

---

## 7. AGENT MODEL

### Agent Table Structure
```rust
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Agent {
    pub id: Uuid,
    pub deployment_hash: String,
    pub capabilities: Option<Value>,      // ["docker", "logs", "compose"]
    pub version: Option<String>,          // Agent version
    pub system_info: Option<Value>,       // OS, arch, etc.
    pub last_heartbeat: Option<DateTime<Utc>>,
    pub status: String,                   // "online" or "offline"
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Agent {
    pub fn new(deployment_hash: String) -> Self {
        Self {
            id: Uuid::new_v4(),
            deployment_hash,
            capabilities: Some(serde_json::json!([])),
            version: None,
            system_info: Some(serde_json::json!({})),
            last_heartbeat: None,
            status: "offline".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }
    
    pub fn is_online(&self) -> bool {
        self.status == "online"
    }
    
    pub fn mark_online(&mut self) {
        self.status = "online".to_string();
        self.last_heartbeat = Some(Utc::now());
        self.updated_at = Utc::now();
    }
    
    pub fn mark_offline(&mut self) {
        self.status = "offline".to_string();
        self.updated_at = Utc::now();
    }
}
```

### Audit Log Model
```rust
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct AuditLog {
    pub id: Uuid,
    pub agent_id: Option<Uuid>,
    pub deployment_hash: Option<String>,
    pub action: String,
    pub status: Option<String>,
    pub details: serde_json::Value,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl AuditLog {
    pub fn new(
        agent_id: Option<Uuid>,
        deployment_hash: Option<String>,
        action: String,
        status: Option<String>,
    ) -> Self { ... }
    
    pub fn with_details(mut self, details: Value) -> Self {
        self.details = details;
        self
    }
    
    pub fn with_ip(mut self, ip: String) -> Self {
        self.ip_address = Some(ip);
        self
    }
    
    pub fn with_user_agent(mut self, user_agent: String) -> Self {
        self.user_agent = Some(user_agent);
        self
    }
}
```

---

## 8. VAULT CLIENT PATTERN (src/helpers/vault.rs)

### Token Storage
```rust
pub struct VaultClient {
    client: Client,
    address: String,
    token: String,
    agent_path_prefix: String,      // e.g., "agent"
    api_prefix: String,              // e.g., "v1"
}

// Store: POST {address}/{api_prefix}/{agent_path_prefix}/{deployment_hash}/token
#[tracing::instrument(name = "Store agent token in Vault", skip(self, token))]
pub async fn store_agent_token(
    &self,
    deployment_hash: &str,
    token: &str,
) -> Result<(), String> {
    let path = format!("{}/{}/{}/token", base, prefix, deployment_hash);
    let payload = json!({
        "data": {
            "token": token,
            "deployment_hash": deployment_hash
        }
    });

    self.client
        .post(&path)
        .header("X-Vault-Token", &self.token)
        .json(&payload)
        .send()
        .await?
        .error_for_status()?;

    Ok(())
}

// Fetch: GET {address}/{api_prefix}/{agent_path_prefix}/{deployment_hash}/token
pub async fn fetch_agent_token(&self, deployment_hash: &str) -> Result<String, String> {
    let response = self.client
        .get(&path)
        .header("X-Vault-Token", &self.token)
        .send()
        .await?;

    // Extract token from response data
    let data: serde_json::Value = response.json().await?;
    let token = data
        .get("data")
        .and_then(|d| d.get("token"))
        .and_then(|t| t.as_str())
        .ok_or("Token not found in Vault response")?;

    Ok(token.to_string())
}
```

---

## 9. HANDLER PATTERNS & STRUCTURE

### Complete Handler Example (src/routes/command/create.rs)

```rust
#[derive(Debug, Deserialize)]
pub struct CreateCommandRequest {
    pub deployment_hash: String,
    pub command_type: String,
    #[serde(default)]
    pub priority: Option<String>,
    #[serde(default)]
    pub parameters: Option<serde_json::Value>,
    #[serde(default)]
    pub timeout_seconds: Option<i32>,
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, Default)]
pub struct CreateCommandResponse {
    pub command_id: String,
    pub deployment_hash: String,
    pub status: String,
}

#[tracing::instrument(name = "Create command", skip(pg_pool, user, settings))]
#[post("")]
pub async fn create_handler(
    user: web::ReqData<Arc<User>>,           // Authenticated user
    req: web::Json<CreateCommandRequest>,    // Request body
    pg_pool: web::Data<PgPool>,             // Database pool
    settings: web::Data<Settings>,          // App config
) -> Result<impl Responder> {
    // 1. Validate input
    if req.deployment_hash.trim().is_empty() {
        return Err(JsonResponse::<()>::build()
            .bad_request("deployment_hash is required"));
    }

    // 2. Validate business logic
    let validated_parameters = 
        status_panel::validate_command_parameters(&req.command_type, &req.parameters)
        .map_err(|err| JsonResponse::<()>::build().bad_request(err))?;

    // 3. Query database
    let deployment = crate::db::deployment::fetch_by_deployment_hash(
        pg_pool.get_ref(),
        &req.deployment_hash,
    )
    .await
    .map_err(|err| JsonResponse::<CreateCommandResponse>::build()
        .internal_server_error(err))?;

    // 4. Create entity
    let mut command = Command::new(
        user.id.clone(),
        req.deployment_hash.clone(),
        req.command_type.clone(),
    );
    
    command.parameters = Some(validated_parameters);
    if let Some(timeout) = req.timeout_seconds {
        command.timeout_seconds = Some(timeout);
    }

    // 5. Save to database
    let saved_command = crate::db::command::insert(pg_pool.get_ref(), command)
        .await
        .map_err(|err| JsonResponse::<CreateCommandResponse>::build()
            .internal_server_error(err))?;

    // 6. Return response
    Ok(JsonResponse::build()
        .set_item(CreateCommandResponse {
            command_id: saved_command.id.to_string(),
            deployment_hash: saved_command.deployment_hash,
            status: saved_command.status,
        })
        .ok("Command created successfully"))
}
```

### Handler Pattern Checklist
✓ Use `#[tracing::instrument]` for observability
✓ Use `#[post]`/`#[get]` macros for routing
✓ Extract authenticated user with `web::ReqData<Arc<User>>`
✓ Extract body with `web::Json<RequestType>`
✓ Validate input (required fields, format, constraints)
✓ Query database with `.await` + `.map_err()` for error handling
✓ Use `tracing::info!`/`warn!`/`error!` for logging
✓ Return `Result<impl Responder>`
✓ Wrap response with `JsonResponse::build().set_item(...).ok(...)`
✓ Return errors with `JsonResponse::build().error_type(...)`

---

## 10. IMPLEMENTATION GUIDE FOR NEW ENDPOINTS

### Endpoint: POST /api/v1/auth/login

```rust
// File: src/routes/auth/mod.rs
pub mod login;
pub use login::*;

// File: src/routes/auth/login.rs
use actix_web::{post, web, HttpResponse, Result, Responder};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub session_token: String,           // 86-char random token
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
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[tracing::instrument(name = "User login", skip(req, pool))]
#[post("/login")]
pub async fn login_handler(
    req: web::Json<LoginRequest>,
    pool: web::Data<PgPool>,
    vault_client: web::Data<crate::helpers::VaultClient>,
) -> Result<impl Responder> {
    // 1. Validate input
    if req.email.trim().is_empty() {
        return Err(crate::helpers::JsonResponse::<LoginResponse>::build()
            .bad_request("email is required"));
    }
    if req.password.trim().is_empty() {
        return Err(crate::helpers::JsonResponse::<LoginResponse>::build()
            .bad_request("password is required"));
    }

    // 2. Query user by email (requires user table in stacker DB)
    let user = db::user::fetch_by_email(pool.get_ref(), &req.email)
        .await
        .map_err(|err| crate::helpers::JsonResponse::<LoginResponse>::build()
            .internal_server_error(err))?;

    let user = match user {
        Some(u) => u,
        None => {
            tracing::warn!("Login attempt with non-existent email: {}", req.email);
            return Err(crate::helpers::JsonResponse::<LoginResponse>::build()
                .not_found("Invalid credentials"));
        }
    };

    // 3. Verify password (bcrypt or argon2)
    if !verify_password(&req.password, &user.password_hash)? {
        tracing::warn!("Failed login attempt for: {}", req.email);
        return Err(crate::helpers::JsonResponse::<LoginResponse>::build()
            .forbidden("Invalid credentials"));
    }

    // 4. Generate session token (86-char random)
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

    let _ = db::audit::log(pool.get_ref(), audit_log).await;

    // 8. Return response
    Ok(HttpResponse::Ok().json(
        crate::helpers::JsonResponse::build()
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
            .to_json_response()
    ))
}

fn generate_session_token() -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut rng = rand::thread_rng();
    (0..86).map(|_| {
        let idx = rng.gen_range(0..CHARSET.len());
        CHARSET[idx] as char
    }).collect()
}

fn verify_password(password: &str, hash: &str) -> Result<bool, String> {
    // Use bcrypt or argon2
    bcrypt::verify(password, hash)
        .map_err(|e| format!("Password verification failed: {}", e))
}
```

### Endpoint: POST /api/v1/agents/link

```rust
// File: src/routes/agent/link.rs
use actix_web::{post, web, HttpResponse, Result, Responder};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::Arc;

#[derive(Debug, Deserialize)]
pub struct LinkAgentRequest {
    pub session_token: String,      // From login
    pub deployment_id: i32,         // Target deployment
    pub fingerprint: String,        // Agent fingerprint
}

#[derive(Debug, Serialize)]
pub struct LinkAgentResponse {
    pub agent_id: String,
    pub deployment_id: i32,
    pub credentials: AgentCredentials,
}

#[derive(Debug, Serialize)]
pub struct AgentCredentials {
    pub token: String,              // Agent auth token
    pub deployment_hash: String,
    pub server_url: String,
}

#[tracing::instrument(name = "Link agent to deployment", skip(pool, vault_client))]
#[post("/link")]
pub async fn link_handler(
    req: web::Json<LinkAgentRequest>,
    pool: web::Data<PgPool>,
    vault_client: web::Data<crate::helpers::VaultClient>,
    settings: web::Data<crate::configuration::Settings>,
) -> Result<impl Responder> {
    // 1. Validate input
    if req.session_token.trim().is_empty() {
        return Err(crate::helpers::JsonResponse::<LinkAgentResponse>::build()
            .bad_request("session_token is required"));
    }

    // 2. Fetch session from Vault by session token
    let user_id = vault_client
        .fetch_session_user_id(&req.session_token)
        .await
        .map_err(|err| {
            tracing::warn!("Invalid or expired session token");
            crate::helpers::JsonResponse::<LinkAgentResponse>::build()
                .forbidden("Invalid or expired session")
        })?;

    // 3. Fetch deployment and verify user owns it
    let deployment = db::deployment::fetch(pool.get_ref(), req.deployment_id)
        .await
        .map_err(|err| crate::helpers::JsonResponse::<LinkAgentResponse>::build()
            .internal_server_error(err))?;

    let deployment = match deployment {
        Some(d) => d,
        None => {
            return Err(crate::helpers::JsonResponse::<LinkAgentResponse>::build()
                .not_found("Deployment not found"));
        }
    };

    // Verify user owns this deployment
    if deployment.user_id.as_deref() != Some(&user_id) {
        tracing::warn!("Unauthorized link attempt by user {} for deployment {}",
            user_id, req.deployment_id);
        return Err(crate::helpers::JsonResponse::<LinkAgentResponse>::build()
            .forbidden("You do not own this deployment"));
    }

    // 4. Check if agent already linked
    let existing_agent = db::agent::fetch_by_deployment_hash(
        pool.get_ref(),
        &deployment.deployment_hash,
    )
    .await
    .map_err(|err| crate::helpers::JsonResponse::<LinkAgentResponse>::build()
        .internal_server_error(err))?;

    let (agent_id, agent_token) = if let Some(agent) = existing_agent {
        // Reuse existing agent
        let token = vault_client
            .fetch_agent_token(&deployment.deployment_hash)
            .await
            .map_err(|_| crate::helpers::JsonResponse::<LinkAgentResponse>::build()
                .internal_server_error("Failed to fetch agent token"))?;
        
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
            .map_err(|err| crate::helpers::JsonResponse::<LinkAgentResponse>::build()
                .internal_server_error(err))?;

        let token = generate_agent_token();
        
        // Store token in Vault
        let vault = vault_client.clone();
        let hash = deployment.deployment_hash.clone();
        let token_copy = token.clone();
        actix_web::rt::spawn(async move {
            for retry in 0..3 {
                if vault.store_agent_token(&hash, &token_copy).await.is_ok() {
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
    Ok(HttpResponse::Ok().json(
        crate::helpers::JsonResponse::build()
            .set_item(LinkAgentResponse {
                agent_id,
                deployment_id: req.deployment_id,
                credentials: AgentCredentials {
                    token: agent_token,
                    deployment_hash: deployment.deployment_hash,
                    server_url: settings.server.base_url.clone(),
                },
            })
            .to_json_response()
    ))
}

fn generate_agent_token() -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut rng = rand::thread_rng();
    (0..86).map(|_| {
        let idx = rng.gen_range(0..CHARSET.len());
        CHARSET[idx] as char
    }).collect()
}
```

### Register Routes in startup.rs

```rust
.service(
    web::scope("/api/v1/auth")
        .service(routes::auth::login_handler),
)
.service(
    web::scope("/api/v1/agents")
        .service(routes::agent::link_handler),
)
```

---

## 11. CONFIGURATION & DEPENDENCY INJECTION

### Available Injected Data (from startup.rs)
```rust
web::Data<Settings>                     // App configuration
web::Data<Pool<Postgres>>              // API database
web::Data<AgentPgPool>                 // Agent database
web::Data<MqManager>                   // RabbitMQ
web::Data<VaultClient>                 // Vault (token storage)
web::Data<reqwest::Client>            // HTTP client (OAuth, etc.)
web::Data<OAuthCache>                  // OAuth token cache
web::Data<Arc<ToolRegistry>>          // MCP tools
web::Data<Arc<HealthChecker>>         // Health checks
web::Data<Arc<HealthMetrics>>         // Metrics
web::Data<Arc<dyn UserServiceConnector>>  // User service connector
web::Data<Arc<dyn InstallServiceConnector>> // Install service
web::Data<Arc<Cors>>                   // CORS config
Arc<models::User>                       // Authenticated user (from extensions)
```

### Tracing/Logging
```rust
// Fields are automatically captured from function parameters
#[tracing::instrument(name = "Handler name", skip(pool, vault_client))]
#[post("/endpoint")]
pub async fn handler(
    user: web::ReqData<Arc<User>>,
    pool: web::Data<PgPool>,
    vault_client: web::Data<VaultClient>,  // Skip from logs
) -> Result<impl Responder> {
    tracing::info!("User action starting");
    tracing::warn!("Warning message");
    tracing::error!("Error occurred: {:?}", err);
    tracing::debug!("Debug details");
}
```

---

## 12. KEY PATTERNS SUMMARY

### Error Handling
- DB functions return `Result<T, String>`
- Handlers return `Result<impl Responder>`
- All errors wrapped in `JsonResponse::build().error_type(msg)`
- Errors logged with `tracing::error!`

### Authentication
- User injected via `web::ReqData<Arc<models::User>>`
- Authenticated users have `user.id` and `user.role`
- Ownership checks: `if d.user_id.as_deref() != Some(&user.id) {}`

### Database
- Use `sqlx::query_as!` for type-safe queries
- Handle `RowNotFound` separately from other errors
- Use `.instrument(query_span)` for tracing

### Async Operations
- Token storage uses `actix_web::rt::spawn` for fire-and-forget async
- Retry logic with exponential backoff for Vault operations
- Error logging but don't fail the request if async fails

### Responses
- Always use `JsonResponse::build().set_item(...).ok(msg)` for success
- Use appropriate error methods: `.bad_request()`, `.not_found()`, etc.
- Empty responses use `.no_content()`
- Created resources use `.created(msg)`

