# Stacker Server Codebase Analysis - Complete Documentation

This directory contains comprehensive documentation about the Stacker Server codebase patterns and how to add the two new endpoints.

## Documentation Files

### 1. **QUICK_REFERENCE.md** ⭐ START HERE
- **Length**: 283 lines
- **Purpose**: High-level summary of all key patterns
- **Contains**:
  - Route structure overview
  - Authentication/user extraction patterns
  - Database query patterns
  - Response/error handling
  - Vault client usage
  - Audit logging
  - Middleware stack
  - Dependency injection
  - Implementation checklists for both endpoints
  - Database models needed
  - Testing examples

**Best for**: Quick lookup, implementation planning, testing

---

### 2. **IMPLEMENTATION_GUIDE.md** 📚 DETAILED REFERENCE
- **Length**: 1,131 lines
- **Purpose**: In-depth explanation of all codebase patterns
- **Contains**:
  - Route structure & registration (with file organization)
  - Agent registration pattern (complete flow with idempotency)
  - Authentication & middleware (all 6 auth methods)
  - Database layer (connection pools, query patterns, error handling)
  - Response/error handling builder pattern
  - Deployment model (table structure, responses)
  - Agent model (table structure, lifecycle methods)
  - Vault client pattern (token storage with retry logic)
  - Complete handler pattern example
  - Implementation guide for both endpoints (full code)
  - Configuration & dependency injection
  - Key patterns summary

**Best for**: Understanding why patterns exist, deep dives, reference implementation

---

### 3. **CODE_SNIPPETS.md** 💻 COPY-PASTE READY
- **Length**: 605 lines
- **Purpose**: Production-ready code snippets
- **Contains**:
  - `src/routes/auth/login.rs` - Complete login handler
  - `src/routes/auth/mod.rs` - Module definition
  - `src/routes/agent/link.rs` - Complete link handler
  - Updated `src/routes/agent/mod.rs` - Add link module
  - Updated `src/routes/mod.rs` - Add auth module
  - `src/db/user.rs` - User database queries
  - Updated `src/startup.rs` - Register new routes
  - VaultClient extensions - Add session methods
  - Database migration SQL - Create users/sessions tables
  - Recommended: Database-backed sessions instead of Vault

**Best for**: Copy-paste implementation, exact code patterns

---

## Quick Start Implementation Path

### Step 1: Read QUICK_REFERENCE.md
- Understand the patterns
- Review implementation checklists
- Note database requirements

### Step 2: Copy Code from CODE_SNIPPETS.md
- Create `src/routes/auth/` directory and files
- Add `src/routes/agent/link.rs`
- Update route registrations
- Create database migrations

### Step 3: Use IMPLEMENTATION_GUIDE.md for Questions
- If you need to understand WHY a pattern is used
- If you need to adapt code for different scenarios
- If you want to see how existing patterns work

---

## Key Findings from Codebase Analysis

### Route Organization
```
/api/v1/agent       → Agent registration/management
/api/v1/deployments → Deployment status queries
/api/v1/commands    → Command creation/execution
/api/v1/auth        → ⭐ NEW: Login endpoint
/api/v1/agents      → ⭐ EXTENDED: Link endpoint
```

### Authentication Methods (Tried in Order)
1. Agent Token (X-Agent-Token header)
2. JWT Bearer Token (Authorization header)
3. OAuth Callback Tokens
4. Session Cookies
5. HMAC Signature
6. Anonymous (public access)

### Error Handling Pattern
```rust
// All DB functions return Result<T, String>
// All handlers return Result<impl Responder>
// All errors wrapped in JsonResponse with appropriate HTTP status

Err(JsonResponse::<ResponseType>::build()
    .bad_request("msg"))           // 400
Err(JsonResponse::<ResponseType>::build()
    .forbidden("msg"))             // 403
Err(JsonResponse::<ResponseType>::build()
    .not_found("msg"))             // 404
Err(JsonResponse::<ResponseType>::build()
    .internal_server_error("msg")) // 500
```

### Token Generation & Storage Pattern
- **Token Format**: 86-character random string (alphanumeric + dash/underscore)
- **Storage**: Vault (distributed) or Database (recommended for sessions)
- **Async Storage**: Fire-and-forget with 3 retries on exponential backoff (2s, 4s, 8s)
- **Request Success**: Not blocked by Vault storage failures
- **Idempotency**: Tokens reused if agent/session already exists

### Deployment Model
```
User (1) ──→ (N) Projects ──→ (N) Deployments ──→ (1) Agent
                 user_id          user_id + deployment_hash
```

**Key Query Pattern**:
```rust
// Ownership verification
if d.user_id.as_deref() != Some(&user_id) {
    return Err(JsonResponse::build().not_found("..."));  // Hide that it exists
}
```

### Middleware Stack
```
App wrapping order:
1. CORS - Allow cross-origin requests
2. Tracing - Log all requests
3. Authorization (Casbin) - Role-based access control
4. Authentication (6 methods) - Extract & inject User
5. Compression - Gzip responses
```

### Database Pattern
- **Main Pool**: `api_pool` - General purpose
- **Agent Pool**: `agent_pool` - Dedicated for agent operations
- **Query Style**: `sqlx::query_as!()` for compile-time checking
- **Error Handling**: Map `RowNotFound` separately, convert all to `String`
- **Tracing**: All queries wrapped with `.instrument(query_span)`

### Deployment Queries Available
```rust
db::deployment::fetch(pool, id) → Option<Deployment>
db::deployment::fetch_by_user(pool, user_id, limit) → Vec<Deployment>
db::deployment::fetch_by_project_id(pool, project_id) → Option<Deployment>
db::deployment::fetch_by_user_and_project(pool, user_id, project_id, limit) → Vec<Deployment>
db::deployment::fetch_by_deployment_hash(pool, hash) → Option<Deployment>
```

### Audit Logging Pattern
```rust
let audit_log = models::AuditLog::new(
    Some(agent_id),
    Some(deployment_hash),
    "action_name".to_string(),
    Some("success".to_string()),
)
.with_details(serde_json::json!({"key": value}))
.with_ip(req.peer_addr().map(|a| a.ip().to_string()).unwrap_or_default());

db::agent::log_audit(pool.get_ref(), audit_log).await;
```

---

## Files Changed/Created

### New Files
1. `src/routes/auth/mod.rs` - Auth module definition
2. `src/routes/auth/login.rs` - Login handler (complete)
3. `src/routes/agent/link.rs` - Link agent handler (complete)
4. `src/db/user.rs` - User database queries
5. `migrations/[DATE]_create_users_sessions.sql` - DB schema

### Modified Files
1. `src/routes/mod.rs` - Add `pub(crate) mod auth`
2. `src/routes/agent/mod.rs` - Add `pub use link::*`
3. `src/startup.rs` - Register `/api/v1/auth` and `/api/v1/agents` scopes
4. `src/models/user.rs` - Add `password_hash` field
5. `src/helpers/vault.rs` - Add session token methods (optional)

---

## Testing the Endpoints

### Test 1: Login
```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "password123"
  }'

Expected Response (200):
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

### Test 2: Link Agent
```bash
curl -X POST http://localhost:8080/api/v1/agents/link \
  -H "Content-Type: application/json" \
  -d '{
    "session_token": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
    "deployment_id": 1,
    "fingerprint": "agent-fingerprint-hash"
  }'

Expected Response (200):
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

---

## Dependencies Required

The code uses these crates (likely already in Cargo.toml):
- `actix-web` - HTTP framework
- `serde` / `serde_json` - JSON serialization
- `sqlx` - Database queries
- `rand` - Token generation
- `chrono` - Timestamps
- `uuid` - ID generation
- `bcrypt` - Password hashing (add if not present)
- `tracing` - Logging & instrumentation

If `bcrypt` is missing, add to `Cargo.toml`:
```toml
bcrypt = "0.15"
```

---

## Architecture Patterns Checklist

✓ **Route Pattern**: Scoped web services with macro-based handlers
✓ **Auth Pattern**: Middleware-injected Arc<User> + ReqData extraction
✓ **DB Pattern**: sqlx with Result<T, String> error type
✓ **Response Pattern**: JsonResponse builder with skip_serializing_if
✓ **Error Pattern**: Typed error methods returning HTTP errors
✓ **Token Pattern**: 86-char random string stored in Vault/DB
✓ **Async Pattern**: Fire-and-forget with actix_web::rt::spawn
✓ **Retry Pattern**: Exponential backoff (2^n seconds)
✓ **Audit Pattern**: AuditLog with details + IP + timestamp
✓ **Ownership Pattern**: User ID string comparison with .as_deref()
✓ **Logging Pattern**: tracing::instrument + tracing::info/warn/error
✓ **Injection Pattern**: web::Data<T> for all shared state

---

## Next Steps

1. **Read QUICK_REFERENCE.md** for overview (10 min)
2. **Review CODE_SNIPPETS.md** for actual code (20 min)
3. **Create new files** and update existing ones (30 min)
4. **Run database migrations** (5 min)
5. **Test endpoints** with curl or Postman (10 min)
6. **Refer to IMPLEMENTATION_GUIDE.md** if clarification needed

---

## Questions?

Each documentation file has specific use cases:

- **"How does X pattern work?"** → IMPLEMENTATION_GUIDE.md
- **"What's the quick reference?"** → QUICK_REFERENCE.md
- **"Show me the code"** → CODE_SNIPPETS.md
- **"What about error handling?"** → QUICK_REFERENCE.md or IMPLEMENTATION_GUIDE.md
- **"How do I test?"** → QUICK_REFERENCE.md (Testing section)

---

Generated from analysis of:
- `/Users/vasilipascal/work/try.direct/stacker/src/routes/` - Route handlers
- `/Users/vasilipascal/work/try.direct/stacker/src/middleware/` - Auth & authorization
- `/Users/vasilipascal/work/try.direct/stacker/src/db/` - Database queries
- `/Users/vasilipascal/work/try.direct/stacker/src/models/` - Data models
- `/Users/vasilipascal/work/try.direct/stacker/src/helpers/` - Response builders & utilities
- `/Users/vasilipascal/work/try.direct/stacker/src/startup.rs` - Server configuration

