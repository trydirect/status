# Stacker Server Endpoint Implementation - Start Here

This directory contains 4 comprehensive documentation files for implementing two new endpoints:
- **POST /api/v1/auth/login** (email + password → session_token + user's deployments)
- **POST /api/v1/agents/link** (session_token + deployment_id + fingerprint → agent credentials)

## 📖 Documentation Files

### 1. **🚀 QUICK_REFERENCE.md** - RECOMMENDED START HERE
**Time to read**: 10 minutes  
**Best for**: Implementation planning and quick pattern lookup

**Contains**:
- Summary of all key patterns
- Implementation checklists for both endpoints
- Error response format
- Testing examples with curl
- Database models needed

**👉 Start here for**: Understanding what you need to do

---

### 2. **💻 CODE_SNIPPETS.md** - COPY-PASTE READY CODE
**Time to read**: 15 minutes (to find what you need)  
**Best for**: Implementation - copy-paste production-ready code

**Contains**:
- Complete `src/routes/auth/login.rs` handler
- Complete `src/routes/agent/link.rs` handler  
- All file modifications needed
- Database migration SQL
- VaultClient extensions

**👉 Use this for**: Copying exact code to implement

---

### 3. **📚 IMPLEMENTATION_GUIDE.md** - DEEP REFERENCE
**Time to read**: 45 minutes (or read as needed)  
**Best for**: Understanding patterns, troubleshooting, adapting code

**Contains**:
- Route structure & registration explained
- Complete agent registration flow breakdown
- All 6 authentication methods explained
- Database query patterns with examples
- Response/error handling with builder pattern
- Vault client token storage with retry logic
- Audit logging patterns
- Complete handler pattern example
- Middleware stack composition

**👉 Use this for**: "Why does this pattern exist?" and troubleshooting

---

### 4. **📋 ANALYSIS_README.md** - PROJECT OVERVIEW
**Time to read**: 15 minutes  
**Best for**: Understanding the big picture and implementation roadmap

**Contains**:
- Master index
- Key findings from codebase analysis
- Files changed/created summary
- Quick start implementation path
- Architecture patterns checklist
- Dependencies required

**👉 Use this for**: Project-level overview and quick reference

---

## 🎯 Quick Implementation Path (30 minutes)

```
1. Read QUICK_REFERENCE.md                (10 min)
   ↓
2. Copy code from CODE_SNIPPETS.md         (10 min)
   ↓
3. Run database migrations & test          (10 min)
   ↓
✅ Done! Both endpoints working
```

If you get stuck:
→ Check IMPLEMENTATION_GUIDE.md for explanations
→ Refer to existing route handlers in `src/routes/`

---

## 🚀 One-Minute Summary

**Pattern**: Scoped routes with authenticated user extraction  
**Auth**: JWT/OAuth/Cookie/Agent tokens injected via middleware  
**DB**: sqlx queries returning Result<T, String>  
**Responses**: JsonResponse builder pattern with error methods  
**Tokens**: 86-char random strings, async storage in Vault/DB  
**Logging**: Audit logs with details, IP address, timestamps  

---

## 📝 Implementation Checklist

### Login Endpoint
- [ ] Create `src/routes/auth/login.rs` (copy from CODE_SNIPPETS)
- [ ] Create `src/routes/auth/mod.rs`
- [ ] Create `src/db/user.rs` with `fetch_by_email()`
- [ ] Update `src/routes/mod.rs` to add auth module
- [ ] Update `src/startup.rs` to register route
- [ ] Run database migration for users table
- [ ] Test with curl POST /api/v1/auth/login

### Link Endpoint
- [ ] Create `src/routes/agent/link.rs` (copy from CODE_SNIPPETS)
- [ ] Update `src/routes/agent/mod.rs`
- [ ] Update `src/startup.rs` to register route
- [ ] Update `src/db/` if needed for session queries
- [ ] Test with curl POST /api/v1/agents/link

---

## 🧪 Testing

### Login Test
```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"pass123"}'
```

### Link Test
```bash
curl -X POST http://localhost:8080/api/v1/agents/link \
  -H "Content-Type: application/json" \
  -d '{
    "session_token":"<token_from_login>",
    "deployment_id":1,
    "fingerprint":"hash"
  }'
```

Expected: 200 OK with credentials

---

## 💡 Key Patterns in Codebase

1. **Routes**: Scoped with `web::scope()` + `#[post]`/`#[get]` macros
2. **Auth**: User injected via `web::ReqData<Arc<models::User>>`
3. **DB**: All functions return `Result<T, String>`
4. **Responses**: `JsonResponse::build().set_item(data).ok("msg")`
5. **Errors**: `.bad_request()`, `.not_found()`, `.forbidden()`, `.internal_server_error()`
6. **Tokens**: 86-char random, stored async with retry
7. **Audit**: `AuditLog::new(...).with_details(...).with_ip(...)`

---

## 📁 Files to Create/Modify

### New Files
- `src/routes/auth/mod.rs`
- `src/routes/auth/login.rs`
- `src/routes/agent/link.rs`
- `src/db/user.rs`
- `migrations/[DATE]_create_users_sessions.sql`

### Modified Files
- `src/routes/mod.rs` - Add auth module
- `src/routes/agent/mod.rs` - Add link handler
- `src/startup.rs` - Register routes
- `src/models/user.rs` - Add password_hash field

All changes are in CODE_SNIPPETS.md!

---

## ❓ FAQ

**Q: Where's the authentication?**  
A: Middleware automatically extracts JWT/OAuth/Cookie tokens. See IMPLEMENTATION_GUIDE.md section 3.

**Q: How do I store sessions?**  
A: Use database (recommended) or Vault. CODE_SNIPPETS.md shows both approaches.

**Q: What's with the 86-char tokens?**  
A: Pattern from existing agent registration. Provides good entropy with alphanumeric + dash/underscore.

**Q: How do errors work?**  
A: JsonResponse builder with error methods. Returns appropriate HTTP status codes. See QUICK_REFERENCE.md.

**Q: Do I need Vault?**  
A: For agents (existing pattern). For sessions, database is simpler. See CODE_SNIPPETS.md.

**Q: How do I verify the user owns the deployment?**  
A: Check `if d.user_id.as_deref() != Some(&user_id) { forbidden }`. See QUICK_REFERENCE.md.

---

## 🔗 File Relationships

```
Login Endpoint
├── POST /api/v1/auth/login
├── Routes: src/routes/auth/login.rs
├── DB: src/db/user.rs (fetch by email)
├── Response: session_token + user + deployments
└── Uses: JsonResponse, AuditLog

Link Endpoint
├── POST /api/v1/agents/link  
├── Routes: src/routes/agent/link.rs
├── Auth: session_token validation
├── DB: deployment fetch + verify ownership
├── Response: agent_id + credentials
└── Uses: JsonResponse, AuditLog, Vault
```

---

## 📚 Recommended Reading Order

1. **This file** (1 min) ← You are here
2. **QUICK_REFERENCE.md** (10 min)
3. **CODE_SNIPPETS.md** (copy what you need)
4. **Refer to IMPLEMENTATION_GUIDE.md** as needed

---

## 🎓 Learning the Codebase

If you want to understand the codebase patterns:

1. **Routes**: `src/routes/agent/register.rs` (excellent example)
2. **Auth**: `src/middleware/authentication/` (how tokens are extracted)
3. **DB**: `src/db/deployment.rs` (query patterns)
4. **Responses**: `src/helpers/json.rs` (JsonResponse builder)
5. **Middleware**: `src/startup.rs` (middleware stack)

---

## ✅ Validation Checklist

After implementing, verify:
- [ ] Both endpoints respond with 200 OK
- [ ] Login returns session_token + user + deployments
- [ ] Link returns agent_id + credentials + token
- [ ] Invalid credentials return 403 Forbidden
- [ ] Missing fields return 400 Bad Request
- [ ] Unauthorized users return 403 Forbidden
- [ ] Database migrations run successfully
- [ ] Audit logs created for both actions
- [ ] Token generated (86 characters)

---

## 🆘 Troubleshooting

**"Route not found"**
→ Check startup.rs scope registration

**"User not found"**  
→ Ensure users table created and user exists

**"Invalid credentials"**
→ Check password hashing (bcrypt)

**"Deployment not found"**
→ Verify deployment belongs to user

**"Unauthorized"**
→ Check session token validity and user ownership

See IMPLEMENTATION_GUIDE.md for detailed error handling patterns.

---

## 📞 Next Steps

1. ✅ Read QUICK_REFERENCE.md (10 min)
2. ✅ Copy code from CODE_SNIPPETS.md (10 min)
3. ✅ Update files and run migrations (10 min)
4. ✅ Test with curl (5 min)
5. 🎉 Done!

**Total time**: ~35 minutes

---

**Location**: `/Users/vasilipascal/work/try.direct/stacker/`

Good luck! 🚀
