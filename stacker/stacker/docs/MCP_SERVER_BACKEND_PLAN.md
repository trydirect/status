# MCP Server Backend Implementation Plan

## Overview
This document outlines the implementation plan for adding Model Context Protocol (MCP) server capabilities to the Stacker backend. The MCP server will expose Stacker's functionality as tools that AI assistants can use to help users build and deploy application stacks.

> **Current status:** The original 17-tool MVP has been surpassed. As of
> v0.2.8 the registry exposes 85+ tools, including remote service secret
> management (`list_remote_secret_targets`, `list_remote_service_secrets`,
> `get_remote_service_secret`, `set_remote_service_secret`,
> `delete_remote_service_secret`) with metadata-only reads and Vault-backed
> writes. All tool calls require explicit per-tool Casbin `CALL` policies under
> `/mcp/tools/<tool_name>`; sensitive write/destructive tools additionally
> require verified 2FA/MFA.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  Stacker Backend (Rust/Actix-web)                      │
│                                                         │
│  ┌──────────────────┐        ┌────────────────────┐   │
│  │  REST API        │        │  MCP Server        │   │
│  │  (Existing)      │        │  (New)             │   │
│  │                  │        │                    │   │
│  │  /project        │◄───────┤  Tool Registry     │   │
│  │  /cloud          │        │  - create_project  │   │
│  │  /rating         │        │  - list_projects   │   │
│  │  /deployment     │        │  - get_templates   │   │
│  └──────────────────┘        │  - deploy_project  │   │
│           │                  │  - etc...          │   │
│           │                  └────────────────────┘   │
│           │                           │               │
│           │                           │               │
│           └───────────┬───────────────┘               │
│                       ▼                               │
│              ┌─────────────────┐                      │
│              │ PostgreSQL DB   │                      │
│              │ + Session Store │                      │
│              └─────────────────┘                      │
└─────────────────────────────────────────────────────────┘
                        │
                        │ WebSocket (JSON-RPC 2.0)
                        ▼
┌─────────────────────────────────────────────────────────┐
│  Frontend (React) or AI Client                         │
│  - Sends tool requests                                 │
│  - Receives tool results                               │
│  - Manages conversation context                        │
└─────────────────────────────────────────────────────────┘
```

## Technology Stack

### Core Dependencies
```toml
[dependencies]
# MCP Protocol
tokio-tungstenite = "0.21"        # WebSocket server
serde_json = "1.0"                 # JSON-RPC 2.0 serialization
uuid = { version = "1.0", features = ["v4"] }  # Request IDs

# Existing (reuse)
actix-web = "4.4"                  # HTTP server
sqlx = "0.8"                       # Database
tokio = { version = "1", features = ["full"] }
```

### MCP Protocol Specification
- **Protocol**: JSON-RPC 2.0 over WebSocket
- **Version**: MCP 2024-11-05
- **Transport**: `wss://api.try.direct/mcp` (production)
- **Authentication**: OAuth Bearer token (reuse existing auth)

## Implementation Phases

---

## Phase 1: Foundation (Week 1-2)

### 1.1 MCP Protocol Implementation

**Create core protocol structures:**

```rust
// src/mcp/protocol.rs
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "jsonrpc")]
pub struct JsonRpcRequest {
    pub jsonrpc: String,  // "2.0"
    pub id: Option<Value>,
    pub method: String,
    pub params: Option<Value>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

// MCP-specific types
#[derive(Debug, Serialize, Deserialize)]
pub struct Tool {
    pub name: String,
    pub description: String,
    #[serde(rename = "inputSchema")]
    pub input_schema: Value,  // JSON Schema for parameters
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ToolListResponse {
    pub tools: Vec<Tool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CallToolRequest {
    pub name: String,
    pub arguments: Option<Value>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CallToolResponse {
    pub content: Vec<ToolContent>,
    #[serde(rename = "isError", skip_serializing_if = "Option::is_none")]
    pub is_error: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ToolContent {
    #[serde(rename = "text")]
    Text { text: String },
    #[serde(rename = "image")]
    Image { 
        data: String,  // base64
        #[serde(rename = "mimeType")]
        mime_type: String 
    },
}
```

### 1.2 WebSocket Handler

```rust
// src/mcp/websocket.rs
use actix::{Actor, StreamHandler};
use actix_web::{web, Error, HttpRequest, HttpResponse};
use actix_web_actors::ws;
use tokio_tungstenite::tungstenite::protocol::Message;

pub struct McpWebSocket {
    user: Arc<models::User>,
    session: McpSession,
}

impl Actor for McpWebSocket {
    type Context = ws::WebsocketContext<Self>;
}

impl StreamHandler<Result<ws::Message, ws::ProtocolError>> for McpWebSocket {
    fn handle(&mut self, msg: Result<ws::Message, ws::ProtocolError>, ctx: &mut Self::Context) {
        match msg {
            Ok(ws::Message::Text(text)) => {
                let request: JsonRpcRequest = serde_json::from_str(&text).unwrap();
                let response = self.handle_jsonrpc(request).await;
                ctx.text(serde_json::to_string(&response).unwrap());
            }
            Ok(ws::Message::Close(reason)) => {
                ctx.close(reason);
                ctx.stop();
            }
            _ => {}
        }
    }
}

impl McpWebSocket {
    async fn handle_jsonrpc(&self, req: JsonRpcRequest) -> JsonRpcResponse {
        match req.method.as_str() {
            "initialize" => self.handle_initialize(req).await,
            "tools/list" => self.handle_tools_list(req).await,
            "tools/call" => self.handle_tools_call(req).await,
            _ => JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                id: req.id,
                result: None,
                error: Some(JsonRpcError {
                    code: -32601,
                    message: "Method not found".to_string(),
                    data: None,
                }),
            },
        }
    }
}

// Route registration
pub async fn mcp_websocket(
    req: HttpRequest,
    stream: web::Payload,
    user: web::ReqData<Arc<models::User>>,
    pg_pool: web::Data<PgPool>,
) -> Result<HttpResponse, Error> {
    let ws = McpWebSocket {
        user: user.into_inner(),
        session: McpSession::new(),
    };
    ws::start(ws, &req, stream)
}
```

### 1.3 Tool Registry

```rust
// src/mcp/registry.rs
use std::collections::HashMap;
use async_trait::async_trait;

#[async_trait]
pub trait ToolHandler: Send + Sync {
    async fn execute(
        &self,
        args: Value,
        context: &ToolContext,
    ) -> Result<ToolContent, String>;
    
    fn schema(&self) -> Tool;
}

pub struct ToolRegistry {
    handlers: HashMap<String, Box<dyn ToolHandler>>,
}

impl ToolRegistry {
    pub fn new() -> Self {
        let mut registry = Self {
            handlers: HashMap::new(),
        };
        
        // Register all tools
        registry.register("create_project", Box::new(CreateProjectTool));
        registry.register("list_projects", Box::new(ListProjectsTool));
        registry.register("get_project", Box::new(GetProjectTool));
        registry.register("update_project", Box::new(UpdateProjectTool));
        registry.register("delete_project", Box::new(DeleteProjectTool));
        registry.register("generate_compose", Box::new(GenerateComposeTool));
        registry.register("deploy_project", Box::new(DeployProjectTool));
        registry.register("list_templates", Box::new(ListTemplatesTool));
        registry.register("get_template", Box::new(GetTemplateTool));
        registry.register("list_clouds", Box::new(ListCloudsTool));
        registry.register("suggest_resources", Box::new(SuggestResourcesTool));
        
        registry
    }
    
    pub fn get(&self, name: &str) -> Option<&Box<dyn ToolHandler>> {
        self.handlers.get(name)
    }
    
    pub fn list_tools(&self) -> Vec<Tool> {
        self.handlers.values().map(|h| h.schema()).collect()
    }
}

pub struct ToolContext {
    pub user: Arc<models::User>,
    pub pg_pool: PgPool,
    pub settings: Arc<Settings>,
}
```

### 1.4 Session Management

```rust
// src/mcp/session.rs
use std::collections::HashMap;

pub struct McpSession {
    pub id: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub context: HashMap<String, Value>,  // Store conversation state
}

impl McpSession {
    pub fn new() -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            created_at: chrono::Utc::now(),
            context: HashMap::new(),
        }
    }
    
    pub fn set_context(&mut self, key: String, value: Value) {
        self.context.insert(key, value);
    }
    
    pub fn get_context(&self, key: &str) -> Option<&Value> {
        self.context.get(key)
    }
}
```

**Deliverables:**
- [ ] MCP protocol types in `src/mcp/protocol.rs`
- [ ] WebSocket handler in `src/mcp/websocket.rs`
- [ ] Tool registry in `src/mcp/registry.rs`
- [ ] Session management in `src/mcp/session.rs`
- [ ] Route registration: `web::resource("/mcp").route(web::get().to(mcp_websocket))`

---

## Phase 2: Core Tools (Week 3-4)

### 2.1 Project Management Tools

```rust
// src/mcp/tools/project.rs

pub struct CreateProjectTool;

#[async_trait]
impl ToolHandler for CreateProjectTool {
    async fn execute(&self, args: Value, ctx: &ToolContext) -> Result<ToolContent, String> {
        let form: forms::project::Add = serde_json::from_value(args)
            .map_err(|e| format!("Invalid arguments: {}", e))?;
        
        let project = db::project::insert(
            &ctx.pg_pool,
            &ctx.user.id,
            &form,
        ).await
        .map_err(|e| format!("Database error: {}", e))?;
        
        Ok(ToolContent::Text {
            text: serde_json::to_string(&project).unwrap(),
        })
    }
    
    fn schema(&self) -> Tool {
        Tool {
            name: "create_project".to_string(),
            description: "Create a new application stack project with services, networking, and deployment configuration".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Project name (required)"
                    },
                    "description": {
                        "type": "string",
                        "description": "Project description (optional)"
                    },
                    "apps": {
                        "type": "array",
                        "description": "List of applications/services",
                        "items": {
                            "type": "object",
                            "properties": {
                                "name": { "type": "string" },
                                "dockerImage": {
                                    "type": "object",
                                    "properties": {
                                        "namespace": { "type": "string" },
                                        "repository": { "type": "string" },
                                        "password": { "type": "string" }
                                    },
                                    "required": ["repository"]
                                },
                                "resources": {
                                    "type": "object",
                                    "properties": {
                                        "cpu": { "type": "number", "description": "CPU cores (0-8)" },
                                        "ram": { "type": "number", "description": "RAM in GB (0-16)" },
                                        "storage": { "type": "number", "description": "Storage in GB (0-100)" }
                                    }
                                },
                                "ports": {
                                    "type": "array",
                                    "items": {
                                        "type": "object",
                                        "properties": {
                                            "hostPort": { "type": "number" },
                                            "containerPort": { "type": "number" }
                                        }
                                    }
                                }
                            },
                            "required": ["name", "dockerImage"]
                        }
                    }
                },
                "required": ["name", "apps"]
            }),
        }
    }
}

pub struct ListProjectsTool;

#[async_trait]
impl ToolHandler for ListProjectsTool {
    async fn execute(&self, _args: Value, ctx: &ToolContext) -> Result<ToolContent, String> {
        let projects = db::project::fetch_by_user(&ctx.pg_pool, &ctx.user.id)
            .await
            .map_err(|e| format!("Database error: {}", e))?;
        
        Ok(ToolContent::Text {
            text: serde_json::to_string(&projects).unwrap(),
        })
    }
    
    fn schema(&self) -> Tool {
        Tool {
            name: "list_projects".to_string(),
            description: "List all projects owned by the authenticated user".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {}
            }),
        }
    }
}
```

### 2.2 Template & Discovery Tools

```rust
// src/mcp/tools/templates.rs

pub struct ListTemplatesTool;

#[async_trait]
impl ToolHandler for ListTemplatesTool {
    async fn execute(&self, args: Value, ctx: &ToolContext) -> Result<ToolContent, String> {
        #[derive(Deserialize)]
        struct Args {
            category: Option<String>,
            search: Option<String>,
        }
        
        let params: Args = serde_json::from_value(args).unwrap_or_default();
        
        // Fetch public templates from rating table
        let templates = db::rating::fetch_public_templates(&ctx.pg_pool, params.category)
            .await
            .map_err(|e| format!("Database error: {}", e))?;
        
        // Filter by search term if provided
        let filtered = if let Some(search) = params.search {
            templates.into_iter()
                .filter(|t| t.name.to_lowercase().contains(&search.to_lowercase()))
                .collect()
        } else {
            templates
        };
        
        Ok(ToolContent::Text {
            text: serde_json::to_string(&filtered).unwrap(),
        })
    }
    
    fn schema(&self) -> Tool {
        Tool {
            name: "list_templates".to_string(),
            description: "List available stack templates (WordPress, Node.js, Django, etc.) with ratings and descriptions".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "category": {
                        "type": "string",
                        "enum": ["web", "api", "database", "cms", "ecommerce"],
                        "description": "Filter by category (optional)"
                    },
                    "search": {
                        "type": "string",
                        "description": "Search templates by name (optional)"
                    }
                }
            }),
        }
    }
}

pub struct SuggestResourcesTool;

#[async_trait]
impl ToolHandler for SuggestResourcesTool {
    async fn execute(&self, args: Value, _ctx: &ToolContext) -> Result<ToolContent, String> {
        #[derive(Deserialize)]
        struct Args {
            app_type: String,
            expected_traffic: Option<String>,  // "low", "medium", "high"
        }
        
        let params: Args = serde_json::from_value(args)
            .map_err(|e| format!("Invalid arguments: {}", e))?;
        
        // Simple heuristic-based suggestions
        let (cpu, ram, storage) = match params.app_type.to_lowercase().as_str() {
            "wordpress" | "cms" => (1, 2, 20),
            "nodejs" | "express" => (1, 1, 10),
            "django" | "flask" => (2, 2, 15),
            "nextjs" | "react" => (1, 2, 10),
            "mysql" | "postgresql" => (2, 4, 50),
            "redis" | "memcached" => (1, 1, 5),
            "nginx" | "traefik" => (1, 0.5, 5),
            _ => (1, 1, 10),  // default
        };
        
        // Adjust for traffic
        let multiplier = match params.expected_traffic.as_deref() {
            Some("high") => 2.0,
            Some("medium") => 1.5,
            _ => 1.0,
        };
        
        let suggestion = serde_json::json!({
            "cpu": (cpu as f64 * multiplier).ceil() as i32,
            "ram": (ram as f64 * multiplier).ceil() as i32,
            "storage": (storage as f64 * multiplier).ceil() as i32,
            "recommendation": format!(
                "For {} with {} traffic: {}x{} CPU, {} GB RAM, {} GB storage",
                params.app_type,
                params.expected_traffic.as_deref().unwrap_or("low"),
                (cpu as f64 * multiplier).ceil(),
                if multiplier > 1.0 { "vCPU" } else { "core" },
                (ram as f64 * multiplier).ceil(),
                (storage as f64 * multiplier).ceil()
            )
        });
        
        Ok(ToolContent::Text {
            text: serde_json::to_string(&suggestion).unwrap(),
        })
    }
    
    fn schema(&self) -> Tool {
        Tool {
            name: "suggest_resources".to_string(),
            description: "Suggest appropriate CPU, RAM, and storage limits for an application type".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "app_type": {
                        "type": "string",
                        "description": "Application type (e.g., 'wordpress', 'nodejs', 'postgresql')"
                    },
                    "expected_traffic": {
                        "type": "string",
                        "enum": ["low", "medium", "high"],
                        "description": "Expected traffic level (optional, default: low)"
                    }
                },
                "required": ["app_type"]
            }),
        }
    }
}
```

**Deliverables:**
- [ ] Project CRUD tools (create, list, get, update, delete)
- [ ] Deployment tools (generate_compose, deploy)
- [ ] Template discovery tools (list_templates, get_template)
- [ ] Resource suggestion tool
- [ ] Cloud provider tools (list_clouds, add_cloud)

---

## Phase 3: Advanced Features (Week 5-6)

### 3.1 Context & State Management

```rust
// Store partial project data during multi-turn conversations
session.set_context("draft_project".to_string(), serde_json::json!({
    "name": "My API",
    "apps": [
        {
            "name": "api",
            "dockerImage": { "repository": "node:18-alpine" }
        }
    ],
    "step": 2  // User is on step 2 of 5
}));
```

### 3.2 Validation Tools

```rust
pub struct ValidateDomainTool;

#[async_trait]
impl ToolHandler for ValidateDomainTool {
    async fn execute(&self, args: Value, _ctx: &ToolContext) -> Result<ToolContent, String> {
        #[derive(Deserialize)]
        struct Args {
            domain: String,
        }
        
        let params: Args = serde_json::from_value(args)
            .map_err(|e| format!("Invalid arguments: {}", e))?;
        
        // Simple regex validation
        let domain_regex = regex::Regex::new(r"^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$").unwrap();
        let is_valid = domain_regex.is_match(&params.domain);
        
        let result = serde_json::json!({
            "domain": params.domain,
            "valid": is_valid,
            "message": if is_valid {
                "Domain format is valid"
            } else {
                "Invalid domain format. Use lowercase letters, numbers, hyphens, and dots only"
            }
        });
        
        Ok(ToolContent::Text {
            text: serde_json::to_string(&result).unwrap(),
        })
    }
    
    fn schema(&self) -> Tool {
        Tool {
            name: "validate_domain".to_string(),
            description: "Validate domain name format".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "Domain to validate (e.g., 'example.com')"
                    }
                },
                "required": ["domain"]
            }),
        }
    }
}
```

### 3.3 Deployment Status Tools

```rust
pub struct GetDeploymentStatusTool;

#[async_trait]
impl ToolHandler for GetDeploymentStatusTool {
    async fn execute(&self, args: Value, ctx: &ToolContext) -> Result<ToolContent, String> {
        #[derive(Deserialize)]
        struct Args {
            deployment_id: i32,
        }
        
        let params: Args = serde_json::from_value(args)
            .map_err(|e| format!("Invalid arguments: {}", e))?;
        
        let deployment = db::deployment::fetch(&ctx.pg_pool, params.deployment_id)
            .await
            .map_err(|e| format!("Database error: {}", e))?;
        
        Ok(ToolContent::Text {
            text: serde_json::to_string(&deployment).unwrap(),
        })
    }
    
    fn schema(&self) -> Tool {
        Tool {
            name: "get_deployment_status".to_string(),
            description: "Get current deployment status and details".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "deployment_id": {
                        "type": "number",
                        "description": "Deployment ID"
                    }
                },
                "required": ["deployment_id"]
            }),
        }
    }
}
```

**Deliverables:**
- [ ] Session context persistence
- [ ] Domain validation tool
- [ ] Port validation tool
- [ ] Git repository parsing tool
- [ ] Deployment status monitoring tool

---

## Phase 4: Security & Production (Week 7-8)

### 4.1 Authentication & Authorization

```rust
// Reuse existing OAuth middleware
// src/mcp/websocket.rs

pub async fn mcp_websocket(
    req: HttpRequest,
    stream: web::Payload,
    user: web::ReqData<Arc<models::User>>,  // ← Injected by auth middleware
    pg_pool: web::Data<PgPool>,
) -> Result<HttpResponse, Error> {
    // User is already authenticated via Bearer token
    // Casbin rules apply: only admin/user roles can access MCP
    
    let ws = McpWebSocket {
        user: user.into_inner(),
        session: McpSession::new(),
    };
    ws::start(ws, &req, stream)
}
```

**Casbin Rules for MCP:**
```sql
-- migrations/20251228000000_casbin_mcp_rules.up.sql
INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
VALUES 
  ('p', 'group_admin', '/mcp', 'GET', '', '', ''),
  ('p', 'group_user', '/mcp', 'GET', '', '', '')
ON CONFLICT ON CONSTRAINT unique_key_sqlx_adapter DO NOTHING;
```

### 4.2 Rate Limiting

```rust
// src/mcp/rate_limit.rs
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub struct RateLimiter {
    limits: Arc<Mutex<HashMap<String, Vec<Instant>>>>,
    max_requests: usize,
    window: Duration,
}

impl RateLimiter {
    pub fn new(max_requests: usize, window: Duration) -> Self {
        Self {
            limits: Arc::new(Mutex::new(HashMap::new())),
            max_requests,
            window,
        }
    }
    
    pub fn check(&self, user_id: &str) -> Result<(), String> {
        let mut limits = self.limits.lock().unwrap();
        let now = Instant::now();
        
        let requests = limits.entry(user_id.to_string()).or_insert_with(Vec::new);
        
        // Remove expired entries
        requests.retain(|&time| now.duration_since(time) < self.window);
        
        if requests.len() >= self.max_requests {
            return Err(format!(
                "Rate limit exceeded: {} requests per {} seconds",
                self.max_requests,
                self.window.as_secs()
            ));
        }
        
        requests.push(now);
        Ok(())
    }
}

// Usage in McpWebSocket
impl McpWebSocket {
    async fn handle_tools_call(&self, req: JsonRpcRequest) -> JsonRpcResponse {
        // Rate limit: 100 tool calls per minute per user
        if let Err(msg) = self.rate_limiter.check(&self.user.id) {
            return JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                id: req.id,
                result: None,
                error: Some(JsonRpcError {
                    code: -32000,
                    message: msg,
                    data: None,
                }),
            };
        }
        
        // ... proceed with tool execution
    }
}
```

### 4.3 Error Handling & Logging

```rust
// Enhanced error responses with tracing
impl McpWebSocket {
    async fn handle_tools_call(&self, req: JsonRpcRequest) -> JsonRpcResponse {
        let call_req: CallToolRequest = match serde_json::from_value(req.params.unwrap()) {
            Ok(r) => r,
            Err(e) => {
                tracing::error!("Invalid tool call params: {:?}", e);
                return JsonRpcResponse {
                    jsonrpc: "2.0".to_string(),
                    id: req.id,
                    result: None,
                    error: Some(JsonRpcError {
                        code: -32602,
                        message: "Invalid params".to_string(),
                        data: Some(serde_json::json!({ "error": e.to_string() })),
                    }),
                };
            }
        };
        
        let tool_span = tracing::info_span!("mcp_tool_call", tool = %call_req.name, user = %self.user.id);
        let _enter = tool_span.enter();
        
        match self.registry.get(&call_req.name) {
            Some(handler) => {
                match handler.execute(
                    call_req.arguments.unwrap_or(serde_json::json!({})),
                    &self.context(),
                ).await {
                    Ok(content) => {
                        tracing::info!("Tool executed successfully");
                        JsonRpcResponse {
                            jsonrpc: "2.0".to_string(),
                            id: req.id,
                            result: Some(serde_json::to_value(CallToolResponse {
                                content: vec![content],
                                is_error: None,
                            }).unwrap()),
                            error: None,
                        }
                    }
                    Err(e) => {
                        tracing::error!("Tool execution failed: {}", e);
                        JsonRpcResponse {
                            jsonrpc: "2.0".to_string(),
                            id: req.id,
                            result: Some(serde_json::to_value(CallToolResponse {
                                content: vec![ToolContent::Text {
                                    text: format!("Error: {}", e),
                                }],
                                is_error: Some(true),
                            }).unwrap()),
                            error: None,
                        }
                    }
                }
            }
            None => {
                tracing::warn!("Unknown tool requested: {}", call_req.name);
                JsonRpcResponse {
                    jsonrpc: "2.0".to_string(),
                    id: req.id,
                    result: None,
                    error: Some(JsonRpcError {
                        code: -32601,
                        message: format!("Tool not found: {}", call_req.name),
                        data: None,
                    }),
                }
            }
        }
    }
}
```

**Deliverables:**
- [ ] Casbin rules for MCP endpoint
- [ ] Rate limiting (100 calls/min per user)
- [ ] Comprehensive error handling
- [ ] Structured logging with tracing
- [ ] Input validation for all tools

---

## Phase 5: Testing & Documentation (Week 9)

### 5.1 Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_create_project_tool() {
        let tool = CreateProjectTool;
        let ctx = create_test_context().await;
        
        let args = serde_json::json!({
            "name": "Test Project",
            "apps": [{
                "name": "web",
                "dockerImage": { "repository": "nginx" }
            }]
        });
        
        let result = tool.execute(args, &ctx).await;
        assert!(result.is_ok());
        
        let ToolContent::Text { text } = result.unwrap();
        let project: models::Project = serde_json::from_str(&text).unwrap();
        assert_eq!(project.name, "Test Project");
    }
    
    #[tokio::test]
    async fn test_list_templates_tool() {
        let tool = ListTemplatesTool;
        let ctx = create_test_context().await;
        
        let result = tool.execute(serde_json::json!({}), &ctx).await;
        assert!(result.is_ok());
    }
}
```

### 5.2 Integration Tests

```rust
// tests/mcp_integration.rs
use actix_web::test;
use tokio_tungstenite::connect_async;

#[actix_web::test]
async fn test_mcp_websocket_connection() {
    let app = spawn_app().await;
    
    let ws_url = format!("ws://{}/mcp", app.address);
    let (ws_stream, _) = connect_async(ws_url).await.unwrap();
    
    // Send initialize request
    let init_msg = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {}
        }
    });
    
    // ... test flow
}

#[actix_web::test]
async fn test_create_project_via_mcp() {
    // Test full create project flow via MCP
}
```

### 5.3 Documentation

**API Documentation:**
- Generate OpenAPI/Swagger spec for MCP tools
- Document all tool schemas with examples
- Create integration guide for frontend developers

**Example Documentation:**
```markdown
## MCP Tool: create_project

**Description**: Create a new application stack project

**Parameters:**
```json
{
  "name": "My WordPress Site",
  "apps": [
    {
      "name": "wordpress",
      "dockerImage": {
        "repository": "wordpress",
        "tag": "latest"
      },
      "resources": {
        "cpu": 2,
        "ram": 4,
        "storage": 20
      },
      "ports": [
        { "hostPort": 80, "containerPort": 80 }
      ]
    }
  ]
}
```

**Response:**
```json
{
  "id": 123,
  "name": "My WordPress Site",
  "user_id": "user_abc",
  "created_at": "2025-12-27T10:00:00Z",
  ...
}
```
```

**Deliverables:**
- [ ] Unit tests for all tools (>80% coverage)
- [ ] Integration tests for WebSocket connection
- [ ] End-to-end tests for tool execution flow
- [ ] API documentation (MCP tool schemas)
- [ ] Integration guide for frontend

---

## Deployment Configuration

### Update `startup.rs`

```rust
// src/startup.rs
use crate::mcp;

pub async fn run(
    listener: TcpListener,
    pg_pool: Pool<Postgres>,
    settings: Settings,
) -> Result<Server, std::io::Error> {
    // ... existing setup ...
    
    // Initialize MCP registry
    let mcp_registry = web::Data::new(mcp::ToolRegistry::new());
    
    let server = HttpServer::new(move || {
        App::new()
            // ... existing middleware and routes ...
            
            // Add MCP WebSocket endpoint
            .service(
                web::resource("/mcp")
                    .route(web::get().to(mcp::mcp_websocket))
            )
            .app_data(mcp_registry.clone())
    })
    .listen(listener)?
    .run();
    
    Ok(server)
}
```

### Update `Cargo.toml`

```toml
[dependencies]
tokio-tungstenite = "0.21"
uuid = { version = "1.0", features = ["v4", "serde"] }
async-trait = "0.1"
regex = "1.10"

# Consider adding MCP SDK if available
# mcp-server = "0.1"  # Hypothetical official SDK
```

---

## Monitoring & Metrics

### Key Metrics to Track

```rust
// src/mcp/metrics.rs
use prometheus::{IntCounterVec, HistogramVec, Registry};

pub struct McpMetrics {
    pub tool_calls_total: IntCounterVec,
    pub tool_duration: HistogramVec,
    pub websocket_connections: IntCounterVec,
    pub errors_total: IntCounterVec,
}

impl McpMetrics {
    pub fn new(registry: &Registry) -> Self {
        let tool_calls_total = IntCounterVec::new(
            prometheus::Opts::new("mcp_tool_calls_total", "Total MCP tool calls"),
            &["tool", "user_id", "status"]
        ).unwrap();
        registry.register(Box::new(tool_calls_total.clone())).unwrap();
        
        // ... register other metrics
        
        Self {
            tool_calls_total,
            // ...
        }
    }
}
```

**Metrics to expose:**
- `mcp_tool_calls_total{tool, user_id, status}` - Counter
- `mcp_tool_duration_seconds{tool}` - Histogram
- `mcp_websocket_connections_active` - Gauge
- `mcp_errors_total{tool, error_type}` - Counter

---

## Complete Tool List (Initial Release)

### Project Management (7 tools)
1. ✅ `create_project` - Create new project
2. ✅ `list_projects` - List user's projects
3. ✅ `get_project` - Get project details
4. ✅ `update_project` - Update project
5. ✅ `delete_project` - Delete project
6. ✅ `generate_compose` - Generate docker-compose.yml
7. ✅ `deploy_project` - Deploy to cloud

### Template & Discovery (3 tools)
8. ✅ `list_templates` - List available templates
9. ✅ `get_template` - Get template details
10. ✅ `suggest_resources` - Suggest resource limits

### Cloud Management (2 tools)
11. ✅ `list_clouds` - List cloud providers
12. ✅ `add_cloud` - Add cloud credentials

### Validation (3 tools)
13. ✅ `validate_domain` - Validate domain format
14. ✅ `validate_ports` - Validate port configuration
15. ✅ `parse_git_repo` - Parse Git repository URL

### Deployment (2 tools)
16. ✅ `list_deployments` - List deployments
17. ✅ `get_deployment_status` - Get deployment status

**Total: 17 tools for MVP**

---

## Success Criteria

### Functional Requirements
- [ ] All 17 tools implemented and tested
- [ ] WebSocket connection stable for >1 hour
- [ ] Handle 100 concurrent WebSocket connections
- [ ] Rate limiting prevents abuse
- [ ] Authentication/authorization enforced

### Performance Requirements
- [ ] Tool execution <500ms (p95)
- [ ] WebSocket latency <50ms
- [ ] Support 10 tool calls/second per user
- [ ] No memory leaks in long-running sessions

### Security Requirements
- [ ] OAuth authentication required
- [ ] Casbin ACL enforced
- [ ] Input validation on all parameters
- [ ] SQL injection protection (via sqlx)
- [ ] Rate limiting (100 calls/min per user)

---

## Migration Path

1. **Week 1-2**: Core protocol + 3 basic tools (create_project, list_projects, list_templates)
2. **Week 3-4**: All 17 tools implemented
3. **Week 5-6**: Advanced features (validation, suggestions)
4. **Week 7-8**: Security hardening + production readiness
5. **Week 9**: Testing + documentation
6. **Week 10**: Beta release with frontend integration

---

## Questions & Decisions

### Open Questions
1. **Session persistence**: Store in PostgreSQL or Redis?
   - **Recommendation**: Redis for ephemeral session data
   
2. **Tool versioning**: How to handle breaking changes?
   - **Recommendation**: Version in tool name (`create_project_v1`)
   
3. **Error recovery**: Retry failed tool calls?
   - **Recommendation**: Let AI/client decide on retry

### Technical Decisions
- ✅ Use tokio-tungstenite for WebSocket
- ✅ JSON-RPC 2.0 over WebSocket (not HTTP SSE)
- ✅ Reuse existing auth middleware
- ✅ Store sessions in memory (move to Redis later)
- ✅ Rate limit at WebSocket level (not per-tool)

---

## Contact & Resources

**References:**
- MCP Specification: https://spec.modelcontextprotocol.io/
- Example Rust MCP Server: https://github.com/modelcontextprotocol/servers
- Actix WebSocket: https://actix.rs/docs/websockets/

**Team Contacts:**
- Backend Lead: [Your Name]
- Frontend Integration: [Frontend Lead]
- DevOps: [DevOps Contact]
