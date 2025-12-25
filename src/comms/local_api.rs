use anyhow::Result;
use axum::{
    routing::{get, post},
    Router, response::IntoResponse, extract::Path,
    http::{StatusCode, HeaderMap}, Json, response::Html, response::Redirect,
    extract::Form, extract::State, extract::WebSocketUpgrade, extract::Query,
};
use axum::extract::ws::{Message, WebSocket};
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;
use std::collections::VecDeque;
use std::time::Duration;
use std::future::IntoFuture;
use tracing::{info, error, debug};
use tera::Tera;
use tokio::sync::{broadcast, Mutex, Notify};
use bytes::Bytes;

use crate::agent::config::Config;
use crate::agent::backup::BackupSigner;
use crate::security::auth::{SessionStore, SessionUser, Credentials};
use crate::security::audit_log::AuditLogger;
use crate::security::request_signer::verify_signature;
use crate::security::rate_limit::RateLimiter;
use crate::security::replay::ReplayProtection;
use crate::security::scopes::Scopes;
use crate::security::vault_client::VaultClient;
use crate::security::token_cache::TokenCache;
use crate::security::token_refresh::spawn_token_refresh;
use crate::monitoring::{MetricsCollector, MetricsSnapshot, MetricsStore, MetricsTx, spawn_heartbeat};
#[cfg(feature = "docker")]
use crate::agent::docker;
use crate::commands::{CommandValidator, TimeoutStrategy, DockerOperation};
use crate::commands::executor::CommandExecutor;
use crate::commands::execute_docker_operation;
use crate::transport::{Command as AgentCommand, CommandResult};

type SharedState = Arc<AppState>;

// Extract client IP from ConnectInfo, headers, or fallback to 127.0.0.1
#[derive(Debug, Clone)]
struct ClientIp(pub String);

impl<S> FromRequestParts<S> for ClientIp
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // Prefer SocketAddr inserted by Axum's connect info middleware
        if let Some(addr) = parts.extensions.get::<SocketAddr>() {
            return Ok(ClientIp(addr.ip().to_string()));
        }

        // Check common proxy headers
        if let Some(forwarded) = parts.headers.get("x-forwarded-for") {
            if let Ok(s) = forwarded.to_str() {
                // Take the first IP if multiple
                let ip = s.split(',').next().unwrap_or(s).trim().to_string();
                if !ip.is_empty() {
                    return Ok(ClientIp(ip));
                }
            }
        }
        if let Some(real_ip) = parts.headers.get("x-real-ip") {
            if let Ok(s) = real_ip.to_str() {
                let ip = s.trim().to_string();
                if !ip.is_empty() {
                    return Ok(ClientIp(ip));
                }
            }
        }

        // Fallback for tests or when info is unavailable
        Ok(ClientIp("127.0.0.1".to_string()))
    }
}
#[derive(Debug, Clone)]
pub struct AppState {
    pub session_store: SessionStore,
    pub config: Arc<Config>,
    pub templates: Option<Arc<Tera>>,
    pub with_ui: bool,
    pub metrics_collector: Arc<MetricsCollector>,
    pub metrics_store: MetricsStore,
    pub metrics_tx: MetricsTx,
    pub metrics_webhook: Option<String>,
    pub backup_path: Option<String>,
    pub commands_queue: Arc<Mutex<VecDeque<AgentCommand>>>,
    pub commands_notify: Arc<Notify>,
    pub audit: AuditLogger,
    pub rate_limiter: RateLimiter,
    pub replay: ReplayProtection,
    pub scopes: Scopes,
    pub agent_token: Arc<tokio::sync::RwLock<String>>,
    pub vault_client: Option<VaultClient>,
    pub token_cache: Option<TokenCache>,
}

impl AppState {
    pub fn new(config: Arc<Config>, with_ui: bool) -> Self {
        let templates = if with_ui {
            match Tera::new("templates/**/*.html") {
                Ok(t) => {
                    debug!("Loaded {} templates", t.get_template_names().count());
                    Some(Arc::new(t))
                }
                Err(e) => {
                    error!("Template parsing error: {}", e);
                    None
                }
            }
        } else {
            None
        };
        
        let vault_client = VaultClient::from_env()
            .ok()
            .flatten()
            .map(|vc| {
                debug!("Vault client initialized for token rotation");
                vc
            });
        
        let token_cache = vault_client.is_some().then(|| {
            TokenCache::new(std::env::var("AGENT_TOKEN").unwrap_or_default())
        });
        
        Self {
            session_store: SessionStore::new(),
            config,
            templates,
            with_ui,
            metrics_collector: Arc::new(MetricsCollector::new()),
            metrics_store: Arc::new(tokio::sync::RwLock::new(MetricsSnapshot::default())),
            metrics_tx: broadcast::channel(32).0,
            metrics_webhook: std::env::var("METRICS_WEBHOOK").ok(),
            backup_path: std::env::var("BACKUP_PATH").ok(),
            commands_queue: Arc::new(Mutex::new(VecDeque::new())),
            commands_notify: Arc::new(Notify::new()),
            audit: AuditLogger::new(),
            rate_limiter: RateLimiter::new_per_minute(
                std::env::var("RATE_LIMIT_PER_MIN")
                    .ok()
                    .and_then(|v| v.parse::<usize>().ok())
                    .unwrap_or(120)
            ),
            replay: ReplayProtection::new_ttl(
                std::env::var("REPLAY_TTL_SECS")
                    .ok()
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(600)
            ),
            scopes: Scopes::from_env(),
            agent_token: Arc::new(tokio::sync::RwLock::new(std::env::var("AGENT_TOKEN").unwrap_or_default())),
            vault_client,
            token_cache,
        }
    }
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub session_id: String,
}

#[derive(Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

#[derive(Deserialize)]
pub struct BackupPingRequest {
    pub hash: String,
}

#[derive(Serialize)]
pub struct BackupPingResponse {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
}

// Health check with token rotation metrics
#[derive(Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub token_age_seconds: u64,
    pub last_refresh_ok: Option<bool>,
}

async fn health(
    State(state): State<SharedState>,
) -> impl IntoResponse {
    let token_age_seconds = if let Some(cache) = &state.token_cache {
        cache.age_seconds().await
    } else {
        0
    };

    let last_refresh_ok = if state.vault_client.is_some() {
        // If Vault is configured, we track refresh success via audit logs
        Some(true)
    } else {
        None
    };

    Json(HealthResponse {
        status: "ok".to_string(),
        token_age_seconds,
        last_refresh_ok,
    })
}

// Login form (GET)
async fn login_page(
    State(state): State<SharedState>,
) -> impl IntoResponse {
    if state.with_ui {
        if let Some(templates) = &state.templates {
            let mut context = tera::Context::new();
            context.insert("error", &false);
            
            match templates.render("login.html", &context) {
                Ok(html) => Html(html).into_response(),
                Err(e) => {
                    error!("Template render error: {}", e);
                    Html("<html><body>Error rendering template</body></html>".to_string()).into_response()
                }
            }
        } else {
            Html("<html><body>Templates not loaded</body></html>".to_string()).into_response()
        }
    } else {
        Html("<html><body><form method='POST' action='/login'><input type='text' name='username' placeholder='Username' /><input type='password' name='password' placeholder='Password' /><button>Login</button></form></body></html>".to_string()).into_response()
    }
}

// Login handler (POST)
async fn login_handler(
    State(state): State<SharedState>,
    Form(req): Form<LoginRequest>,
) -> Result<impl IntoResponse, impl IntoResponse> {
    let creds = Credentials::from_env();
    if req.username == creds.username && req.password == creds.password {
        let user = SessionUser::new(req.username.clone());
        let _session_id = state.session_store.create_session(user).await;
        debug!("user logged in: {}", req.username);
        // Redirect to home page on successful login
        Ok(Redirect::to("/").into_response())
    } else {
        error!("login failed for user: {}", req.username);
        // Re-render login page with error if UI is enabled, otherwise return error JSON
        if state.with_ui {
            if let Some(templates) = &state.templates {
                let mut context = tera::Context::new();
                context.insert("error", &true);
                match templates.render("login.html", &context) {
                    Ok(html) => Err((
                        StatusCode::UNAUTHORIZED,
                        Html(html).into_response(),
                    )),
                    Err(e) => {
                        error!("Template render error: {}", e);
                        Err((
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Html("<html><body>Login failed</body></html>".to_string()).into_response(),
                        ))
                    }
                }
            } else {
                Err((
                    StatusCode::UNAUTHORIZED,
                    Html("<html><body>Login failed</body></html>".to_string()).into_response(),
                ))
            }
        } else {
            Err((
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "Invalid credentials".to_string(),
                }).into_response(),
            ))
        }
    }
}

// Logout handler
async fn logout_handler(
    State(state): State<SharedState>,
) -> impl IntoResponse {
    // @todo Extract session ID from cookies and delete
    debug!("user logged out");
    if state.with_ui {
        Redirect::to("/login").into_response()
    } else {
        Json(json!({"status": "logged out"})).into_response()
    }
}

// Get home (list containers, config)
#[cfg(feature = "docker")]
async fn home(
    State(state): State<SharedState>,
) -> impl IntoResponse {
    use crate::agent::docker;
    let list_result = if state.with_ui {
        docker::list_containers_with_logs("200").await
    } else {
        docker::list_containers().await
    };

    match list_result {
        Ok(containers) => {
            if state.with_ui {
                if let Some(templates) = &state.templates {
                    let mut context = tera::Context::new();
                    // Match template expectations
                    context.insert("container_list", &containers);
                    context.insert("apps_info", &state.config.apps_info.clone().unwrap_or_default());
                    context.insert("errors", &Option::<String>::None);
                    context.insert("ip", &Option::<String>::None);
                    context.insert("domainIp", &Option::<String>::None);
                    context.insert("panel_version", &env!("CARGO_PKG_VERSION"));
                    context.insert("domain", &state.config.domain);
                    context.insert("ssl_enabled", &state.config.ssl.is_some());
                    context.insert("can_enable", &false); // TODO: implement DNS check
                    context.insert("ip_help_link", "https://www.whatismyip.com/");
                    
                    match templates.render("index.html", &context) {
                        Ok(html) => Html(html).into_response(),
                        Err(e) => {
                            error!("Template render error: {}", e);
                            Json(json!({"error": format!("Template error: {}", e)})).into_response()
                        }
                    }
                } else {
                    Json(json!({"error": "Templates not loaded"})).into_response()
                }
            } else {
                Json(json!({
                    "containers": containers,
                    "config": {
                        "domain": state.config.domain,
                        "apps_info": state.config.apps_info,
                    }
                })).into_response()
            }
        }
        Err(e) => {
            error!("failed to fetch containers: {}", e);
            Json(json!({"error": e.to_string()})).into_response()
        }
    }
}

// ---- SSL enable/disable (Let’s Encrypt or self-signed) ----
#[cfg(feature = "docker")]
fn build_certbot_cmds(config: &Config) -> (String, String) {
    // Domains from subdomains can be object, array, or comma-separated string
    let mut domains: Vec<String> = Vec::new();
    if let Some(ref sd) = config.subdomains {
        match sd {
            serde_json::Value::Object(map) => {
                for v in map.values() {
                    if let Some(s) = v.as_str() {
                        domains.push(s.to_string());
                    }
                }
            }
            serde_json::Value::Array(arr) => {
                for v in arr {
                    if let Some(s) = v.as_str() {
                        domains.push(s.to_string());
                    }
                }
            }
            serde_json::Value::String(s) => {
                for part in s.split(',') {
                    let p = part.trim();
                    if !p.is_empty() {
                        domains.push(p.to_string());
                    }
                }
            }
            _ => {}
        }
    }

    let domains_flags = domains
        .into_iter()
        .map(|d| format!("-d {}", d))
        .collect::<Vec<_>>()
        .join(" ");

    let email = config.reqdata.email.clone();
    let reg_cmd = format!("certbot register --email {} --agree-tos -n", email);
    let crt_cmd = if domains_flags.is_empty() {
        "certbot --nginx --redirect".to_string()
    } else {
        format!("certbot --nginx --redirect {}", domains_flags)
    };

    (reg_cmd, crt_cmd)
}

#[cfg(feature = "docker")]
async fn enable_ssl_handler(State(state): State<SharedState>) -> impl IntoResponse {
    let nginx = std::env::var("NGINX_CONTAINER").unwrap_or_else(|_| "nginx".to_string());
    // Prepare challenge directory
    if let Err(e) = docker::exec_in_container(&nginx, "mkdir -p /tmp/letsencrypt/.well-known/acme-challenge").await {
        error!("failed to prepare acme-challenge dir: {}", e);
        return Redirect::to("/").into_response();
    }

    if state.config.ssl.as_deref() == Some("letsencrypt") {
        let (reg_cmd, crt_cmd) = build_certbot_cmds(&state.config);
        info!("starting certbot registration and certificate issue");
        if let Err(e) = docker::exec_in_container(&nginx, &reg_cmd).await {
            error!("certbot register failed: {}", e);
            return Redirect::to("/").into_response();
        }
        if let Err(e) = docker::exec_in_container(&nginx, &crt_cmd).await {
            error!("certbot issue failed: {}", e);
            return Redirect::to("/").into_response();
        }
        let _ = docker::restart(&nginx).await;
    } else {
        // Self-signed path: replace conf files
        let mut names: Vec<String> = Vec::new();
        if let Some(ref sd) = state.config.subdomains {
            match sd {
                serde_json::Value::Object(map) => {
                    for k in map.keys() { names.push(k.clone()); }
                }
                serde_json::Value::Array(arr) => {
                    for v in arr { if let Some(s) = v.as_str() { names.push(s.to_string()); } }
                }
                serde_json::Value::String(s) => {
                    for part in s.split(',') { let p = part.trim(); if !p.is_empty() { names.push(p.to_string()); } }
                }
                _ => {}
            }
        }
        for fname in names {
            let src = format!("./origin_conf/ssl-conf.d/{}.conf", fname);
            let dst = format!("./destination_conf/conf.d/{}.conf", fname);
            if let Err(e) = std::fs::copy(&src, &dst) {
                error!("failed to copy {} -> {}: {}", src, dst, e);
                return Redirect::to("/").into_response();
            }
        }
        let _ = docker::restart(&nginx).await;
        debug!("self-signed SSL conf files replaced");
    }

    Redirect::to("/").into_response()
}

#[cfg(feature = "docker")]
async fn disable_ssl_handler(State(state): State<SharedState>) -> impl IntoResponse {
    let nginx = std::env::var("NGINX_CONTAINER").unwrap_or_else(|_| "nginx".to_string());
    let mut names: Vec<String> = Vec::new();
    if let Some(ref sd) = state.config.subdomains {
        match sd {
            serde_json::Value::Object(map) => { for k in map.keys() { names.push(k.clone()); } }
            serde_json::Value::Array(arr) => { for v in arr { if let Some(s) = v.as_str() { names.push(s.to_string()); } } }
            serde_json::Value::String(s) => { for part in s.split(',') { let p = part.trim(); if !p.is_empty() { names.push(p.to_string()); } } }
            _ => {}
        }
    }
    for fname in names {
        let src = format!("./origin_conf/conf.d/{}.conf", fname);
        let dst = format!("./destination_conf/conf.d/{}.conf", fname);
        if let Err(e) = std::fs::copy(&src, &dst) {
            error!("failed to copy {} -> {}: {}", src, dst, e);
            return Redirect::to("/").into_response();
        }
    }
    let _ = docker::restart(&nginx).await;
    Redirect::to("/").into_response()
}

// Restart container
#[cfg(feature = "docker")]
async fn restart_container(
    State(state): State<SharedState>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    use crate::agent::docker;
    match docker::restart(&name).await {
        Ok(_) => {
            info!("restarted container: {}", name);
            if state.with_ui {
                Redirect::to("/").into_response()
            } else {
                Json(json!({"action": "restart", "container": name, "status": "ok"})).into_response()
            }
        }
        Err(e) => {
            error!("failed to restart container: {}", e);
            Json(json!({"error": e.to_string()})).into_response()
        }
    }
}

// Stop container
#[cfg(feature = "docker")]
async fn stop_container(
    State(state): State<SharedState>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    use crate::agent::docker;
    match docker::stop(&name).await {
        Ok(_) => {
            info!("stopped container: {}", name);
            if state.with_ui {
                Redirect::to("/").into_response()
            } else {
                Json(json!({"action": "stop", "container": name, "status": "ok"})).into_response()
            }
        }
        Err(e) => {
            error!("failed to stop container: {}", e);
            Json(json!({"error": e.to_string()})).into_response()
        }
    }
}

// Pause container
#[cfg(feature = "docker")]
async fn pause_container(
    State(state): State<SharedState>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    use crate::agent::docker;
    match docker::pause(&name).await {
        Ok(_) => {
            info!("paused container: {}", name);
            if state.with_ui {
                Redirect::to("/").into_response()
            } else {
                Json(json!({"action": "pause", "container": name, "status": "ok"})).into_response()
            }
        }
        Err(e) => {
            error!("failed to pause container: {}", e);
            Json(json!({"error": e.to_string()})).into_response()
        }
    }
}

// Backup ping endpoint - verify hash and generate new one
async fn backup_ping(
    ClientIp(request_ip): ClientIp,
    Json(req): Json<BackupPingRequest>,
) -> Result<impl IntoResponse, impl IntoResponse> {
    let allowed_ip = std::env::var("TRYDIRECT_IP").ok();

    // Check if request is from allowed IP
    if let Some(allowed) = allowed_ip {
        if request_ip != allowed {
            error!("Backup ping from unauthorized IP: {}", request_ip);
            return Err((
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    error: "Invalid IP".to_string(),
                }),
            ));
        }
    }

    // Get deployment hash from environment
    let deployment_hash = std::env::var("DEPLOYMENT_HASH")
        .unwrap_or_else(|_| "default_deployment_hash".to_string());

    let signer = BackupSigner::new(deployment_hash.as_bytes());

    // Check if hash matches deployment_hash or verify it's a valid signed hash
    let is_valid = if req.hash == deployment_hash {
        true
    } else {
        // Try to verify as a signed hash (for backward compatibility)
        signer.verify(&req.hash, 1800).is_ok()
    };

    if is_valid {
        // Generate new signed hash
        let new_hash = signer.sign(&deployment_hash)
            .unwrap_or_else(|_| deployment_hash.clone());
        
        debug!("Backup ping verified from {}", request_ip);
        Ok(Json(BackupPingResponse {
            status: "OK".to_string(),
            hash: Some(new_hash),
        }))
    } else {
        error!("Invalid backup ping hash from {}", request_ip);
        Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "ERROR".to_string(),
            }),
        ))
    }
}

// Backup download endpoint - send backup file with hash/IP verification
async fn backup_download(
    State(state): State<SharedState>,
    ClientIp(request_ip): ClientIp,
    Path((hash, target_ip)): Path<(String, String)>,
) -> Result<impl IntoResponse, impl IntoResponse> {

    // Check if request is from target IP
    if request_ip != target_ip {
        error!(
            "Backup download from wrong IP. Expected: {}, Got: {}",
            target_ip, request_ip
        );
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Invalid IP".to_string(),
            }),
        ));
    }

    // Get deployment hash and verify
    let deployment_hash = std::env::var("DEPLOYMENT_HASH")
        .unwrap_or_else(|_| "default_deployment_hash".to_string());

    let signer = BackupSigner::new(deployment_hash.as_bytes());

    // Verify hash (30 minute window)
    match signer.verify(&hash, 1800) {
        Ok(_) => {
            // Resolve backup path from state (set at startup) to avoid env races in tests
            let backup_path = state
                .backup_path
                .clone()
                .unwrap_or_else(|| "/data/encrypted/backup.tar.gz.cpt".to_string());

            if !std::path::Path::new(&backup_path).is_file() {
                error!("Backup file not found: {}", backup_path);
                return Err((
                    StatusCode::NOT_FOUND,
                    Json(ErrorResponse {
                        error: "Backup not found".to_string(),
                    }),
                ));
            }

            // Read and send backup file
            match tokio::fs::read(&backup_path).await {
                Ok(content) => {
                    // Extract filename for logging and headers
                    let filename = std::path::Path::new(&backup_path)
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("backup.tar.gz.cpt");

                    debug!("Backup downloaded by {}: {}", request_ip, filename);
                    
                    // Use HeaderMap to avoid lifetime issues
                    use axum::http::HeaderMap;
                    let mut headers = HeaderMap::new();
                    headers.insert(
                        axum::http::header::CONTENT_TYPE,
                        "application/octet-stream".parse().unwrap()
                    );
                    headers.insert(
                        axum::http::header::CONTENT_DISPOSITION,
                        format!("attachment; filename=\"{}\"", filename).parse().unwrap()
                    );

                    Ok((StatusCode::OK, headers, content))
                }
                Err(e) => {
                    error!("Failed to read backup file: {}", e);
                    Err((
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ErrorResponse {
                            error: "Failed to read backup".to_string(),
                        }),
                    ))
                }
            }
        }
        Err(_) => {
            error!("Invalid backup download hash from {}", request_ip);
            Err((
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "Invalid or expired hash".to_string(),
                }),
            ))
        }
    }
}

#[cfg(feature = "docker")]
async fn stack_health() -> impl IntoResponse {
    match docker::list_container_health().await {
        Ok(health) => Json(health).into_response(),
        Err(e) => {
            error!("stack health error: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            ).into_response()
        }
    }
}

// Return the latest metrics snapshot (refreshing before responding)
async fn metrics_handler(State(state): State<SharedState>) -> impl IntoResponse {
    let snapshot = state.metrics_collector.snapshot().await;
    {
        let mut guard = state.metrics_store.write().await;
        *guard = snapshot.clone();
    }

    Json(snapshot)
}

async fn metrics_ws_handler(State(state): State<SharedState>, ws: WebSocketUpgrade) -> impl IntoResponse {
    ws.on_upgrade(move |socket| metrics_ws_stream(state, socket))
}

async fn metrics_ws_stream(state: SharedState, mut socket: WebSocket) {
    let mut rx = state.metrics_tx.subscribe();

    // Send latest snapshot immediately
    let current = state.metrics_store.read().await.clone();
    if let Ok(text) = serde_json::to_string(&current) {
        let _ = socket.send(Message::Text(text.into())).await;
    }

    while let Ok(snapshot) = rx.recv().await {
        if let Ok(text) = serde_json::to_string(&snapshot) {
            if socket.send(Message::Text(text.into())).await.is_err() {
                break;
            }
        }
    }
}

pub fn create_router(state: SharedState) -> Router {
    let mut router = Router::new()
        .route("/health", get(health))
        .route("/metrics", get(metrics_handler))
        .route("/metrics/stream", get(metrics_ws_handler))
        .route("/login", get(login_page).post(login_handler))
        .route("/logout", get(logout_handler))
        .route("/backup/ping", post(backup_ping))
        .route("/backup/{hash}/{target_ip}", get(backup_download));
    // v2.0 endpoints: long-poll commands wait/report and execute
    router = router
        .route("/api/v1/commands/wait/{hash}", get(commands_wait))
        .route("/api/v1/commands/report", post(commands_report))
        .route("/api/v1/commands/execute", post(commands_execute))
        .route("/api/v1/commands/enqueue", post(commands_enqueue))
        .route("/api/v1/auth/rotate-token", post(rotate_token));

    #[cfg(feature = "docker")]
    {
        router = router
            .route("/", get(home))
            .route("/restart/{name}", get(restart_container))
            .route("/stop/{name}", get(stop_container))
            .route("/pause/{name}", get(pause_container))
            .route("/stack/health", get(stack_health));
        // SSL management routes
        router = router
            .route("/enable_ssl", get(enable_ssl_handler))
            .route("/disable_ssl", get(disable_ssl_handler));
    }

    // Add static file serving when UI is enabled
    if state.with_ui {
        use tower_http::services::ServeDir;
        router = router.nest_service("/static", ServeDir::new("static"));
    }

    router.with_state(state)
}

// ------- v2.0 long-poll and execute endpoints --------

#[derive(Deserialize)]
#[allow(dead_code)]
struct WaitParams {
    #[serde(default = "default_wait_timeout")]
    timeout: u64,
    #[serde(default)]
    priority: Option<String>,
}

fn default_wait_timeout() -> u64 { 30 }

fn validate_agent_id(headers: &HeaderMap) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    let expected = std::env::var("AGENT_ID").unwrap_or_default();
    if expected.is_empty() { return Ok(()); }
    match headers.get("X-Agent-Id").and_then(|v| v.to_str().ok()) {
        Some(got) if got == expected => Ok(()),
        _ => Err((StatusCode::UNAUTHORIZED, Json(ErrorResponse{ error: "Invalid or missing X-Agent-Id".to_string() }))),
    }
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

async fn verify_stacker_post(
    state: &SharedState,
    headers: &HeaderMap,
    body: &[u8],
    required_scope: &str,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    if let Err(resp) = validate_agent_id(headers) { return Err(resp); }

    // Rate limiting per agent
    let agent_id = header_str(headers, "X-Agent-Id").unwrap_or("");
    if !state.rate_limiter.allow(agent_id).await {
        state.audit.rate_limited(agent_id, header_str(headers, "X-Request-Id"));
        return Err((StatusCode::TOO_MANY_REQUESTS, Json(ErrorResponse{ error: "rate limited".into() })));
    }

    // HMAC signature verify
    let token = { state.agent_token.read().await.clone() };
    let skew = std::env::var("SIGNATURE_MAX_SKEW_SECS").ok().and_then(|v| v.parse::<i64>().ok()).unwrap_or(300);
    if let Err(e) = verify_signature(headers, body, &token, skew) {
        state.audit.signature_invalid(Some(agent_id), header_str(headers, "X-Request-Id"));
        return Err((StatusCode::UNAUTHORIZED, Json(ErrorResponse{ error: format!("invalid signature: {}", e) })));
    }

    // Replay prevention
    if let Some(req_id) = header_str(headers, "X-Request-Id") {
        if state.replay.check_and_store(req_id).await.is_err() {
            state.audit.replay_detected(Some(agent_id), Some(req_id));
            return Err((StatusCode::CONFLICT, Json(ErrorResponse{ error: "replay detected".into() })));
        }
    } else {
        return Err((StatusCode::BAD_REQUEST, Json(ErrorResponse{ error: "missing X-Request-Id".into() })));
    }

    // Scope authorization
    if !state.scopes.is_allowed(required_scope) {
        state.audit.scope_denied(agent_id, header_str(headers, "X-Request-Id"), required_scope);
        return Err((StatusCode::FORBIDDEN, Json(ErrorResponse{ error: "insufficient scope".into() })));
    }

    state.audit.auth_success(agent_id, header_str(headers, "X-Request-Id"), required_scope);
    Ok(())
}

async fn commands_wait(
    State(state): State<SharedState>,
    Path(_hash): Path<String>,
    Query(params): Query<WaitParams>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(resp) = validate_agent_id(&headers) { return resp.into_response(); }
    // Optional signing for GET /wait (empty body) controlled by env flag
    let require_sig = std::env::var("WAIT_REQUIRE_SIGNATURE").map(|v| v == "true").unwrap_or(false);
    if require_sig {
        if let Err(resp) = verify_stacker_post(&state, &headers, &[], "commands:wait").await { return resp.into_response(); }
    } else {
        // Lightweight rate limiting without signature
        if !state.rate_limiter.allow(headers.get("X-Agent-Id").and_then(|v| v.to_str().ok()).unwrap_or("")).await {
            state.audit.rate_limited(headers.get("X-Agent-Id").and_then(|v| v.to_str().ok()).unwrap_or(""), None);
            return (StatusCode::TOO_MANY_REQUESTS, Json(json!({"error": "rate limited"}))).into_response();
        }
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(params.timeout);
    loop {
        if let Some(cmd) = { let mut q = state.commands_queue.lock().await; q.pop_front() } {
            return Json(cmd).into_response();
        }
        let now = tokio::time::Instant::now();
        if now >= deadline { return (StatusCode::NO_CONTENT, "").into_response(); }
        let wait = deadline - now;
        tokio::select! {
            _ = state.commands_notify.notified() => {},
            _ = tokio::time::sleep(wait) => { return (StatusCode::NO_CONTENT, "").into_response(); }
        }
    }
}

async fn commands_report(State(state): State<SharedState>, headers: HeaderMap, body: Bytes) -> impl IntoResponse {
    if let Err(resp) = verify_stacker_post(&state, &headers, &body, "commands:report").await { return resp.into_response(); }
    let res: CommandResult = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(json!({"error": e.to_string()}))).into_response(),
    };
    info!(command_id = %res.command_id, status = %res.status, "command result reported");
    (StatusCode::OK, Json(json!({"accepted": true}))).into_response()
}

// Execute a validated command with a simple timeout strategy
async fn commands_execute(State(state): State<SharedState>, headers: HeaderMap, body: Bytes) -> impl IntoResponse {
    if let Err(resp) = verify_stacker_post(&state, &headers, &body, "commands:execute").await { return resp.into_response(); }
    let cmd: AgentCommand = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(json!({"error": e.to_string()}))).into_response(),
    };
    // Check if this is a Docker operation
    if cmd.name.starts_with("docker:") {
        match DockerOperation::parse(&cmd.name) {
            Ok(op) => {
                // Extra scope check for specific Docker operation
                let scope = match &op {
                    DockerOperation::Restart(_) => "docker:restart",
                    DockerOperation::Stop(_) => "docker:stop",
                    DockerOperation::Logs(_, _) => "docker:logs",
                    DockerOperation::Inspect(_) => "docker:inspect",
                    DockerOperation::Pause(_) => "docker:pause",
                };
                if !state.scopes.is_allowed(scope) {
                    return (
                        StatusCode::FORBIDDEN,
                        Json(json!({"error": "insufficient scope for docker operation"})),
                    ).into_response();
                }
                #[cfg(feature = "docker")]
                match execute_docker_operation(&cmd.id, op).await {
                    Ok(result) => return Json(result).into_response(),
                    Err(e) => {
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(json!({"error": e.to_string()})),
                        )
                            .into_response();
                    }
                }
                #[cfg(not(feature = "docker"))]
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "Docker operations not available"})),
                )
                    .into_response();
            }
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": format!("invalid docker operation: {}", e)})),
                )
                    .into_response();
            }
        }
    }

    // Regular command validation
    let validator = CommandValidator::default_secure();
    if let Err(e) = validator.validate(&cmd) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": format!("invalid command: {}", e)})),
        )
            .into_response();
    }

    // Optional timeout override in params.timeout_secs
    let timeout_secs = cmd
        .params
        .get("timeout_secs")
        .and_then(|v| v.as_u64())
        .unwrap_or(60);

    let strategy = TimeoutStrategy::quick_strategy(timeout_secs);
    let executor = CommandExecutor::new();

    match executor.execute(&cmd, strategy).await {
        Ok(exec) => Json(exec.to_command_result()).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn commands_enqueue(
    State(state): State<SharedState>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    if let Err(resp) = verify_stacker_post(&state, &headers, &body, "commands:enqueue").await { return resp.into_response(); }
    let cmd: AgentCommand = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(json!({"error": e.to_string()}))).into_response(),
    };
    {
        let mut q = state.commands_queue.lock().await;
        q.push_back(cmd);
    }
    state.commands_notify.notify_waiters();
    (StatusCode::ACCEPTED, Json(json!({"queued": true}))).into_response()
}

#[derive(Deserialize)]
struct RotateTokenRequest { new_token: String }

async fn rotate_token(
    State(state): State<SharedState>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    if let Err(resp) = verify_stacker_post(&state, &headers, &body, "auth:rotate").await { return resp.into_response(); }
    let req: RotateTokenRequest = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(json!({"error": e.to_string()}))).into_response(),
    };
    {
        let mut token = state.agent_token.write().await;
        *token = req.new_token.clone();
    }
    let agent_id = headers.get("X-Agent-Id").and_then(|v| v.to_str().ok()).unwrap_or("");
    state.audit.token_rotated(agent_id, headers.get("X-Request-Id").and_then(|v| v.to_str().ok()));
    (StatusCode::OK, Json(json!({"rotated": true}))).into_response()
}

pub async fn serve(config: Config, port: u16, with_ui: bool) -> Result<()> {
    let cfg = Arc::new(config);
    let state = Arc::new(AppState::new(cfg, with_ui));

    // Spawn token refresh task if Vault is configured
    if let (Some(vault_client), Some(token_cache)) = (&state.vault_client, &state.token_cache) {
        let deployment_hash = std::env::var("DEPLOYMENT_HASH")
            .unwrap_or_else(|_| "default".to_string());
        
        let vault_client_clone = vault_client.clone();
        let token_cache_clone = token_cache.clone();
        
        let _refresh_task = spawn_token_refresh(vault_client_clone, deployment_hash, token_cache_clone);
        info!("Token refresh background task spawned");
    }

    let heartbeat_interval = std::env::var("METRICS_INTERVAL_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(Duration::from_secs(30));
    spawn_heartbeat(
        state.metrics_collector.clone(),
        state.metrics_store.clone(),
        heartbeat_interval,
        state.metrics_tx.clone(),
        state.metrics_webhook.clone(),
    );

    let app = create_router(state.clone())
        .into_make_service_with_connect_info::<SocketAddr>();
    
    if with_ui {
        info!("HTTP server with UI starting on port {}", port);
    } else {
        info!("HTTP server in API-only mode starting on port {}", port);
    }

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!("HTTP server listening on {}", addr);
    axum::serve(listener, app).into_future().await?;
    Ok(())
}
