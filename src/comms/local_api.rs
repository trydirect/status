use anyhow::Result;
use axum::extract::ws::{Message, WebSocket};
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::{
    extract::Form,
    extract::Path,
    extract::Query,
    extract::State,
    extract::WebSocketUpgrade,
    http::{HeaderMap, StatusCode},
    response::Html,
    response::IntoResponse,
    response::Redirect,
    routing::{get, post},
    Json, Router,
};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::VecDeque;
use std::future::IntoFuture;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tera::Tera;
use tokio::sync::{broadcast, Mutex, Notify};
use tracing::{debug, error, info};

use crate::agent::backup::BackupSigner;
use crate::agent::config::Config;
#[cfg(feature = "docker")]
use crate::agent::docker;
#[cfg(feature = "docker")]
use crate::commands::execute_docker_operation;
use crate::commands::executor::CommandExecutor;
use crate::commands::firewall::FirewallPolicy;
use crate::commands::{
    backup_current_binary, deploy_temp_binary, record_rollback, restart_service, rollback_latest,
};
use crate::commands::{
    check_remote_version, get_update_status, start_update_job, UpdateJobs, UpdatePhase,
};
use crate::commands::{
    execute_stacker_command, parse_stacker_command, CommandValidator, DockerOperation, PipeRuntime,
    TimeoutStrategy,
};
use crate::comms::notifications::{self, MarkReadRequest, NotificationStore, UnreadCountResponse};
use crate::monitoring::{
    spawn_heartbeat, CommandExecutionMetrics, CommandMetricsStore, ControlPlane, MetricsCollector,
    MetricsSnapshot, MetricsStore, MetricsTx,
};
use crate::security::audit_log::AuditLogger;
use crate::security::auth::{Credentials, SessionStore, SessionUser};
use crate::security::rate_limit::RateLimiter;
use crate::security::replay::ReplayProtection;
use crate::security::request_signer::verify_signature;
use crate::security::scopes::Scopes;
use crate::security::token_cache::TokenCache;
use crate::security::token_refresh::spawn_token_refresh;
use crate::security::vault_client::VaultClient;
use crate::transport::{Command as AgentCommand, CommandResult};
use crate::VERSION;

type SharedState = Arc<AppState>;

/// Build cookie attributes. Include `Secure` only when STATUS_PANEL_HTTPS=true
/// (or when behind a TLS-terminating proxy). Without TLS, browsers ignore Secure cookies.
fn cookie_attributes() -> &'static str {
    let secure = std::env::var("STATUS_PANEL_HTTPS")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);
    if secure {
        "Path=/; HttpOnly; Secure; SameSite=Strict"
    } else {
        "Path=/; HttpOnly; SameSite=Strict"
    }
}

// Extract client IP from ConnectInfo or fallback to 127.0.0.1
#[derive(Debug, Clone)]
struct ClientIp(pub String);

impl<S> FromRequestParts<S> for ClientIp
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // Use ConnectInfo<SocketAddr> from Axum's connect info middleware.
        // Do NOT trust proxy headers (X-Forwarded-For, X-Real-Ip) as they are
        // trivially spoofable and would allow rate-limit bypass.
        if let Some(connect_info) = parts
            .extensions
            .get::<axum::extract::ConnectInfo<SocketAddr>>()
        {
            return Ok(ClientIp(connect_info.0.ip().to_string()));
        }

        // Fallback for tests (oneshot doesn't populate ConnectInfo)
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
    pub command_metrics: CommandMetricsStore,
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
    pub update_jobs: UpdateJobs,
    pub firewall_policy: FirewallPolicy,
    pub login_limiter: RateLimiter,
    pub notification_store: NotificationStore,
    pub pipe_runtime: PipeRuntime,
}

impl AppState {
    pub fn new(config: Arc<Config>, with_ui: bool, api_port: Option<u16>) -> Self {
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
            .inspect(|_| debug!("Vault client initialized for token rotation"));

        let token_cache = vault_client
            .is_some()
            .then(|| TokenCache::new(std::env::var("AGENT_TOKEN").unwrap_or_default()));

        let firewall_policy = FirewallPolicy::from_config(&config, api_port);

        Self {
            session_store: SessionStore::new(),
            config,
            templates,
            with_ui,
            metrics_collector: Arc::new(MetricsCollector::new()),
            metrics_store: Arc::new(tokio::sync::RwLock::new(MetricsSnapshot::default())),
            command_metrics: Arc::new(tokio::sync::RwLock::new(CommandExecutionMetrics::default())),
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
                    .unwrap_or(120),
            ),
            replay: ReplayProtection::new_ttl(
                std::env::var("REPLAY_TTL_SECS")
                    .ok()
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(600),
            ),
            scopes: Scopes::from_env(),
            agent_token: Arc::new(tokio::sync::RwLock::new(
                std::env::var("AGENT_TOKEN").unwrap_or_default(),
            )),
            vault_client,
            token_cache,
            update_jobs: Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),
            firewall_policy,
            login_limiter: RateLimiter::new_per_minute(5),
            notification_store: notifications::new_notification_store(),
            pipe_runtime: PipeRuntime::new(),
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

#[derive(Serialize)]
struct CapabilitiesResponse {
    compose_agent: bool,
    control_plane: String,
    version: String,
    features: Vec<String>,
}

// Health check with token rotation metrics
#[derive(Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub token_age_seconds: u64,
    pub last_refresh_ok: Option<bool>,
    pub command_metrics: CommandExecutionMetrics,
}

// ---- Marketplace types ----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackInfo {
    pub id: String,
    pub name: String,
    pub description: String,
    pub version: String,
    pub author: String,
    pub category: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon_url: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MarketplaceResponse {
    pub stacks: Vec<StackInfo>,
    pub total: usize,
}

#[derive(Debug, Deserialize)]
pub struct MarketplaceDeployRequest {
    pub stack_id: String,
    #[serde(default)]
    pub purchase_token: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct MarketplaceDeployResponse {
    pub status: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deploy_id: Option<String>,
}

// ---- Dashboard linking types ----

#[derive(Debug, Deserialize)]
pub struct LinkLoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct LinkSelectRequest {
    pub session_token: String,
    pub deployment_id: String,
}

#[derive(Debug, Deserialize)]
pub struct UnlinkRequest {}

async fn health(State(state): State<SharedState>) -> impl IntoResponse {
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

    let command_metrics = state.command_metrics.read().await.clone();

    Json(HealthResponse {
        status: "ok".to_string(),
        token_age_seconds,
        last_refresh_ok,
        command_metrics,
    })
}

async fn command_metrics_handler(State(state): State<SharedState>) -> impl IntoResponse {
    Json(state.command_metrics.read().await.clone())
}

async fn record_command_execution(state: &SharedState, executed_by: &str) {
    let control_plane = ControlPlane::from_value(Some(executed_by));
    let mut metrics = state.command_metrics.write().await;
    metrics.record_execution(control_plane);
}

async fn attach_command_provenance(
    state: &SharedState,
    mut result: CommandResult,
    executed_by: &str,
) -> CommandResult {
    record_command_execution(state, executed_by).await;
    result.executed_by = Some(executed_by.to_string());
    result
}

// Login form (GET)
async fn login_page(State(state): State<SharedState>) -> impl IntoResponse {
    if state.with_ui {
        if let Some(templates) = &state.templates {
            let mut context = tera::Context::new();
            context.insert("error", &false);

            match templates.render("login.html", &context) {
                Ok(html) => Html(html).into_response(),
                Err(e) => {
                    error!("Template render error: {}", e);
                    Html("<html><body>Error rendering template</body></html>".to_string())
                        .into_response()
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
    client_ip: ClientIp,
    Form(req): Form<LoginRequest>,
) -> Result<impl IntoResponse, impl IntoResponse> {
    if !state.login_limiter.allow(&client_ip.0).await {
        if state.with_ui {
            if let Some(templates) = &state.templates {
                let mut context = tera::Context::new();
                context.insert("error", &true);
                if let Ok(html) = templates.render("login.html", &context) {
                    return Err((StatusCode::TOO_MANY_REQUESTS, Html(html).into_response()));
                }
            }
            return Err((
                StatusCode::TOO_MANY_REQUESTS,
                Html(
                    "<html><body>Too many login attempts. Try again later.</body></html>"
                        .to_string(),
                )
                .into_response(),
            ));
        } else {
            return Err((
                StatusCode::TOO_MANY_REQUESTS,
                Json(ErrorResponse {
                    error: "Too many login attempts. Try again later.".to_string(),
                })
                .into_response(),
            ));
        }
    }
    let creds = match Credentials::from_env() {
        Ok(c) => c,
        Err(_) => {
            error!("login attempt but credentials are not configured");
            if state.with_ui {
                if let Some(templates) = &state.templates {
                    let mut context = tera::Context::new();
                    context.insert("error", &true);
                    if let Ok(html) = templates.render("login.html", &context) {
                        return Err((StatusCode::SERVICE_UNAVAILABLE, Html(html).into_response()));
                    }
                }
                return Err((
                    StatusCode::SERVICE_UNAVAILABLE,
                    Html(
                        "<html><body>Credentials not configured. Run `status init`.</body></html>"
                            .to_string(),
                    )
                    .into_response(),
                ));
            } else {
                return Err((
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(ErrorResponse {
                        error: "Credentials not configured. Set STATUS_PANEL_USERNAME and STATUS_PANEL_PASSWORD.".to_string(),
                    })
                    .into_response(),
                ));
            }
        }
    };
    // Constant-time comparison to prevent timing attacks on credentials
    let user_match =
        subtle::ConstantTimeEq::ct_eq(req.username.as_bytes(), creds.username.as_bytes());
    let pass_match =
        subtle::ConstantTimeEq::ct_eq(req.password.as_bytes(), creds.password.as_bytes());
    if (user_match & pass_match).into() {
        let user = SessionUser::new(req.username.clone());
        let session_id = state.session_store.create_session(user).await;
        debug!("user logged in: {}", req.username);
        use axum::http::header::SET_COOKIE;
        if state.with_ui {
            // Set session cookie (HttpOnly, Secure if HTTPS)
            let cookie = format!("session_id={}; {}", session_id, cookie_attributes());
            let mut resp = Redirect::to("/").into_response();
            resp.headers_mut()
                .append(SET_COOKIE, cookie.parse().unwrap());
            Ok(resp)
        } else {
            Ok(Json(LoginResponse { session_id }).into_response())
        }
    } else {
        error!("login failed for user: {}", req.username);
        // Re-render login page with error if UI is enabled, otherwise return error JSON
        if state.with_ui {
            if let Some(templates) = &state.templates {
                let mut context = tera::Context::new();
                context.insert("error", &true);
                match templates.render("login.html", &context) {
                    Ok(html) => Err((StatusCode::UNAUTHORIZED, Html(html).into_response())),
                    Err(e) => {
                        error!("Template render error: {}", e);
                        Err((
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Html("<html><body>Login failed</body></html>".to_string())
                                .into_response(),
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
                })
                .into_response(),
            ))
        }
    }
}

// Logout handler
async fn logout_handler(State(state): State<SharedState>, headers: HeaderMap) -> impl IntoResponse {
    // Extract session_id from cookie and invalidate
    if let Some(cookie_header) = headers.get("cookie") {
        if let Ok(cookies) = cookie_header.to_str() {
            for pair in cookies.split(';') {
                let pair = pair.trim();
                if let Some(session_id) = pair.strip_prefix("session_id=") {
                    state.session_store.delete_session(session_id).await;
                    debug!("session invalidated: {}", session_id);
                    break;
                }
            }
        }
    }

    debug!("user logged out");
    use axum::http::header::SET_COOKIE;
    let clear_cookie = format!("session_id=; {}; Max-Age=0", cookie_attributes());

    if state.with_ui {
        let mut resp = Redirect::to("/login").into_response();
        resp.headers_mut()
            .append(SET_COOKIE, clear_cookie.parse().unwrap());
        resp
    } else {
        let mut resp = Json(json!({"status": "logged out"})).into_response();
        resp.headers_mut()
            .append(SET_COOKIE, clear_cookie.parse().unwrap());
        resp
    }
}

// Get home (list containers, config)
#[cfg(feature = "docker")]
async fn home(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    use crate::agent::docker;
    use axum::response::Redirect;
    // Extract session_id from real request cookies
    let session_id = headers
        .get(axum::http::header::COOKIE)
        .and_then(|cookie_header| {
            cookie_header.to_str().ok().and_then(|cookie_str| {
                cookie_str.split(';').find_map(|cookie| {
                    let cookie = cookie.trim();
                    cookie.strip_prefix("session_id=").map(|v| v.to_string())
                })
            })
        });
    let valid_session = if let Some(ref sid) = session_id {
        state.session_store.get_session(sid).await.is_some()
    } else {
        false
    };
    if state.with_ui && !valid_session {
        return Redirect::to("/login").into_response();
    }
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
                    context.insert(
                        "apps_info",
                        &state.config.apps_info.clone().unwrap_or_default(),
                    );
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
                }))
                .into_response()
            }
        }
        Err(e) => {
            error!("failed to fetch containers: {}", e);
            Json(json!({"error": e.to_string()})).into_response()
        }
    }
}

// ---- SSL enable/disable (Let’s Encrypt or self-signed) ----
/// Build certbot argv vectors — each argument is a separate element to avoid
/// shell interpretation. Passed directly to `exec_in_container_argv`.
#[cfg(feature = "docker")]
fn build_certbot_argv(config: &Config) -> Result<(Vec<String>, Vec<String>), String> {
    use crate::security::validation::{is_safe_shell_value, is_valid_domain, is_valid_email};

    let email = &config.reqdata.email;
    if !is_valid_email(email) || !is_safe_shell_value(email) {
        return Err(format!("Invalid or unsafe email for certbot: {}", email));
    }

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

    // Validate every domain
    for d in &domains {
        if !is_valid_domain(d) || !is_safe_shell_value(d) {
            return Err(format!("Invalid or unsafe domain for certbot: {}", d));
        }
    }

    let reg_argv = vec![
        "certbot".to_string(),
        "register".to_string(),
        "--email".to_string(),
        email.clone(),
        "--agree-tos".to_string(),
        "-n".to_string(),
    ];

    let mut crt_argv = vec![
        "certbot".to_string(),
        "--nginx".to_string(),
        "--redirect".to_string(),
    ];
    for d in domains {
        crt_argv.push("-d".to_string());
        crt_argv.push(d);
    }

    Ok((reg_argv, crt_argv))
}

#[cfg(feature = "docker")]
async fn enable_ssl_handler(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if require_session(&state, &headers).await.is_none() {
        return unauthorized_response(&state);
    }
    let nginx = std::env::var("NGINX_CONTAINER").unwrap_or_else(|_| "nginx".to_string());
    // Prepare challenge directory
    if let Err(e) = docker::exec_in_container(
        &nginx,
        "mkdir -p /tmp/letsencrypt/.well-known/acme-challenge",
    )
    .await
    {
        error!("failed to prepare acme-challenge dir: {}", e);
        return Redirect::to("/").into_response();
    }

    if state.config.ssl.as_deref() == Some("letsencrypt") {
        let (reg_argv, crt_argv) = match build_certbot_argv(&state.config) {
            Ok(cmds) => cmds,
            Err(e) => {
                error!("certbot command validation failed: {}", e);
                return Redirect::to("/").into_response();
            }
        };
        info!("starting certbot registration and certificate issue");
        if let Err(e) = docker::exec_in_container_argv(&nginx, reg_argv).await {
            error!("certbot register failed: {}", e);
            return Redirect::to("/").into_response();
        }
        if let Err(e) = docker::exec_in_container_argv(&nginx, crt_argv).await {
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
                    for k in map.keys() {
                        names.push(k.clone());
                    }
                }
                serde_json::Value::Array(arr) => {
                    for v in arr {
                        if let Some(s) = v.as_str() {
                            names.push(s.to_string());
                        }
                    }
                }
                serde_json::Value::String(s) => {
                    for part in s.split(',') {
                        let p = part.trim();
                        if !p.is_empty() {
                            names.push(p.to_string());
                        }
                    }
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
async fn disable_ssl_handler(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if require_session(&state, &headers).await.is_none() {
        return unauthorized_response(&state);
    }
    let nginx = std::env::var("NGINX_CONTAINER").unwrap_or_else(|_| "nginx".to_string());
    let mut names: Vec<String> = Vec::new();
    if let Some(ref sd) = state.config.subdomains {
        match sd {
            serde_json::Value::Object(map) => {
                for k in map.keys() {
                    names.push(k.clone());
                }
            }
            serde_json::Value::Array(arr) => {
                for v in arr {
                    if let Some(s) = v.as_str() {
                        names.push(s.to_string());
                    }
                }
            }
            serde_json::Value::String(s) => {
                for part in s.split(',') {
                    let p = part.trim();
                    if !p.is_empty() {
                        names.push(p.to_string());
                    }
                }
            }
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

/// Extract session_id from cookies and verify against the session store.
/// Returns None if no valid session found.
#[cfg(feature = "docker")]
async fn require_session(state: &SharedState, headers: &HeaderMap) -> Option<String> {
    let session_id = headers
        .get(axum::http::header::COOKIE)
        .and_then(|h| h.to_str().ok())
        .and_then(|cookies| {
            cookies
                .split(';')
                .find_map(|c| c.trim().strip_prefix("session_id=").map(|v| v.to_string()))
        })?;
    state
        .session_store
        .get_session(&session_id)
        .await
        .map(|_| session_id)
}

#[cfg(feature = "docker")]
fn unauthorized_response(state: &SharedState) -> axum::http::Response<axum::body::Body> {
    if state.with_ui {
        Redirect::to("/login").into_response()
    } else {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "authentication required"})),
        )
            .into_response()
    }
}

// Restart container
#[cfg(feature = "docker")]
async fn restart_container(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> impl IntoResponse {
    if require_session(&state, &headers).await.is_none() {
        return unauthorized_response(&state);
    }
    use crate::agent::docker;
    match docker::restart(&name).await {
        Ok(_) => {
            info!("restarted container: {}", name);
            if state.with_ui {
                Redirect::to("/").into_response()
            } else {
                Json(json!({"action": "restart", "container": name, "status": "ok"}))
                    .into_response()
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
    headers: HeaderMap,
    Path(name): Path<String>,
) -> impl IntoResponse {
    if require_session(&state, &headers).await.is_none() {
        return unauthorized_response(&state);
    }
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
    headers: HeaderMap,
    Path(name): Path<String>,
) -> impl IntoResponse {
    if require_session(&state, &headers).await.is_none() {
        return unauthorized_response(&state);
    }
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
    let deployment_hash =
        std::env::var("DEPLOYMENT_HASH").unwrap_or_else(|_| "default_deployment_hash".to_string());

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
        let new_hash = signer
            .sign(&deployment_hash)
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
    let deployment_hash =
        std::env::var("DEPLOYMENT_HASH").unwrap_or_else(|_| "default_deployment_hash".to_string());

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
                        "application/octet-stream".parse().unwrap(),
                    );
                    headers.insert(
                        axum::http::header::CONTENT_DISPOSITION,
                        format!("attachment; filename=\"{}\"", filename)
                            .parse()
                            .unwrap(),
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
            )
                .into_response()
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

async fn metrics_ws_handler(
    State(state): State<SharedState>,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
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

async fn capabilities_handler(State(state): State<SharedState>) -> impl IntoResponse {
    let compose_agent_env = std::env::var("COMPOSE_AGENT_ENABLED")
        .ok()
        .and_then(|v| v.parse::<bool>().ok());
    let compose_agent = compose_agent_env.unwrap_or(state.config.compose_agent_enabled);

    let control_plane = std::env::var("CONTROL_PLANE")
        .ok()
        .or_else(|| state.config.control_plane.clone())
        .unwrap_or_else(|| "status_panel".to_string());

    // Basic capability set; extend if docker feature is enabled
    let mut features = vec!["monitoring".to_string()];
    if cfg!(feature = "docker") {
        features.push("docker".to_string());
        features.push("compose".to_string());
        features.push("logs".to_string());
        features.push("restart".to_string());
    }
    features.push("pipes".to_string());
    features.push("activate_pipe".to_string());
    features.push("deactivate_pipe".to_string());
    features.push("trigger_pipe".to_string());
    if compose_agent {
        features.push("compose_agent".to_string());
    }

    // Detect Kata Containers runtime availability
    #[cfg(feature = "docker")]
    {
        if crate::commands::stacker::detect_kata_runtime().await {
            features.push("kata".to_string());
        }
    }

    let resp = CapabilitiesResponse {
        compose_agent,
        control_plane,
        version: VERSION.to_string(),
        features,
    };

    Json(resp)
}

// ---- Marketplace handlers ----

fn render_template(state: &AppState, name: &str, context: &tera::Context) -> impl IntoResponse {
    if let Some(templates) = &state.templates {
        match templates.render(name, context) {
            Ok(html) => Html(html).into_response(),
            Err(e) => {
                error!("Template render error: {}", e);
                Json(json!({"error": format!("Template error: {}", e)})).into_response()
            }
        }
    } else {
        Json(json!({"error": "Templates not loaded"})).into_response()
    }
}

async fn marketplace_page(State(state): State<SharedState>) -> impl IntoResponse {
    if !state.with_ui {
        return Json(json!({"error": "UI not enabled"})).into_response();
    }

    let marketplace_url = std::env::var("MARKETPLACE_URL")
        .unwrap_or_else(|_| "https://marketplace.try.direct".to_string());

    // Try to fetch stacks from marketplace API
    let stacks: Vec<StackInfo> = match reqwest::Client::new()
        .get(format!("{}/api/v1/marketplace/stacks", marketplace_url))
        .timeout(Duration::from_secs(5))
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => resp
            .json::<MarketplaceResponse>()
            .await
            .map(|r| r.stacks)
            .unwrap_or_default(),
        _ => {
            debug!("marketplace API unreachable, showing empty state");
            Vec::new()
        }
    };

    let mut context = tera::Context::new();
    context.insert("stacks", &stacks);
    context.insert("panel_version", &env!("CARGO_PKG_VERSION"));
    render_template(&state, "marketplace.html", &context).into_response()
}

async fn marketplace_stacks_api(State(_state): State<SharedState>) -> impl IntoResponse {
    let marketplace_url = std::env::var("MARKETPLACE_URL")
        .unwrap_or_else(|_| "https://marketplace.try.direct".to_string());

    match reqwest::Client::new()
        .get(format!("{}/api/v1/marketplace/stacks", marketplace_url))
        .timeout(Duration::from_secs(10))
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            let body: serde_json::Value = resp
                .json()
                .await
                .unwrap_or(json!({"stacks": [], "total": 0}));
            Json(body).into_response()
        }
        Ok(resp) => {
            let status = resp.status();
            (
                status,
                Json(json!({"error": format!("Marketplace returned {}", status)})),
            )
                .into_response()
        }
        Err(e) => {
            let status = if e.is_timeout() {
                StatusCode::GATEWAY_TIMEOUT
            } else {
                StatusCode::BAD_GATEWAY
            };
            (
                status,
                Json(json!({"error": format!("Failed to reach marketplace: {}", e)})),
            )
                .into_response()
        }
    }
}

async fn marketplace_deploy(
    State(state): State<SharedState>,
    Json(req): Json<MarketplaceDeployRequest>,
) -> impl IntoResponse {
    info!(stack_id = %req.stack_id, "marketplace deploy requested");

    // Validate stack_id to prevent path traversal
    if req.stack_id.contains("..")
        || req.stack_id.contains('/')
        || req.stack_id.contains('\\')
        || !req
            .stack_id
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid stack_id"})),
        )
            .into_response();
    }

    let deploy_id = uuid::Uuid::new_v4().to_string();

    // Spawn deploy in background so we can respond immediately
    let stack_id = req.stack_id.clone();
    let _config = state.config.clone();
    let spawn_deploy_id = deploy_id.clone();
    tokio::spawn(async move {
        info!(stack_id = %stack_id, deploy_id = %spawn_deploy_id, "starting local stacker deploy");
        let result = tokio::process::Command::new("stacker")
            .args([
                "deploy",
                "--from",
                &format!("/opt/stacker/stacks/{}/", stack_id),
            ])
            .output()
            .await;
        match result {
            Ok(output) => {
                if output.status.success() {
                    info!(stack_id = %stack_id, "stacker deploy completed successfully");
                } else {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    error!(stack_id = %stack_id, stderr = %stderr, "stacker deploy failed");
                }
            }
            Err(e) => {
                error!(stack_id = %stack_id, error = %e, "failed to spawn stacker deploy");
            }
        }
    });

    Json(MarketplaceDeployResponse {
        status: "started".to_string(),
        message: format!("Deploy of '{}' has been initiated", req.stack_id),
        deploy_id: Some(deploy_id),
    })
    .into_response()
}

// ---- Dashboard linking handlers ----

async fn link_page(State(state): State<SharedState>) -> impl IntoResponse {
    if !state.with_ui {
        return Json(json!({"error": "UI not enabled"})).into_response();
    }

    let mut context = tera::Context::new();
    context.insert("panel_version", &env!("CARGO_PKG_VERSION"));

    // Check if already linked by looking for saved registration
    let reg_path = "/etc/status-panel/registration.json";
    if let Ok(data) = tokio::fs::read_to_string(reg_path).await {
        if let Ok(reg) = serde_json::from_str::<serde_json::Value>(&data) {
            context.insert("linked", &true);
            context.insert(
                "agent_id",
                &reg.get("agent_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown"),
            );
            context.insert(
                "dashboard_url",
                &reg.get("dashboard_url")
                    .and_then(|v| v.as_str())
                    .unwrap_or(""),
            );
            return render_template(&state, "link.html", &context).into_response();
        }
    }

    context.insert("linked", &false);
    context.insert("step", &"login");
    context.insert("link_error", &Option::<String>::None);
    render_template(&state, "link.html", &context).into_response()
}

/// Step 1: User submits email + password → Stacker validates → returns deployments list
async fn link_login_handler(
    State(state): State<SharedState>,
    Form(req): Form<LinkLoginRequest>,
) -> impl IntoResponse {
    info!(email = %req.email, "dashboard link login requested");

    let stacker_url =
        std::env::var("DASHBOARD_URL").unwrap_or_else(|_| "https://stacker.try.direct".to_string());

    match crate::agent::registration::login_to_stacker(&stacker_url, &req.email, &req.password)
        .await
    {
        Ok(login_resp) => {
            if state.with_ui {
                let mut context = tera::Context::new();
                context.insert("panel_version", &env!("CARGO_PKG_VERSION"));
                context.insert("linked", &false);
                context.insert("step", &"select");
                context.insert("session_token", &login_resp.session_token);
                context.insert("deployments", &login_resp.deployments);
                context.insert("link_error", &Option::<String>::None);
                render_template(&state, "link.html", &context).into_response()
            } else {
                Json(json!({
                    "session_token": login_resp.session_token,
                    "deployments": login_resp.deployments
                }))
                .into_response()
            }
        }
        Err(e) => {
            error!("dashboard link login failed: {}", e);
            if state.with_ui {
                let mut context = tera::Context::new();
                context.insert("panel_version", &env!("CARGO_PKG_VERSION"));
                context.insert("linked", &false);
                context.insert("step", &"login");
                context.insert("link_error", &Some(format!("Login failed: {}", e)));
                render_template(&state, "link.html", &context).into_response()
            } else {
                Json(json!({"error": format!("Login failed: {}", e)})).into_response()
            }
        }
    }
}

/// Step 2: User selects a deployment → agent links to it via Stacker
async fn link_select_handler(
    State(state): State<SharedState>,
    Form(req): Form<LinkSelectRequest>,
) -> impl IntoResponse {
    info!(deployment_id = %req.deployment_id, "linking agent to deployment");

    let stacker_url =
        std::env::var("DASHBOARD_URL").unwrap_or_else(|_| "https://stacker.try.direct".to_string());

    match crate::agent::registration::link_agent_to_deployment(
        &stacker_url,
        &req.session_token,
        &req.deployment_id,
    )
    .await
    {
        Ok(reg) => {
            let save_path = std::path::Path::new("/etc/status-panel/registration.json");
            if let Err(e) = crate::agent::registration::save_registration(save_path, &reg) {
                error!("could not save registration: {}", e);
            }
            if state.with_ui {
                Redirect::to("/link").into_response()
            } else {
                Json(json!({"status": "linked", "agent_id": reg.agent_id})).into_response()
            }
        }
        Err(e) => {
            error!("agent linking failed: {}", e);
            if state.with_ui {
                let mut context = tera::Context::new();
                context.insert("panel_version", &env!("CARGO_PKG_VERSION"));
                context.insert("linked", &false);
                context.insert("step", &"login");
                context.insert(
                    "link_error",
                    &Some(format!("Linking failed: {}. Please login again.", e)),
                );
                render_template(&state, "link.html", &context).into_response()
            } else {
                Json(json!({"error": format!("Linking failed: {}", e)})).into_response()
            }
        }
    }
}

async fn unlink_handler(State(state): State<SharedState>) -> impl IntoResponse {
    let reg_path = "/etc/status-panel/registration.json";
    match tokio::fs::try_exists(reg_path).await {
        Ok(true) => {
            if let Err(e) = tokio::fs::remove_file(reg_path).await {
                error!("failed to remove registration: {}", e);
            } else {
                info!("dashboard unlinked, registration removed");
            }
        }
        Ok(false) => {
            info!("unlink requested but no registration file found");
        }
        Err(e) => {
            error!("failed to check registration file at {}: {}", reg_path, e);
        }
    }
    if state.with_ui {
        Redirect::to("/link").into_response()
    } else {
        Json(json!({"status": "unlinked"})).into_response()
    }
}

// ---- Notification API handlers ----

async fn notifications_list(State(state): State<SharedState>) -> impl IntoResponse {
    let summary = notifications::get_summary(&state.notification_store).await;
    Json(summary)
}

async fn notifications_mark_read(
    State(state): State<SharedState>,
    Json(req): Json<MarkReadRequest>,
) -> impl IntoResponse {
    notifications::mark_read(&state.notification_store, &req.ids, req.all).await;
    Json(json!({"status": "ok"}))
}

async fn notifications_unread_count(State(state): State<SharedState>) -> impl IntoResponse {
    let count = notifications::get_unread_count(&state.notification_store).await;
    Json(UnreadCountResponse {
        unread_count: count,
    })
}

pub fn create_router(state: SharedState) -> Router {
    let mut router = Router::new()
        .route("/health", get(health))
        .route("/capabilities", get(capabilities_handler))
        .route("/metrics", get(metrics_handler))
        .route("/metrics/stream", get(metrics_ws_handler))
        .route("/api/v1/diagnostics/commands", get(command_metrics_handler))
        // Self-update endpoints
        .route("/api/self/version", get(self_version))
        .route("/api/self/update/start", post(self_update_start))
        .route("/api/self/update/status/{id}", get(self_update_status))
        .route("/api/self/update/deploy", post(self_update_deploy))
        .route("/api/self/update/rollback", post(self_update_rollback))
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

    router = router.route(
        "/api/v1/pipes/webhook/{deployment_hash}/{pipe_instance_id}",
        post(pipe_webhook_ingest),
    );

    // Marketplace & dashboard linking
    router = router
        .route("/marketplace", get(marketplace_page))
        .route("/api/v1/marketplace/stacks", get(marketplace_stacks_api))
        .route("/api/v1/marketplace/deploy", post(marketplace_deploy))
        .route("/link", get(link_page).post(link_login_handler))
        .route("/link/select", post(link_select_handler))
        .route("/link/unlink", post(unlink_handler));

    // Notifications
    router = router
        .route("/api/v1/notifications", get(notifications_list))
        .route("/api/v1/notifications/read", post(notifications_mark_read))
        .route(
            "/api/v1/notifications/unread-count",
            get(notifications_unread_count),
        );

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

#[derive(Serialize)]
struct SelfVersionResponse {
    current: String,
    available: Option<String>,
    has_update: bool,
}

async fn self_version(State(_state): State<SharedState>) -> impl IntoResponse {
    let current = VERSION.to_string();
    let mut available: Option<String> = None;
    if let Ok(Some(rv)) = check_remote_version().await {
        available = Some(rv.version);
    }
    let has_update = available.as_ref().map(|a| a != &current).unwrap_or(false);
    Json(SelfVersionResponse {
        current,
        available,
        has_update,
    })
}

#[derive(Deserialize)]
struct StartUpdateRequest {
    version: Option<String>,
}

async fn self_update_start(
    State(state): State<SharedState>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    // Require agent id header as with v2.0 endpoints
    if let Err(resp) = validate_agent_id(&headers) {
        return resp.into_response();
    }
    let req: StartUpdateRequest = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": e.to_string()})),
            )
                .into_response()
        }
    };
    match start_update_job(state.update_jobs.clone(), req.version).await {
        Ok(id) => (StatusCode::ACCEPTED, Json(json!({"job_id": id}))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn self_update_status(
    State(state): State<SharedState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match get_update_status(state.update_jobs.clone(), &id).await {
        Some(st) => {
            let phase = match st.phase {
                UpdatePhase::Pending => "pending",
                UpdatePhase::Downloading => "downloading",
                UpdatePhase::Verifying => "verifying",
                UpdatePhase::Completed => "completed",
                UpdatePhase::Failed(_) => "failed",
            };
            Json(json!({"job_id": id, "phase": phase})).into_response()
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "job not found"})),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
struct DeployRequest {
    job_id: String,
    install_path: Option<String>,
    service_name: Option<String>,
}

async fn self_update_deploy(
    State(_state): State<SharedState>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    if let Err(resp) = validate_agent_id(&headers) {
        return resp.into_response();
    }
    let req: DeployRequest = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": e.to_string()})),
            )
                .into_response()
        }
    };
    let install_path = req
        .install_path
        .unwrap_or_else(|| "/usr/local/bin/status".to_string());
    // Backup current
    match backup_current_binary(&install_path, &req.job_id).await {
        Ok(backup_path) => {
            if let Err(e) = record_rollback(&req.job_id, &backup_path, &install_path).await {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": e.to_string()})),
                )
                    .into_response();
            }
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("backup failed: {}", e)})),
            )
                .into_response()
        }
    }

    // Deploy temp binary
    if let Err(e) = deploy_temp_binary(&req.job_id, &install_path).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("deploy failed: {}", e)})),
        )
            .into_response();
    }

    // Try to restart service if provided
    if let Some(svc) = req.service_name {
        if let Err(e) = restart_service(&svc).await {
            // Best-effort: return 202 with warning so external orchestrator can proceed
            return (
                StatusCode::ACCEPTED,
                Json(json!({"deployed": true, "restart_error": e.to_string()})),
            )
                .into_response();
        }
    }

    (StatusCode::ACCEPTED, Json(json!({"deployed": true}))).into_response()
}

async fn self_update_rollback(
    State(_state): State<SharedState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(resp) = validate_agent_id(&headers) {
        return resp.into_response();
    }
    match rollback_latest().await {
        Ok(Some(entry)) => (
            StatusCode::ACCEPTED,
            Json(json!({"rolled_back": true, "install_path": entry.install_path})),
        )
            .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "no backups available"})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
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

fn default_wait_timeout() -> u64 {
    30
}

fn validate_agent_id(headers: &HeaderMap) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    let expected = std::env::var("AGENT_ID").unwrap_or_default();
    if expected.is_empty() {
        // When AGENT_ID is not configured, reject all requests to prevent
        // unauthenticated access to sensitive endpoints.
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "AGENT_ID not configured".to_string(),
            }),
        ));
    }
    match headers.get("X-Agent-Id").and_then(|v| v.to_str().ok()) {
        Some(got) if got == expected => Ok(()),
        _ => Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Invalid or missing X-Agent-Id".to_string(),
            }),
        )),
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
    validate_agent_id(headers)?;

    // Rate limiting per agent
    let agent_id = header_str(headers, "X-Agent-Id").unwrap_or("");
    if !state.rate_limiter.allow(agent_id).await {
        state
            .audit
            .rate_limited(agent_id, header_str(headers, "X-Request-Id"));
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(ErrorResponse {
                error: "rate limited".into(),
            }),
        ));
    }

    // HMAC signature verify
    let token = { state.agent_token.read().await.clone() };
    let skew = std::env::var("SIGNATURE_MAX_SKEW_SECS")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(300);
    if let Err(e) = verify_signature(headers, body, &token, skew) {
        state
            .audit
            .signature_invalid(Some(agent_id), header_str(headers, "X-Request-Id"));
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: format!("invalid signature: {}", e),
            }),
        ));
    }

    // Replay prevention
    if let Some(req_id) = header_str(headers, "X-Request-Id") {
        if state.replay.check_and_store(req_id).await.is_err() {
            state.audit.replay_detected(Some(agent_id), Some(req_id));
            return Err((
                StatusCode::CONFLICT,
                Json(ErrorResponse {
                    error: "replay detected".into(),
                }),
            ));
        }
    } else {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "missing X-Request-Id".into(),
            }),
        ));
    }

    // Scope authorization
    if !state.scopes.is_allowed(required_scope) {
        state.audit.scope_denied(
            agent_id,
            header_str(headers, "X-Request-Id"),
            required_scope,
        );
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "insufficient scope".into(),
            }),
        ));
    }

    state.audit.auth_success(
        agent_id,
        header_str(headers, "X-Request-Id"),
        required_scope,
    );
    Ok(())
}

async fn commands_wait(
    State(state): State<SharedState>,
    Path(_hash): Path<String>,
    Query(params): Query<WaitParams>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(resp) = validate_agent_id(&headers) {
        return resp.into_response();
    }
    // Optional signing for GET /wait (empty body) controlled by env flag
    let require_sig = std::env::var("WAIT_REQUIRE_SIGNATURE")
        .map(|v| v == "true")
        .unwrap_or(false);
    if require_sig {
        if let Err(resp) = verify_stacker_post(&state, &headers, &[], "commands:wait").await {
            return resp.into_response();
        }
    } else {
        // Lightweight rate limiting without signature
        if !state
            .rate_limiter
            .allow(
                headers
                    .get("X-Agent-Id")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or(""),
            )
            .await
        {
            state.audit.rate_limited(
                headers
                    .get("X-Agent-Id")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or(""),
                None,
            );
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({"error": "rate limited"})),
            )
                .into_response();
        }
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(params.timeout);
    loop {
        if let Some(cmd) = {
            let mut q = state.commands_queue.lock().await;
            q.pop_front()
        } {
            return Json(cmd).into_response();
        }
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return (StatusCode::NO_CONTENT, "").into_response();
        }
        let wait = deadline - now;
        tokio::select! {
            _ = state.commands_notify.notified() => {},
            _ = tokio::time::sleep(wait) => { return (StatusCode::NO_CONTENT, "").into_response(); }
        }
    }
}

async fn commands_report(
    State(state): State<SharedState>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    if let Err(resp) = verify_stacker_post(&state, &headers, &body, "commands:report").await {
        return resp.into_response();
    }
    let res: CommandResult = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": e.to_string()})),
            )
                .into_response()
        }
    };
    if let Some(executed_by) = res.executed_by.as_deref() {
        record_command_execution(&state, executed_by).await;
    }
    info!(command_id = %res.command_id, status = %res.status, "command result reported");
    (StatusCode::OK, Json(json!({"accepted": true}))).into_response()
}

// Execute a validated command with a simple timeout strategy
async fn commands_execute(
    State(state): State<SharedState>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    if let Err(resp) = verify_stacker_post(&state, &headers, &body, "commands:execute").await {
        return resp.into_response();
    }
    let cmd: AgentCommand = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": e.to_string()})),
            )
                .into_response()
        }
    };
    let parsed_stacker_cmd = match parse_stacker_command(&cmd) {
        Ok(value) => value,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": format!("invalid stacker command payload: {}", e)})),
            )
                .into_response()
        }
    };
    let executed_by = ControlPlane::from_value(
        std::env::var("CONTROL_PLANE")
            .ok()
            .as_deref()
            .or(state.config.control_plane.as_deref()),
    )
    .to_string();
    if let Some(stacker_cmd) = parsed_stacker_cmd {
        match execute_stacker_command(
            &cmd,
            &stacker_cmd,
            &state.firewall_policy,
            &state.pipe_runtime,
        )
        .await
        {
            Ok(result) => {
                return Json(attach_command_provenance(&state, result, &executed_by).await)
                    .into_response();
            }
            Err(e) => {
                error!(
                    command_id = %cmd.command_id,
                    err = %e,
                    "stacker command execution failed"
                );
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": e.to_string()})),
                )
                    .into_response();
            }
        }
    }
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
                    )
                        .into_response();
                }
                #[cfg(feature = "docker")]
                match execute_docker_operation(&cmd.command_id, op).await {
                    Ok(result) => {
                        return Json(attach_command_provenance(&state, result, &executed_by).await)
                            .into_response()
                    }
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
        Ok(exec) => {
            Json(attach_command_provenance(&state, exec.to_command_result(), &executed_by).await)
                .into_response()
        }
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
    if let Err(resp) = verify_stacker_post(&state, &headers, &body, "commands:enqueue").await {
        return resp.into_response();
    }
    let cmd: AgentCommand = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": e.to_string()})),
            )
                .into_response()
        }
    };
    if let Err(e) = parse_stacker_command(&cmd) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": format!("invalid stacker command payload: {}", e)})),
        )
            .into_response();
    }
    {
        let mut q = state.commands_queue.lock().await;
        q.push_back(cmd);
    }
    state.commands_notify.notify_waiters();
    (StatusCode::ACCEPTED, Json(json!({"queued": true}))).into_response()
}

async fn pipe_webhook_ingest(
    State(state): State<SharedState>,
    Path((deployment_hash, pipe_instance_id)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    if let Err(resp) = verify_stacker_post(&state, &headers, &body, "commands:execute").await {
        return resp.into_response();
    }

    let payload: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(error) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": format!("invalid webhook payload: {}", error)})),
            )
                .into_response()
        }
    };

    match state
        .pipe_runtime
        .trigger_registered_payload(&deployment_hash, &pipe_instance_id, payload, "webhook")
        .await
    {
        Ok(result) => Json(result).into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": error.to_string()})),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
struct RotateTokenRequest {
    new_token: String,
}

async fn rotate_token(
    State(state): State<SharedState>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    if let Err(resp) = verify_stacker_post(&state, &headers, &body, "auth:rotate").await {
        return resp.into_response();
    }
    let req: RotateTokenRequest = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": e.to_string()})),
            )
                .into_response()
        }
    };
    {
        let mut token = state.agent_token.write().await;
        *token = req.new_token.clone();
    }
    let agent_id = headers
        .get("X-Agent-Id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    state.audit.token_rotated(
        agent_id,
        headers.get("X-Request-Id").and_then(|v| v.to_str().ok()),
    );
    (StatusCode::OK, Json(json!({"rotated": true}))).into_response()
}

/// Return the bind address. Defaults to 127.0.0.1 for security.
/// Pass `Some("0.0.0.0")` to explicitly listen on all interfaces.
pub fn default_bind_address(bind: Option<String>) -> std::net::Ipv4Addr {
    match bind.as_deref() {
        Some(addr) => addr.parse().unwrap_or(std::net::Ipv4Addr::LOCALHOST),
        None => std::net::Ipv4Addr::LOCALHOST,
    }
}

pub async fn serve(config: Config, port: u16, with_ui: bool) -> Result<()> {
    let cfg = Arc::new(config);
    let state = Arc::new(AppState::new(cfg, with_ui, Some(port)));

    // Spawn token refresh task if Vault is configured
    if let (Some(vault_client), Some(token_cache)) = (&state.vault_client, &state.token_cache) {
        let deployment_hash =
            std::env::var("DEPLOYMENT_HASH").unwrap_or_else(|_| "default".to_string());

        let vault_client_clone = vault_client.clone();
        let token_cache_clone = token_cache.clone();

        let _refresh_task =
            spawn_token_refresh(vault_client_clone, deployment_hash, token_cache_clone);
        info!("Token refresh background task spawned");
    }

    let heartbeat_interval = std::env::var("METRICS_INTERVAL_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(Duration::from_secs(30));

    let alert_manager = {
        let cfg = crate::monitoring::alerting::AlertConfig::from_env();
        let mgr = crate::monitoring::alerting::AlertManager::new(cfg);
        if mgr.is_enabled() {
            tracing::info!("outbound alerting enabled");
            Some(Arc::new(mgr))
        } else {
            tracing::debug!("outbound alerting disabled (ALERT_WEBHOOK_URL not set)");
            None
        }
    };

    spawn_heartbeat(
        state.metrics_collector.clone(),
        state.metrics_store.clone(),
        heartbeat_interval,
        state.metrics_tx.clone(),
        state.metrics_webhook.clone(),
        alert_manager,
    );

    // Spawn notification poller if dashboard connection is configured
    {
        let dashboard_url =
            std::env::var("DASHBOARD_URL").unwrap_or_else(|_| "http://localhost:5000".to_string());
        let agent_id = std::env::var("AGENT_ID").unwrap_or_default();
        let agent_token = std::env::var("AGENT_TOKEN").unwrap_or_default();

        if !agent_token.is_empty() {
            // Build a TokenProvider so the poller can refresh on 401/403
            let token_provider = crate::security::token_provider::TokenProvider::from_env(
                state.vault_client.clone(),
            );

            let poll_interval = std::env::var("NOTIFICATION_POLL_SECS")
                .ok()
                .and_then(|s| s.parse::<u64>().ok())
                .map(Duration::from_secs)
                .unwrap_or(Duration::from_secs(300));

            let deployment_hash =
                std::env::var("DEPLOYMENT_HASH").unwrap_or_else(|_| "default".to_string());

            notifications::spawn_notification_poller(
                dashboard_url,
                agent_id,
                token_provider,
                deployment_hash,
                state.notification_store.clone(),
                poll_interval,
            );
            info!("Notification poller spawned");
        } else {
            info!("Notification poller skipped (no AGENT_TOKEN configured)");
        }
    }

    // Periodic cleanup of rate limiter, login limiter, replay protection, and expired sessions
    {
        let state_cleanup = state.clone();
        let session_ttl = state.session_store.ttl();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(300));
            loop {
                interval.tick().await;
                state_cleanup.rate_limiter.cleanup_stale().await;
                state_cleanup.login_limiter.cleanup_stale().await;
                state_cleanup.replay.cleanup_expired().await;
                state_cleanup
                    .session_store
                    .cleanup_expired(session_ttl)
                    .await;
            }
        });
    }

    let app = create_router(state.clone()).into_make_service_with_connect_info::<SocketAddr>();

    if with_ui {
        info!("HTTP server with UI starting on port {}", port);
    } else {
        info!("HTTP server in API-only mode starting on port {}", port);
    }

    let bind = std::env::var("STATUS_PANEL_BIND").ok();
    let bind_addr = default_bind_address(bind);
    let addr = SocketAddr::from((bind_addr, port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!("HTTP server listening on {}", addr);
    axum::serve(listener, app).into_future().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use serde_json::Value;

    fn test_state(control_plane: Option<&str>) -> SharedState {
        Arc::new(AppState::new(
            Arc::new(Config {
                domain: None,
                subdomains: None,
                apps_info: None,
                reqdata: crate::agent::config::ReqData {
                    email: "ops@example.com".to_string(),
                },
                ssl: None,
                compose_agent_enabled: false,
                control_plane: control_plane.map(str::to_string),
                firewall: None,
            }),
            false,
            None,
        ))
    }

    #[tokio::test]
    async fn health_includes_command_metrics() {
        let state = test_state(Some("compose_agent"));
        record_command_execution(&state, "compose_agent").await;

        let response = health(State(state)).await.into_response();
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("health body");
        let payload: Value = serde_json::from_slice(&body).expect("health json");

        assert_eq!(payload["command_metrics"]["compose_agent_count"], 1);
        assert_eq!(payload["command_metrics"]["total_count"], 1);
        assert_eq!(
            payload["command_metrics"]["last_control_plane"],
            Value::String("compose_agent".to_string())
        );
    }

    #[tokio::test]
    async fn command_metrics_handler_returns_snapshot() {
        let state = test_state(Some("status_panel"));
        record_command_execution(&state, "status_panel").await;

        let response = command_metrics_handler(State(state)).await.into_response();
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("metrics body");
        let payload: Value = serde_json::from_slice(&body).expect("metrics json");

        assert_eq!(payload["status_panel_count"], 1);
        assert_eq!(payload["compose_agent_count"], 0);
        assert_eq!(payload["total_count"], 1);
        assert_eq!(
            payload["last_control_plane"],
            Value::String("status_panel".to_string())
        );
    }

    #[tokio::test]
    async fn capabilities_include_pipe_operations() {
        let state = test_state(Some("status_panel"));

        let response = capabilities_handler(State(state)).await.into_response();
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("capabilities body");
        let payload: Value = serde_json::from_slice(&body).expect("capabilities json");
        let features = payload["features"]
            .as_array()
            .expect("features should be an array");

        assert!(features.contains(&Value::String("pipes".to_string())));
        assert!(features.contains(&Value::String("activate_pipe".to_string())));
        assert!(features.contains(&Value::String("deactivate_pipe".to_string())));
        assert!(features.contains(&Value::String("trigger_pipe".to_string())));
    }
}
