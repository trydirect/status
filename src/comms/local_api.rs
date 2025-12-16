use anyhow::Result;
use axum::{
    routing::{get, post},
    Router, response::IntoResponse, extract::Path,
    http::StatusCode, Json, response::Html, response::Redirect,
    extract::Form, extract::ConnectInfo, extract::State, extract::WebSocketUpgrade,
};
use axum::extract::ws::{Message, WebSocket};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use std::future::IntoFuture;
use tracing::{info, error, debug};
use tera::Tera;
use tokio::sync::broadcast;

use crate::agent::config::Config;
use crate::agent::backup::BackupSigner;
use crate::security::auth::{SessionStore, SessionUser, Credentials};
use crate::monitoring::{MetricsCollector, MetricsSnapshot, MetricsStore, MetricsTx, spawn_heartbeat};
#[cfg(feature = "docker")]
use crate::agent::docker;

type SharedState = Arc<AppState>;

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
        
        Self {
            session_store: SessionStore::new(),
            config,
            templates,
            with_ui,
            metrics_collector: Arc::new(MetricsCollector::new()),
            metrics_store: Arc::new(tokio::sync::RwLock::new(MetricsSnapshot::default())),
            metrics_tx: broadcast::channel(32).0,
            metrics_webhook: std::env::var("METRICS_WEBHOOK").ok(),
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

// Health check
async fn health() -> impl IntoResponse {
    Json(json!({"status": "ok"}))
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
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(req): Json<BackupPingRequest>,
) -> Result<impl IntoResponse, impl IntoResponse> {
    let allowed_ip = std::env::var("TRYDIRECT_IP").ok();
    let request_ip = addr.ip().to_string();

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

    // Verify the provided hash
    match signer.verify(&req.hash, 1800) {
        Ok(_) => {
            // Generate new hash
            let new_hash = signer.sign(&deployment_hash)
                .unwrap_or_else(|_| req.hash.clone());
            
            debug!("Backup ping verified from {}", request_ip);
            Ok(Json(BackupPingResponse {
                status: "OK".to_string(),
                hash: Some(new_hash),
            }))
        }
        Err(_) => {
            error!("Invalid backup ping hash from {}", request_ip);
            Err((
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "Invalid hash".to_string(),
                }),
            ))
        }
    }
}

// Backup download endpoint - send backup file with hash/IP verification
async fn backup_download(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path((hash, target_ip)): Path<(String, String)>,
) -> Result<impl IntoResponse, impl IntoResponse> {
    let request_ip = addr.ip().to_string();

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
            // Check if backup file exists
            let backup_path = std::env::var("BACKUP_PATH")
                .unwrap_or_else(|_| "/data/encrypted/backup.tar.gz.cpt".to_string());

            if !std::path::Path::new(&backup_path).exists() {
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
                    debug!("Backup downloaded by {}", request_ip);
                    Ok((
                        StatusCode::OK,
                        [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
                        content,
                    ))
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

    #[cfg(feature = "docker")]
    {
        router = router
            .route("/", get(home))
            .route("/restart/{name}", get(restart_container))
            .route("/stop/{name}", get(stop_container))
            .route("/pause/{name}", get(pause_container))
            .route("/stack/health", get(stack_health));
    }

    // Add static file serving when UI is enabled
    if state.with_ui {
        use tower_http::services::ServeDir;
        router = router.nest_service("/static", ServeDir::new("static"));
    }

    router.with_state(state)
}

pub async fn serve(config: Config, port: u16, with_ui: bool) -> Result<()> {
    let cfg = Arc::new(config);
    let state = Arc::new(AppState::new(cfg, with_ui));

    let heartbeat_interval = Duration::from_secs(30);
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
