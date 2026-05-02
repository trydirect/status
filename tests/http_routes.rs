use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::Value;
use status_panel::agent::config::{Config, ReqData};
use status_panel::comms::local_api::{create_router, AppState};
use std::sync::Arc;
use std::sync::{Mutex, OnceLock};
use tower::ServiceExt;

// Serialize tests that modify env vars
static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
fn lock_env() -> std::sync::MutexGuard<'static, ()> {
    match ENV_LOCK.get_or_init(|| Mutex::new(())).lock() {
        Ok(g) => g,
        Err(e) => e.into_inner(),
    }
}

// Helper to create test config
fn test_config() -> Arc<Config> {
    Arc::new(Config {
        domain: Some("test.example.com".to_string()),
        subdomains: None,
        apps_info: None,
        reqdata: ReqData {
            email: "test@example.com".to_string(),
        },
        ssl: Some("letsencrypt".to_string()),
        compose_agent_enabled: false,
        control_plane: None,
        firewall: None,
    })
}

// Helper to create router without UI
fn test_router() -> Router {
    let state = Arc::new(AppState::new(test_config(), false, None));
    create_router(state)
}

#[tokio::test]
async fn test_health_endpoint() {
    let app = test_router();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_capabilities_endpoint() {
    let app = test_router();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/capabilities")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
    let value: Value = serde_json::from_slice(&body_bytes).unwrap();

    assert_eq!(value["compose_agent"], Value::Bool(false));
    assert_eq!(
        value["control_plane"],
        Value::String("status_panel".to_string())
    );
    assert!(value.get("features").is_some());
}

#[tokio::test]
async fn given_capabilities_request_when_agent_supports_pipe_runtime_then_pipe_features_are_advertised(
) {
    let app = test_router();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/capabilities")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
    let value: Value = serde_json::from_slice(&body_bytes).unwrap();
    let features = value["features"].as_array().expect("features array");

    assert!(features.contains(&Value::String("pipes".to_string())));
    assert!(features.contains(&Value::String("activate_pipe".to_string())));
    assert!(features.contains(&Value::String("deactivate_pipe".to_string())));
    assert!(features.contains(&Value::String("trigger_pipe".to_string())));
}

#[tokio::test]
async fn test_login_page_get() {
    let app = test_router();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/login")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body = String::from_utf8(body_bytes.to_vec()).unwrap();
    assert!(body.contains("username"));
}

#[tokio::test]
async fn test_login_post_success() {
    let _g = lock_env();
    // Set credentials explicitly — no defaults exist
    std::env::set_var("STATUS_PANEL_USERNAME", "admin");
    std::env::set_var("STATUS_PANEL_PASSWORD", "admin123");

    let app = test_router();

    let body = "username=admin&password=admin123";
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    // Should redirect to home (UI mode) or return 200 (API mode)
    assert!(
        response.status() == StatusCode::SEE_OTHER || response.status() == StatusCode::OK,
        "Expected 303 (UI) or 200 (API), got {}",
        response.status()
    );

    std::env::remove_var("STATUS_PANEL_USERNAME");
    std::env::remove_var("STATUS_PANEL_PASSWORD");
}

#[tokio::test]
async fn test_login_post_failure() {
    let _g = lock_env();
    std::env::set_var("STATUS_PANEL_USERNAME", "admin");
    std::env::set_var("STATUS_PANEL_PASSWORD", "admin123");

    let app = test_router();

    let body = "username=wrong&password=wrongpwd";
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    std::env::remove_var("STATUS_PANEL_USERNAME");
    std::env::remove_var("STATUS_PANEL_PASSWORD");
}

#[tokio::test]
async fn test_logout_endpoint() {
    let app = test_router();

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/logout")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_metrics_endpoint() {
    let app = test_router();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/metrics")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

    assert!(json.get("timestamp_ms").is_some());
    assert!(json.get("cpu_usage_pct").is_some());
}

#[tokio::test]
#[cfg(feature = "docker")]
async fn test_home_endpoint() {
    let app = test_router();

    let response = app
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();

    // Should return 200 with container list (or error if Docker not available)
    assert!(
        response.status() == StatusCode::OK
            || response.status() == StatusCode::INTERNAL_SERVER_ERROR
    );
}

#[cfg(feature = "docker")]
#[tokio::test]
async fn test_restart_endpoint() {
    let app = test_router();

    // Without auth, should get UNAUTHORIZED or redirect to login
    let response = app
        .oneshot(
            Request::builder()
                .uri("/restart/test-container")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert!(
        response.status() == StatusCode::UNAUTHORIZED || response.status() == StatusCode::SEE_OTHER,
        "Expected UNAUTHORIZED or redirect, got {}",
        response.status()
    );
}

#[cfg(feature = "docker")]
#[tokio::test]
async fn test_stack_health_endpoint() {
    let app = test_router();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/stack/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert!(
        response.status() == StatusCode::OK
            || response.status() == StatusCode::INTERNAL_SERVER_ERROR
    );
}

#[cfg(feature = "docker")]
#[tokio::test]
async fn test_index_template_renders() {
    use status_panel::agent::docker::{ContainerInfo, PortInfo};
    let tera = tera::Tera::new("templates/**/*.html").unwrap();

    let containers = vec![ContainerInfo {
        name: "demo".to_string(),
        status: "running".to_string(),
        logs: String::new(),
        ports: vec![PortInfo {
            port: "8081".to_string(),
            title: Some("demo".to_string()),
        }],
    }];

    let apps_info = vec![status_panel::agent::config::AppInfo {
        name: "app".into(),
        version: "1.0".into(),
    }];

    let mut context = tera::Context::new();
    context.insert("container_list", &containers);
    context.insert("apps_info", &apps_info);
    context.insert("errors", &Option::<String>::None);
    context.insert("ip", &Option::<String>::None);
    context.insert("domainIp", &Option::<String>::None);
    context.insert("panel_version", &"test".to_string());
    context.insert("domain", &Some("example.com".to_string()));
    context.insert("ssl_enabled", &false);
    context.insert("can_enable", &false);
    context.insert("ip_help_link", &"https://www.whatismyip.com/");

    let html = tera.render("index.html", &context);
    assert!(html.is_ok(), "template error: {:?}", html.err());
}

#[tokio::test]
async fn test_backup_ping_success() {
    use serde_json::json;
    use status_panel::agent::backup::BackupSigner;

    // Set required environment variables
    std::env::set_var("DEPLOYMENT_HASH", "test_deployment_hash");
    std::env::set_var("TRYDIRECT_IP", "127.0.0.1");

    let app = test_router();

    // Create a valid hash
    let signer = BackupSigner::new(b"test_deployment_hash");
    let valid_hash = signer.sign("test_deployment_hash").unwrap();

    let payload = json!({"hash": valid_hash});

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/backup/ping")
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["status"], "OK");
    assert!(json["hash"].is_string());
}

#[tokio::test]
async fn test_backup_ping_with_deployment_hash() {
    use serde_json::json;

    // Set required environment variables
    std::env::set_var("DEPLOYMENT_HASH", "test_deployment_hash");
    std::env::set_var("TRYDIRECT_IP", "127.0.0.1");

    let app = test_router();

    // Test with plain deployment hash (Flask compatibility)
    let payload = json!({"hash": "test_deployment_hash"});

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/backup/ping")
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["status"], "OK");
    assert!(json["hash"].is_string());
}

#[tokio::test]
async fn test_backup_ping_invalid_hash() {
    use serde_json::json;

    std::env::set_var("DEPLOYMENT_HASH", "test_deployment_hash");
    std::env::set_var("TRYDIRECT_IP", "127.0.0.1");

    let app = test_router();

    let payload = json!({"hash": "invalid_hash_value"});

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/backup/ping")
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
#[ignore]
async fn test_backup_download_file_not_found() {
    use status_panel::agent::backup::BackupSigner;

    std::env::set_var("DEPLOYMENT_HASH", "test_deployment_hash");
    let unique = format!(
        "/tmp/nonexistent_backup_{}.tar.gz.cpt",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    );
    std::env::set_var("BACKUP_PATH", unique);

    let app = test_router();

    // Create valid hash
    let signer = BackupSigner::new(b"test_deployment_hash");
    let valid_hash = signer.sign("test_deployment_hash").unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/backup/{}/127.0.0.1", valid_hash))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_backup_download_success() {
    use status_panel::agent::backup::BackupSigner;
    use std::io::Write;
    use tempfile::NamedTempFile;

    std::env::set_var("DEPLOYMENT_HASH", "test_deployment_hash");

    // Create a temporary backup file
    let mut temp_file = NamedTempFile::new().unwrap();
    write!(temp_file, "test backup content").unwrap();
    let temp_path = temp_file.path().to_str().unwrap().to_string();
    std::env::set_var("BACKUP_PATH", &temp_path);

    let app = test_router();

    // Create valid hash
    let signer = BackupSigner::new(b"test_deployment_hash");
    let valid_hash = signer.sign("test_deployment_hash").unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/backup/{}/127.0.0.1", valid_hash))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    // Check headers
    assert_eq!(
        response.headers().get("content-type").unwrap(),
        "application/octet-stream"
    );
    assert!(response.headers().get("content-disposition").is_some());

    // Check body content
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body.as_ref(), b"test backup content");
}

// ---- Notification endpoint tests ----

#[tokio::test]
async fn test_notifications_unread_count_starts_at_zero() {
    let app = test_router();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/notifications/unread-count")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["unread_count"], 0);
}

#[tokio::test]
async fn test_notifications_list_empty() {
    let app = test_router();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/notifications")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["unread_count"], 0);
    assert_eq!(json["notifications"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn test_notifications_mark_read_all_on_empty() {
    let app = test_router();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/notifications/read")
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"all": true}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "ok");
}

#[tokio::test]
async fn test_notifications_full_lifecycle() {
    use status_panel::comms::notifications::{self, Notification, NotificationKind};

    let state = Arc::new(AppState::new(test_config(), false, None));
    let app = create_router(state.clone());

    // Seed notifications into the store directly
    let notifs = vec![
        Notification {
            id: "test-1".to_string(),
            kind: NotificationKind::StackUpdateAvailable,
            title: "Update for MyStack".to_string(),
            message: "Version 2.0 is available".to_string(),
            stack_id: Some("stack-1".to_string()),
            stack_name: Some("MyStack".to_string()),
            new_version: Some("2.0".to_string()),
            created_at: "2026-04-12T00:00:00Z".to_string(),
            read: false,
        },
        Notification {
            id: "test-2".to_string(),
            kind: NotificationKind::StackPublished,
            title: "New stack: CoolApp".to_string(),
            message: "CoolApp has been published".to_string(),
            stack_id: Some("stack-2".to_string()),
            stack_name: Some("CoolApp".to_string()),
            new_version: None,
            created_at: "2026-04-12T01:00:00Z".to_string(),
            read: false,
        },
    ];
    notifications::merge_notifications(&state.notification_store, notifs).await;

    // Check unread count = 2
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/notifications/unread-count")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["unread_count"], 2);

    // List all notifications
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/notifications")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["unread_count"], 2);
    assert_eq!(json["notifications"].as_array().unwrap().len(), 2);

    // Mark one as read
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/notifications/read")
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"ids": ["test-1"]}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Unread count should now be 1
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/notifications/unread-count")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["unread_count"], 1);

    // Mark all as read
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/notifications/read")
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"all": true}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Unread count should now be 0
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/notifications/unread-count")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["unread_count"], 0);
}
