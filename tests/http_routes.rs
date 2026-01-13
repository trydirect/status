use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::Value;
use status_panel::agent::config::{Config, ReqData};
use status_panel::comms::local_api::{create_router, AppState};
use std::sync::Arc;
use tower::ServiceExt;

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
    })
}

// Helper to create router without UI
fn test_router() -> Router {
    let state = Arc::new(AppState::new(test_config(), false));
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
    // Ensure no environment variables interfere
    std::env::remove_var("STATUS_PANEL_USERNAME");
    std::env::remove_var("STATUS_PANEL_PASSWORD");

    let app = test_router();

    let body = "username=admin&password=admin";
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

    // Should redirect to home on successful login
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn test_login_post_failure() {
    let app = test_router();

    let body = "username=wrong&password=wrong";
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

    let response = app
        .oneshot(
            Request::builder()
                .uri("/restart/test-container")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Will fail if container doesn't exist, but route should be valid
    assert!(
        response.status() == StatusCode::OK
            || response.status() == StatusCode::INTERNAL_SERVER_ERROR
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
