use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use tower::ServiceExt;
use std::sync::Arc;
use serde_json::Value;
use status_panel::agent::config::{Config, ReqData};
use status_panel::comms::local_api::{create_router, AppState};

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
        .oneshot(
            Request::builder()
                .uri("/")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Should return 200 with container list (or error if Docker not available)
    assert!(response.status() == StatusCode::OK || response.status() == StatusCode::INTERNAL_SERVER_ERROR);
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
    assert!(response.status() == StatusCode::OK || response.status() == StatusCode::INTERNAL_SERVER_ERROR);
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

        assert!(response.status() == StatusCode::OK || response.status() == StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[cfg(feature = "docker")]
    #[tokio::test]
    async fn test_index_template_renders() {
        use status_panel::agent::docker::{ContainerInfo, PortInfo};
        let mut tera = tera::Tera::new("templates/**/*.html").unwrap();

        let containers = vec![ContainerInfo {
            name: "demo".to_string(),
            status: "running".to_string(),
            logs: String::new(),
            ports: vec![PortInfo { port: "8081".to_string(), title: Some("demo".to_string()) }],
        }];

        let apps_info = vec![status_panel::agent::config::AppInfo { name: "app".into(), version: "1.0".into() }];

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
