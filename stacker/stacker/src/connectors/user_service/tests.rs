use mockito::{Matcher, Server};
use serde_json::json;
use uuid::Uuid;

use super::mock;
use super::utils::is_plan_higher_tier;
use super::{CategoryInfo, ProductInfo, UserProfile, UserServiceClient, UserServiceConnector};

/// Test that get_user_profile returns user with products list
#[tokio::test]
async fn test_mock_get_user_profile_returns_user_with_products() {
    let connector = mock::MockUserServiceConnector;
    let profile = connector.get_user_profile("test_token").await.unwrap();

    // Assertions on user profile structure
    assert_eq!(profile.email, "test@example.com");
    assert!(profile.plan.is_some());

    // Verify products list is populated
    assert!(!profile.products.is_empty());

    // Check for plan product
    let plan_product = profile.products.iter().find(|p| p.product_type == "plan");
    assert!(plan_product.is_some());
    assert_eq!(plan_product.unwrap().code, "professional");

    // Check for template product
    let template_product = profile
        .products
        .iter()
        .find(|p| p.product_type == "template");
    assert!(template_product.is_some());
    assert_eq!(template_product.unwrap().name, "AI Agent Stack Pro");
    assert_eq!(template_product.unwrap().external_id, Some(100));
}

/// Test that get_template_product returns product info for owned templates
#[tokio::test]
async fn test_mock_get_template_product_returns_product_info() {
    let connector = mock::MockUserServiceConnector;

    // Test with template ID that exists (100)
    let product = connector.get_template_product(100).await.unwrap();
    assert!(product.is_some());

    let prod = product.unwrap();
    assert_eq!(prod.id, "uuid-product-ai");
    assert_eq!(prod.name, "AI Agent Stack Pro");
    assert_eq!(prod.code, "ai-agent-stack-pro");
    assert_eq!(prod.product_type, "template");
    assert_eq!(prod.external_id, Some(100));
    assert_eq!(prod.price, Some(99.99));
    assert_eq!(prod.currency, Some("USD".to_string()));
    assert!(prod.is_active);
}

/// Test that get_template_product returns None for non-existent templates
#[tokio::test]
async fn test_mock_get_template_product_not_found() {
    let connector = mock::MockUserServiceConnector;

    // Test with non-existent template ID
    let product = connector.get_template_product(999).await.unwrap();
    assert!(product.is_none());
}

/// Test that user_owns_template correctly identifies owned templates
#[tokio::test]
async fn test_mock_user_owns_template_owned() {
    let connector = mock::MockUserServiceConnector;

    // Test with owned template ID
    let owns = connector
        .user_owns_template("test_token", "100")
        .await
        .unwrap();
    assert!(owns);

    // Test with code containing "ai-agent"
    let owns_code = connector
        .user_owns_template("test_token", "ai-agent-stack-pro")
        .await
        .unwrap();
    assert!(owns_code);
}

/// Test that user_owns_template returns false for non-owned templates
#[tokio::test]
async fn test_mock_user_owns_template_not_owned() {
    let connector = mock::MockUserServiceConnector;

    // Test with non-owned template ID
    let owns = connector
        .user_owns_template("test_token", "999")
        .await
        .unwrap();
    assert!(!owns);

    // Test with random code that doesn't match
    let owns_code = connector
        .user_owns_template("test_token", "random-template")
        .await
        .unwrap();
    assert!(!owns_code);
}

/// Test that user_has_plan always returns true in mock (for testing)
#[tokio::test]
async fn test_mock_user_has_plan() {
    let connector = mock::MockUserServiceConnector;

    let has_professional = connector
        .user_has_plan("user_123", "professional", None)
        .await
        .unwrap();
    assert!(has_professional);

    let has_enterprise = connector
        .user_has_plan("user_123", "enterprise", None)
        .await
        .unwrap();
    assert!(has_enterprise);

    let has_basic = connector
        .user_has_plan("user_123", "basic", None)
        .await
        .unwrap();
    assert!(has_basic);
}

/// Test that get_user_plan returns correct plan info
#[tokio::test]
async fn test_mock_get_user_plan() {
    let connector = mock::MockUserServiceConnector;

    let plan = connector.get_user_plan("user_123").await.unwrap();
    assert_eq!(plan.user_id, "user_123");
    assert_eq!(plan.plan_name, "professional");
    assert!(plan.plan_description.is_some());
    assert_eq!(plan.plan_description.unwrap(), "Professional Plan");
    assert!(plan.active);
}

/// Test that list_available_plans returns multiple plan definitions
#[tokio::test]
async fn test_mock_list_available_plans() {
    let connector = mock::MockUserServiceConnector;

    let plans = connector.list_available_plans().await.unwrap();
    assert!(!plans.is_empty());
    assert_eq!(plans.len(), 3);

    // Verify specific plans exist
    let plan_names: Vec<String> = plans.iter().map(|p| p.name.clone()).collect();
    assert!(plan_names.contains(&"basic".to_string()));
    assert!(plan_names.contains(&"professional".to_string()));
    assert!(plan_names.contains(&"enterprise".to_string()));
}

/// Test that get_categories returns category list
#[tokio::test]
async fn test_mock_get_categories() {
    let connector = mock::MockUserServiceConnector;

    let categories = connector.get_categories().await.unwrap();
    assert!(!categories.is_empty());
    assert_eq!(categories.len(), 3);

    // Verify specific categories exist
    let category_names: Vec<String> = categories.iter().map(|c| c.name.clone()).collect();
    assert!(category_names.contains(&"cms".to_string()));
    assert!(category_names.contains(&"ecommerce".to_string()));
    assert!(category_names.contains(&"ai".to_string()));

    // Verify category has expected fields
    let ai_category = categories.iter().find(|c| c.name == "ai").unwrap();
    assert_eq!(ai_category.title, "AI Agents");
    assert_eq!(ai_category.priority, Some(5));
}

/// Test that create_stack_from_template returns stack with marketplace info
#[tokio::test]
async fn test_mock_create_stack_from_template() {
    let connector = mock::MockUserServiceConnector;
    let template_id = Uuid::new_v4();

    let stack = connector
        .create_stack_from_template(
            &template_id,
            "user_123",
            "1.0.0",
            "My Stack",
            json!({"services": []}),
        )
        .await
        .unwrap();

    assert_eq!(stack.user_id, "user_123");
    assert_eq!(stack.name, "My Stack");
    assert_eq!(stack.marketplace_template_id, Some(template_id));
    assert!(stack.is_from_marketplace);
    assert_eq!(stack.template_version, Some("1.0.0".to_string()));
}

/// Test that get_stack returns stack details
#[tokio::test]
async fn test_mock_get_stack() {
    let connector = mock::MockUserServiceConnector;

    let stack = connector.get_stack(1, "user_123").await.unwrap();
    assert_eq!(stack.id, 1);
    assert_eq!(stack.user_id, "user_123");
    assert_eq!(stack.name, "Test Stack");
}

/// Test that list_stacks returns user's stacks
#[tokio::test]
async fn test_mock_list_stacks() {
    let connector = mock::MockUserServiceConnector;

    let stacks = connector.list_stacks("user_123").await.unwrap();
    assert!(!stacks.is_empty());
    assert_eq!(stacks[0].user_id, "user_123");
}

#[tokio::test]
async fn test_get_installation_by_hash_uses_lightweight_route() {
    let mut server = Server::new_async().await;
    let _mock = server
        .mock("GET", "/install/by-deployment-hash/dep-hash-123")
        .match_header("authorization", "Bearer test_token")
        .match_header("accept", Matcher::Any)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "_id": 13876,
                "stack_code": "caddy",
                "status": "completed",
                "cloud": "htz",
                "deployment_hash": "dep-hash-123",
                "domain": "example.com",
                "server_ip": "192.0.2.10",
                "_created": "2026-04-25T08:53:54+00:00",
                "_updated": "2026-04-25T08:54:04+00:00"
            })
            .to_string(),
        )
        .create_async()
        .await;

    let client = UserServiceClient::new_public(&server.url());
    let installation = client
        .get_installation_by_hash("test_token", "dep-hash-123")
        .await
        .unwrap();

    assert_eq!(installation.id, Some(13876));
    assert_eq!(installation.stack_code.as_deref(), Some("caddy"));
    assert_eq!(
        installation.deployment_hash.as_deref(),
        Some("dep-hash-123")
    );
}

#[tokio::test]
async fn test_get_installation_falls_back_to_legacy_install_route() {
    let mut server = Server::new_async().await;
    let _api_mock = server
        .mock("GET", "/api/1.0/installations/66")
        .match_header("authorization", "Bearer test_token")
        .with_status(404)
        .with_header("content-type", "application/json")
        .with_body(json!({ "_status": "ERR" }).to_string())
        .create_async()
        .await;
    let _legacy_mock = server
        .mock("GET", "/install/66")
        .match_header("authorization", "Bearer test_token")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "_status": "OK",
                "installation": {
                    "id": 66,
                    "status": "completed",
                    "deployment_hash": "dep-hash-66",
                    "request_dump": {
                        "stack_code": "coolify",
                        "provider": "htz",
                        "commonDomain": "example.com",
                        "server_ip": "192.0.2.66"
                    }
                },
                "agent_config": {
                    "token": "agent-token"
                }
            })
            .to_string(),
        )
        .create_async()
        .await;

    let client = UserServiceClient::new_public(&server.url());
    let installation = client.get_installation("test_token", 66).await.unwrap();

    assert_eq!(installation.id, Some(66));
    assert_eq!(installation.stack_code.as_deref(), Some("coolify"));
    assert_eq!(installation.cloud.as_deref(), Some("htz"));
    assert_eq!(installation.domain.as_deref(), Some("example.com"));
    assert_eq!(installation.server_ip.as_deref(), Some("192.0.2.66"));
    assert!(installation.agent_config.is_some());
}

#[tokio::test]
async fn test_get_subscription_plan_accepts_wrapped_user_profile() {
    let mut server = Server::new_async().await;
    let _mock = server
        .mock("GET", "/oauth_server/api/me")
        .match_header("authorization", "Bearer test_token")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "item": {
                    "_id": "user-1",
                    "plan": {
                        "name": "Free",
                        "code": "plan-free-periodically",
                        "includes": [
                            { "code": "deploys-20", "name": "20 deploys per month" }
                        ],
                        "active": true,
                        "price": "0.00"
                    }
                }
            })
            .to_string(),
        )
        .create_async()
        .await;

    let client = UserServiceClient::new_public(&server.url());
    let plan = client.get_subscription_plan("test_token").await.unwrap();

    assert_eq!(plan.name.as_deref(), Some("Free"));
    assert_eq!(plan.code.as_deref(), Some("plan-free-periodically"));
    assert!(plan.includes.unwrap().is_array());
}

/// Test plan hierarchy comparison
#[test]
fn test_is_plan_higher_tier_hierarchy() {
    // Enterprise user can access professional tier
    assert!(is_plan_higher_tier("enterprise", "professional"));

    // Enterprise user can access basic tier
    assert!(is_plan_higher_tier("enterprise", "basic"));

    // Professional user can access basic tier
    assert!(is_plan_higher_tier("professional", "basic"));

    // Basic user cannot access professional
    assert!(!is_plan_higher_tier("basic", "professional"));

    // Basic user cannot access enterprise
    assert!(!is_plan_higher_tier("basic", "enterprise"));

    // Same plan satisfies the requirement
    assert!(is_plan_higher_tier("professional", "professional"));

    // Free plan user can access free tier
    assert!(is_plan_higher_tier("free", "free"));

    // Free plan user cannot access basic or higher
    assert!(!is_plan_higher_tier("free", "basic"));

    // Any paid plan satisfies free requirement
    assert!(is_plan_higher_tier("basic", "free"));
    assert!(is_plan_higher_tier("professional", "free"));
    assert!(is_plan_higher_tier("enterprise", "free"));

    // Case-insensitive comparison
    assert!(is_plan_higher_tier("Professional", "professional"));
    assert!(is_plan_higher_tier("ENTERPRISE", "basic"));
}

/// Test UserProfile deserialization with all fields
#[test]
fn test_user_profile_deserialization() {
    let json = json!({
        "email": "alice@example.com",
        "plan": {
            "name": "professional",
            "date_end": "2026-12-31"
        },
        "products": [
            {
                "id": "prod-1",
                "name": "Professional Plan",
                "code": "professional",
                "product_type": "plan",
                "external_id": null,
                "owned_since": "2025-01-01T00:00:00Z"
            },
            {
                "id": "prod-2",
                "name": "AI Stack",
                "code": "ai-stack",
                "product_type": "template",
                "external_id": 42,
                "owned_since": "2025-01-15T00:00:00Z"
            }
        ]
    });

    let profile: UserProfile = serde_json::from_value(json).unwrap();
    assert_eq!(profile.email, "alice@example.com");
    assert_eq!(profile.products.len(), 2);
    assert_eq!(profile.products[0].code, "professional");
    assert_eq!(profile.products[1].external_id, Some(42));
}

/// Test ProductInfo with optional fields
#[test]
fn test_product_info_deserialization() {
    let json = json!({
        "id": "product-123",
        "name": "AI Stack Template",
        "code": "ai-stack-template",
        "product_type": "template",
        "external_id": 42,
        "price": 99.99,
        "billing_cycle": "one_time",
        "currency": "USD",
        "vendor_id": 123,
        "is_active": true
    });

    let product: ProductInfo = serde_json::from_value(json).unwrap();
    assert_eq!(product.id, "product-123");
    assert_eq!(product.price, Some(99.99));
    assert_eq!(product.external_id, Some(42));
    assert_eq!(product.currency, Some("USD".to_string()));
}

/// Test CategoryInfo deserialization
#[test]
fn test_category_info_deserialization() {
    let json = json!({
        "_id": 5,
        "name": "ai",
        "title": "AI Agents",
        "priority": 5
    });

    let category: CategoryInfo = serde_json::from_value(json).unwrap();
    assert_eq!(category.id, 5);
    assert_eq!(category.name, "ai");
    assert_eq!(category.title, "AI Agents");
    assert_eq!(category.priority, Some(5));
}
