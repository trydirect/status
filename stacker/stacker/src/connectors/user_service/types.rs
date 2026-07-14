use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Response from User Service when creating a stack from marketplace template
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackResponse {
    pub id: i32,
    pub user_id: String,
    pub name: String,
    pub marketplace_template_id: Option<Uuid>,
    pub is_from_marketplace: bool,
    pub template_version: Option<String>,
}

/// User's current plan information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserPlanInfo {
    pub user_id: String,
    pub plan_name: String,
    pub plan_description: Option<String>,
    pub tier: Option<String>,
    pub active: bool,
    pub started_at: Option<String>,
    pub expires_at: Option<String>,
}

/// Available plan definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanDefinition {
    pub name: String,
    pub description: Option<String>,
    pub tier: Option<String>,
    pub features: Option<serde_json::Value>,
}

/// Product owned by a user (from /oauth_server/api/me response)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserProduct {
    pub id: Option<String>,
    pub name: String,
    pub code: String,
    pub product_type: String,
    #[serde(default)]
    pub external_id: Option<i32>, // Stack template ID from Stacker
    #[serde(default)]
    pub owned_since: Option<String>,
}

/// User profile with ownership information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserProfile {
    pub email: String,
    pub plan: Option<serde_json::Value>, // Plan details from existing endpoint
    #[serde(default)]
    pub products: Vec<UserProduct>, // List of owned products
}

/// Product information from User Service catalog
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProductInfo {
    pub id: String,
    pub name: String,
    pub code: String,
    pub product_type: String,
    pub external_id: Option<i32>,
    pub price: Option<f64>,
    pub billing_cycle: Option<String>,
    pub currency: Option<String>,
    pub vendor_id: Option<i32>,
    pub is_active: bool,
}

/// Category information from User Service
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategoryInfo {
    #[serde(rename = "_id")]
    pub id: i32,
    pub name: String,
    pub title: String,
    #[serde(default)]
    pub priority: Option<i32>,
}
