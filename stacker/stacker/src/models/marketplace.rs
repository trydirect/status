use chrono::{DateTime, Utc};
use serde_derive::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default, sqlx::FromRow)]
pub struct StackCategory {
    pub id: i32,
    pub name: String,
    pub title: Option<String>,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default, sqlx::FromRow)]
pub struct StackTemplate {
    pub id: Uuid,
    pub creator_user_id: String,
    pub creator_name: Option<String>,
    pub name: String,
    pub slug: String,
    pub short_description: Option<String>,
    pub long_description: Option<String>,
    pub category_code: Option<String>,
    pub product_id: Option<i32>,
    pub tags: serde_json::Value,
    pub tech_stack: serde_json::Value,
    pub status: String,
    pub is_configurable: Option<bool>,
    pub view_count: Option<i32>,
    pub deploy_count: Option<i32>,
    pub required_plan_name: Option<String>,
    pub price: Option<f64>,
    pub billing_cycle: Option<String>,
    pub currency: Option<String>,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
    pub approved_at: Option<DateTime<Utc>>,
    pub verifications: serde_json::Value,
    pub infrastructure_requirements: serde_json::Value,
    pub public_ports: Option<serde_json::Value>,
    pub vendor_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[sqlx(default)]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[sqlx(default)]
    pub changelog: Option<String>,
    #[serde(default)]
    #[sqlx(default)]
    pub config_files: serde_json::Value,
    #[serde(default)]
    #[sqlx(default)]
    pub assets: serde_json::Value,
    #[serde(default)]
    #[sqlx(default)]
    pub seed_jobs: serde_json::Value,
    #[serde(default)]
    #[sqlx(default)]
    pub post_deploy_hooks: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[sqlx(default)]
    pub update_mode_capabilities: Option<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct InfrastructureRequirements {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supported_clouds: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supported_os: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_ram_mb: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_disk_gb: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_cpu_cores: Option<i32>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default, sqlx::FromRow)]
pub struct StackTemplateVersion {
    pub id: Uuid,
    pub template_id: Uuid,
    pub version: String,
    pub stack_definition: serde_json::Value,
    #[serde(default)]
    pub config_files: serde_json::Value,
    pub assets: serde_json::Value,
    #[serde(default)]
    pub seed_jobs: serde_json::Value,
    #[serde(default)]
    pub post_deploy_hooks: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub update_mode_capabilities: Option<serde_json::Value>,
    pub definition_format: Option<String>,
    pub changelog: Option<String>,
    pub is_latest: Option<bool>,
    pub created_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct MarketplaceAsset {
    pub storage_provider: String,
    pub bucket: String,
    pub key: String,
    pub filename: String,
    pub sha256: String,
    pub size: i64,
    pub content_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mount_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fetch_target: Option<String>,
    #[serde(default)]
    pub decompress: bool,
    #[serde(default)]
    pub executable: bool,
    #[serde(default = "default_true")]
    pub immutable: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default, sqlx::FromRow)]
pub struct StackTemplateReview {
    pub id: Uuid,
    pub template_id: Uuid,
    pub reviewer_user_id: Option<String>,
    pub decision: String,
    pub review_reason: Option<String>,
    pub security_checklist: Option<serde_json::Value>,
    pub submitted_at: Option<DateTime<Utc>>,
    pub reviewed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default, sqlx::FromRow)]
pub struct MarketplaceVendorProfile {
    pub creator_user_id: String,
    pub verification_status: String,
    pub onboarding_status: String,
    pub payouts_enabled: bool,
    pub payout_provider: Option<String>,
    pub payout_account_ref: Option<String>,
    pub metadata: serde_json::Value,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
}

impl MarketplaceVendorProfile {
    pub fn default_for_creator(creator_user_id: &str) -> Self {
        Self {
            creator_user_id: creator_user_id.to_string(),
            verification_status: "unverified".to_string(),
            onboarding_status: "not_started".to_string(),
            payouts_enabled: false,
            payout_provider: None,
            payout_account_ref: None,
            metadata: serde_json::json!({}),
            created_at: None,
            updated_at: None,
        }
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Analytics Models (TDD: defined for test compilation)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Marketplace event for analytics tracking
/// Tracks view and deploy events with template_id, user, cloud_provider, timestamp, metadata
/// NOTE: Does NOT include finance fields (no amount, revenue, payout, withdrawal, balance)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, sqlx::FromRow)]
pub struct MarketplaceEvent {
    pub id: Uuid,
    pub template_id: Uuid,
    pub event_type: String, // "view" or "deploy"
    pub viewer_user_id: Option<String>,
    pub deployer_user_id: Option<String>,
    pub cloud_provider: Option<String>,
    pub occurred_at: DateTime<Utc>,
    pub metadata: serde_json::Value,
}

/// Vendor analytics response model
/// Contains usage metrics only - NO finance fields
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VendorAnalytics {
    pub creator_id: String,
    pub period: AnalyticsPeriod,
    pub summary: AnalyticsSummary,
    pub views_series: Vec<SeriesBucket>,
    pub deployments_series: Vec<SeriesBucket>,
    pub cloud_breakdown: Vec<CloudBreakdown>,
    pub top_templates: Vec<TemplatePerformance>,
    pub templates: Vec<TemplateAnalytics>,
}

/// Analytics period definition
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalyticsPeriod {
    pub key: String, // "7d", "30d", "90d", "all", "custom"
    pub start_date: Option<DateTime<Utc>>,
    pub end_date: Option<DateTime<Utc>>,
    pub bucket: String, // "day", "week", "month", "all"
}

/// Analytics summary metrics
/// NOTE: Does NOT include finance fields (no totalEarnings, revenue, earnings, payout)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalyticsSummary {
    pub total_views: i64,
    pub total_deployments: i64,
    pub conversion_rate: f64,
    pub published_templates: i32,
    pub top_cloud: Option<String>,
    pub top_template_id: Option<Uuid>,
}

/// Time series bucket for views/deployments
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SeriesBucket {
    pub bucket_start: DateTime<Utc>,
    pub bucket_end: DateTime<Utc>,
    pub count: i64,
}

/// Cloud provider deployment breakdown
/// NOTE: Does NOT include finance fields (no revenue, earnings)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudBreakdown {
    pub cloud_provider: String,
    pub deployments: i64,
    pub percentage: f64,
}

/// Template performance metrics for top templates
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TemplatePerformance {
    pub template_id: Uuid,
    pub slug: String,
    pub name: String,
    pub views: i64,
    pub deployments: i64,
    pub conversion_rate: f64,
}

/// Template analytics with full details
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TemplateAnalytics {
    pub template_id: Uuid,
    pub creator_user_id: String,
    pub slug: String,
    pub name: String,
    pub status: String,
    pub views: i64,
    pub deployments: i64,
    pub conversion_rate: f64,
}

#[cfg(test)]
mod tests {
    use super::{InfrastructureRequirements, MarketplaceVendorProfile};

    #[test]
    fn infrastructure_requirements_default_is_empty() {
        let requirements = InfrastructureRequirements::default();

        assert!(requirements.supported_clouds.is_empty());
        assert!(requirements.supported_os.is_empty());
        assert_eq!(None, requirements.min_ram_mb);
        assert_eq!(None, requirements.min_disk_gb);
        assert_eq!(None, requirements.min_cpu_cores);
    }

    #[test]
    fn infrastructure_requirements_round_trip_serialization() {
        let requirements = InfrastructureRequirements {
            supported_clouds: vec!["hetzner".to_string(), "aws".to_string()],
            supported_os: vec!["ubuntu-22.04".to_string()],
            min_ram_mb: Some(2048),
            min_disk_gb: Some(20),
            min_cpu_cores: Some(2),
        };

        let value = serde_json::to_value(&requirements).expect("serialize requirements");
        let round_trip: InfrastructureRequirements =
            serde_json::from_value(value).expect("deserialize requirements");

        assert_eq!(requirements, round_trip);
    }

    #[test]
    fn infrastructure_requirements_partial_json_deserializes() {
        let requirements: InfrastructureRequirements =
            serde_json::from_value(serde_json::json!({ "min_ram_mb": 512 }))
                .expect("deserialize partial requirements");

        assert!(requirements.supported_clouds.is_empty());
        assert!(requirements.supported_os.is_empty());
        assert_eq!(Some(512), requirements.min_ram_mb);
        assert_eq!(None, requirements.min_disk_gb);
        assert_eq!(None, requirements.min_cpu_cores);
    }

    #[test]
    fn marketplace_vendor_profile_default_for_creator_is_safe() {
        let profile = MarketplaceVendorProfile::default_for_creator("creator-1");

        assert_eq!("creator-1", profile.creator_user_id);
        assert_eq!("unverified", profile.verification_status);
        assert_eq!("not_started", profile.onboarding_status);
        assert!(!profile.payouts_enabled);
        assert_eq!(serde_json::json!({}), profile.metadata);
    }
}
