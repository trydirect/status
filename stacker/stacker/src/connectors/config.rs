use serde::{Deserialize, Serialize};

/// Configuration for external service connectors
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorConfig {
    pub user_service: Option<UserServiceConfig>,
    pub install_service: Option<InstallServiceConfig>,
    pub payment_service: Option<PaymentServiceConfig>,
    pub events: Option<EventsConfig>,
    pub dockerhub_service: Option<DockerHubConnectorConfig>,
}

/// User Service connector configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserServiceConfig {
    /// Enable/disable User Service integration
    pub enabled: bool,
    /// Base URL for User Service API (e.g., http://localhost:4100/server/user)
    pub base_url: String,
    /// HTTP request timeout in seconds
    pub timeout_secs: u64,
    /// Number of retry attempts for failed requests
    pub retry_attempts: usize,
    /// OAuth token for inter-service authentication (from env: USER_SERVICE_AUTH_TOKEN)
    #[serde(skip)]
    pub auth_token: Option<String>,
}

impl Default for UserServiceConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            base_url: "http://localhost:4100/server/user".to_string(),
            timeout_secs: 10,
            retry_attempts: 3,
            auth_token: None,
        }
    }
}

/// Install Service connector configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallServiceConfig {
    /// Enable/disable Install Service integration
    pub enabled: bool,
}

impl Default for InstallServiceConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

/// Payment Service connector configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentServiceConfig {
    /// Enable/disable Payment Service integration
    pub enabled: bool,
    /// Base URL for Payment Service API (e.g., http://localhost:8000)
    pub base_url: String,
    /// HTTP request timeout in seconds
    pub timeout_secs: u64,
    /// Bearer token for authentication
    #[serde(skip)]
    pub auth_token: Option<String>,
}

impl Default for PaymentServiceConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            base_url: "http://localhost:8000".to_string(),
            timeout_secs: 15,
            auth_token: None,
        }
    }
}

/// RabbitMQ Events configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventsConfig {
    /// Enable/disable async event publishing
    pub enabled: bool,
    /// AMQP connection string (amqp://user:password@host:port/%2f)
    pub amqp_url: String,
    /// Event exchange name
    pub exchange: String,
    /// Prefetch count for consumer
    pub prefetch: u16,
}

impl Default for EventsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            amqp_url: "amqp://guest:guest@localhost:5672/%2f".to_string(),
            exchange: "stacker_events".to_string(),
            prefetch: 10,
        }
    }
}

impl Default for ConnectorConfig {
    fn default() -> Self {
        Self {
            user_service: Some(UserServiceConfig::default()),
            install_service: Some(InstallServiceConfig::default()),
            payment_service: Some(PaymentServiceConfig::default()),
            events: Some(EventsConfig::default()),
            dockerhub_service: Some(DockerHubConnectorConfig::default()),
        }
    }
}

/// Docker Hub caching connector configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DockerHubConnectorConfig {
    /// Enable/disable Docker Hub connector
    pub enabled: bool,
    /// Docker Hub API base URL
    pub base_url: String,
    /// HTTP timeout in seconds
    pub timeout_secs: u64,
    /// Number of retry attempts for transient failures
    pub retry_attempts: usize,
    /// Page size when fetching namespaces/repositories/tags
    #[serde(default = "DockerHubConnectorConfig::default_page_size")]
    pub page_size: u32,
    /// Optional Redis connection string override
    #[serde(default)]
    pub redis_url: Option<String>,
    /// Cache TTL for namespace search results
    #[serde(default = "DockerHubConnectorConfig::default_namespaces_ttl")]
    pub cache_ttl_namespaces_secs: u64,
    /// Cache TTL for repository listings
    #[serde(default = "DockerHubConnectorConfig::default_repositories_ttl")]
    pub cache_ttl_repositories_secs: u64,
    /// Cache TTL for tag listings
    #[serde(default = "DockerHubConnectorConfig::default_tags_ttl")]
    pub cache_ttl_tags_secs: u64,
    /// Optional Docker Hub username (falls back to DOCKERHUB_USERNAME env)
    #[serde(default)]
    pub username: Option<String>,
    /// Optional Docker Hub personal access token (falls back to DOCKERHUB_TOKEN env)
    #[serde(default)]
    pub personal_access_token: Option<String>,
}

impl DockerHubConnectorConfig {
    const fn default_page_size() -> u32 {
        50
    }

    const fn default_namespaces_ttl() -> u64 {
        86_400
    }

    const fn default_repositories_ttl() -> u64 {
        21_600
    }

    const fn default_tags_ttl() -> u64 {
        3_600
    }
}

impl Default for DockerHubConnectorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            base_url: "https://hub.docker.com".to_string(),
            timeout_secs: 10,
            retry_attempts: 3,
            page_size: Self::default_page_size(),
            redis_url: Some("redis://127.0.0.1/0".to_string()),
            cache_ttl_namespaces_secs: Self::default_namespaces_ttl(),
            cache_ttl_repositories_secs: Self::default_repositories_ttl(),
            cache_ttl_tags_secs: Self::default_tags_ttl(),
            username: None,
            personal_access_token: None,
        }
    }
}
