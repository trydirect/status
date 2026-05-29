use crate::connectors::ConnectorConfig;
use serde;

#[derive(Clone, serde::Deserialize)]
pub struct Settings {
    pub database: DatabaseSettings,
    pub app_port: u16,
    pub app_host: String,
    pub auth_url: String,
    #[serde(default = "Settings::default_auth_request_timeout_secs")]
    pub auth_request_timeout_secs: u64,
    #[serde(default = "Settings::default_auth_connect_timeout_secs")]
    pub auth_connect_timeout_secs: u64,
    #[serde(default = "Settings::default_user_service_url")]
    pub user_service_url: String,
    pub max_clients_number: i64,
    #[serde(default = "Settings::default_agent_command_poll_timeout_secs")]
    pub agent_command_poll_timeout_secs: u64,
    #[serde(default = "Settings::default_agent_command_poll_interval_secs")]
    pub agent_command_poll_interval_secs: u64,
    #[serde(default = "Settings::default_casbin_reload_enabled")]
    pub casbin_reload_enabled: bool,
    #[serde(default = "Settings::default_casbin_reload_interval_secs")]
    pub casbin_reload_interval_secs: u64,
    #[serde(default)]
    pub amqp: AmqpSettings,
    #[serde(default)]
    pub vault: VaultSettings,
    #[serde(default)]
    pub connectors: ConnectorConfig,
    #[serde(default)]
    pub deployment: DeploymentSettings,
    #[serde(default)]
    pub marketplace_assets: MarketplaceAssetSettings,
}

impl std::fmt::Debug for Settings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Settings")
            .field("database", &self.database)
            .field("app_port", &self.app_port)
            .field("app_host", &self.app_host)
            .field("auth_url", &self.auth_url)
            .field("auth_request_timeout_secs", &self.auth_request_timeout_secs)
            .field("auth_connect_timeout_secs", &self.auth_connect_timeout_secs)
            .field("user_service_url", &self.user_service_url)
            .field("max_clients_number", &self.max_clients_number)
            .field(
                "agent_command_poll_timeout_secs",
                &self.agent_command_poll_timeout_secs,
            )
            .field(
                "agent_command_poll_interval_secs",
                &self.agent_command_poll_interval_secs,
            )
            .field("casbin_reload_enabled", &self.casbin_reload_enabled)
            .field(
                "casbin_reload_interval_secs",
                &self.casbin_reload_interval_secs,
            )
            .field("amqp", &self.amqp)
            .field("vault", &self.vault)
            .field("connectors", &self.connectors)
            .field("deployment", &self.deployment)
            .field("marketplace_assets", &self.marketplace_assets)
            .finish()
    }
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            database: DatabaseSettings::default(),
            app_port: 8000,
            app_host: "127.0.0.1".to_string(),
            auth_url: "http://localhost:8080/me".to_string(),
            auth_request_timeout_secs: Self::default_auth_request_timeout_secs(),
            auth_connect_timeout_secs: Self::default_auth_connect_timeout_secs(),
            user_service_url: Self::default_user_service_url(),
            max_clients_number: 10,
            agent_command_poll_timeout_secs: Self::default_agent_command_poll_timeout_secs(),
            agent_command_poll_interval_secs: Self::default_agent_command_poll_interval_secs(),
            casbin_reload_enabled: Self::default_casbin_reload_enabled(),
            casbin_reload_interval_secs: Self::default_casbin_reload_interval_secs(),
            amqp: AmqpSettings::default(),
            vault: VaultSettings::default(),
            connectors: ConnectorConfig::default(),
            deployment: DeploymentSettings::default(),
            marketplace_assets: MarketplaceAssetSettings::default(),
        }
    }
}

impl Settings {
    fn default_user_service_url() -> String {
        "http://user:4100".to_string()
    }

    fn default_auth_request_timeout_secs() -> u64 {
        5
    }

    fn default_auth_connect_timeout_secs() -> u64 {
        2
    }

    fn default_agent_command_poll_timeout_secs() -> u64 {
        30
    }

    fn default_agent_command_poll_interval_secs() -> u64 {
        3
    }

    fn default_casbin_reload_enabled() -> bool {
        true
    }

    fn default_casbin_reload_interval_secs() -> u64 {
        10
    }
}

#[derive(serde::Deserialize, Clone)]
pub struct DatabaseSettings {
    pub username: String,
    pub password: String,
    pub host: String,
    pub port: u16,
    pub database_name: String,
}

impl std::fmt::Debug for DatabaseSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DatabaseSettings")
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("database_name", &self.database_name)
            .finish()
    }
}

impl Default for DatabaseSettings {
    fn default() -> Self {
        Self {
            username: "postgres".to_string(),
            password: "postgres".to_string(),
            host: "127.0.0.1".to_string(),
            port: 5432,
            database_name: "stacker".to_string(),
        }
    }
}

#[derive(serde::Deserialize, Clone)]
pub struct AmqpSettings {
    pub username: String,
    pub password: String,
    pub host: String,
    pub port: u16,
}

impl std::fmt::Debug for AmqpSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AmqpSettings")
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .field("host", &self.host)
            .field("port", &self.port)
            .finish()
    }
}

impl Default for AmqpSettings {
    fn default() -> Self {
        Self {
            username: "guest".to_string(),
            password: "guest".to_string(),
            host: "127.0.0.1".to_string(),
            port: 5672,
        }
    }
}

/// Deployment-related settings for app configuration paths
#[derive(Debug, serde::Deserialize, Clone)]
pub struct DeploymentSettings {
    /// Base path for app config files on the deployment server
    /// Default: /home/trydirect
    /// Can be overridden via DEFAULT_DEPLOY_DIR env var
    #[serde(default = "DeploymentSettings::default_config_base_path")]
    pub config_base_path: String,
}

impl Default for DeploymentSettings {
    fn default() -> Self {
        Self {
            config_base_path: Self::default_config_base_path(),
        }
    }
}

#[derive(serde::Deserialize, Clone)]
pub struct MarketplaceAssetSettings {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "MarketplaceAssetSettings::default_current_env")]
    pub current_env: String,
    #[serde(default)]
    pub endpoint_url: String,
    #[serde(default = "MarketplaceAssetSettings::default_region")]
    pub region: String,
    #[serde(default)]
    pub access_key_id: String,
    #[serde(default)]
    pub secret_access_key: String,
    #[serde(default = "MarketplaceAssetSettings::default_bucket_dev")]
    pub bucket_dev: String,
    #[serde(default = "MarketplaceAssetSettings::default_bucket_test")]
    pub bucket_test: String,
    #[serde(default = "MarketplaceAssetSettings::default_bucket_staging")]
    pub bucket_staging: String,
    #[serde(default = "MarketplaceAssetSettings::default_bucket_prod")]
    pub bucket_prod: String,
    #[serde(default)]
    pub server_side_encryption: Option<String>,
    #[serde(default = "MarketplaceAssetSettings::default_presign_put_ttl_secs")]
    pub presign_put_ttl_secs: u64,
    #[serde(default = "MarketplaceAssetSettings::default_presign_get_ttl_secs")]
    pub presign_get_ttl_secs: u64,
}

impl std::fmt::Debug for MarketplaceAssetSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MarketplaceAssetSettings")
            .field("enabled", &self.enabled)
            .field("current_env", &self.current_env)
            .field("endpoint_url", &self.endpoint_url)
            .field("region", &self.region)
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"[REDACTED]")
            .field("bucket_dev", &self.bucket_dev)
            .field("bucket_test", &self.bucket_test)
            .field("bucket_staging", &self.bucket_staging)
            .field("bucket_prod", &self.bucket_prod)
            .field("server_side_encryption", &self.server_side_encryption)
            .field("presign_put_ttl_secs", &self.presign_put_ttl_secs)
            .field("presign_get_ttl_secs", &self.presign_get_ttl_secs)
            .finish()
    }
}

impl Default for MarketplaceAssetSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            current_env: Self::default_current_env(),
            endpoint_url: String::new(),
            region: Self::default_region(),
            access_key_id: String::new(),
            secret_access_key: String::new(),
            bucket_dev: Self::default_bucket_dev(),
            bucket_test: Self::default_bucket_test(),
            bucket_staging: Self::default_bucket_staging(),
            bucket_prod: Self::default_bucket_prod(),
            server_side_encryption: Some("AES256".to_string()),
            presign_put_ttl_secs: Self::default_presign_put_ttl_secs(),
            presign_get_ttl_secs: Self::default_presign_get_ttl_secs(),
        }
    }
}

impl MarketplaceAssetSettings {
    fn default_current_env() -> String {
        let current = std::env::var("STACKER_ENV")
            .or_else(|_| std::env::var("APP_ENV"))
            .or_else(|_| std::env::var("NODE_ENV"))
            .unwrap_or_else(|_| "dev".to_string());

        match current.as_str() {
            "production" => "prod".to_string(),
            "development" => "dev".to_string(),
            other => other.to_string(),
        }
    }

    fn default_region() -> String {
        "eu-central".to_string()
    }

    fn default_bucket_dev() -> String {
        "marketplace-assets-dev".to_string()
    }

    fn default_bucket_test() -> String {
        "marketplace-assets-test".to_string()
    }

    fn default_bucket_staging() -> String {
        "marketplace-assets-staging".to_string()
    }

    fn default_bucket_prod() -> String {
        "marketplace-assets-prod".to_string()
    }

    fn default_presign_put_ttl_secs() -> u64 {
        900
    }

    fn default_presign_get_ttl_secs() -> u64 {
        300
    }

    pub fn active_bucket(&self) -> &str {
        match self.current_env.as_str() {
            "test" => &self.bucket_test,
            "staging" => &self.bucket_staging,
            "prod" | "production" => &self.bucket_prod,
            _ => &self.bucket_dev,
        }
    }

    pub fn is_configured(&self) -> bool {
        self.enabled
            && !self.endpoint_url.trim().is_empty()
            && !self.access_key_id.trim().is_empty()
            && !self.secret_access_key.trim().is_empty()
            && !self.active_bucket().trim().is_empty()
    }
}

impl DeploymentSettings {
    fn default_config_base_path() -> String {
        std::env::var("DEFAULT_DEPLOY_DIR").unwrap_or_else(|_| "/home/trydirect".to_string())
    }

    /// Get the full deploy directory for a given project name or deployment hash
    pub fn deploy_dir(&self, name: &str) -> String {
        format!("{}/{}", self.config_base_path.trim_end_matches('/'), name)
    }

    /// Get the base path (for backwards compatibility)
    pub fn base_path(&self) -> &str {
        &self.config_base_path
    }
}

#[derive(serde::Deserialize, Clone)]
pub struct VaultSettings {
    pub address: String,
    pub token: String,
    pub agent_path_prefix: String,
    #[serde(default = "VaultSettings::default_api_prefix")]
    pub api_prefix: String,
    #[serde(default)]
    pub ssh_key_path_prefix: Option<String>,
}

impl std::fmt::Debug for VaultSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultSettings")
            .field("address", &self.address)
            .field("token", &"[REDACTED]")
            .field("agent_path_prefix", &self.agent_path_prefix)
            .field("api_prefix", &self.api_prefix)
            .field("ssh_key_path_prefix", &self.ssh_key_path_prefix)
            .finish()
    }
}

impl Default for VaultSettings {
    fn default() -> Self {
        Self {
            address: "http://127.0.0.1:8200".to_string(),
            token: "dev-token".to_string(),
            agent_path_prefix: "agent".to_string(),
            api_prefix: Self::default_api_prefix(),
            ssh_key_path_prefix: Some("users".to_string()),
        }
    }
}

impl VaultSettings {
    fn default_api_prefix() -> String {
        "v1".to_string()
    }

    /// Overlay Vault settings from environment variables, if present.
    /// If an env var is missing, keep the existing file-provided value.
    pub fn overlay_env(self) -> Self {
        let address = std::env::var("VAULT_ADDRESS").unwrap_or(self.address);
        let token = std::env::var("VAULT_TOKEN").unwrap_or(self.token);
        let agent_path_prefix =
            std::env::var("VAULT_AGENT_PATH_PREFIX").unwrap_or(self.agent_path_prefix);
        let api_prefix = std::env::var("VAULT_API_PREFIX").unwrap_or(self.api_prefix);
        let ssh_key_path_prefix = std::env::var("VAULT_SSH_KEY_PATH_PREFIX").unwrap_or(
            self.ssh_key_path_prefix
                .unwrap_or_else(|| "users".to_string()),
        );

        VaultSettings {
            address,
            token,
            agent_path_prefix,
            api_prefix,
            ssh_key_path_prefix: Some(ssh_key_path_prefix),
        }
    }
}

impl DatabaseSettings {
    // Connection string: postgresql://<username>:<password>@<host>:<port>/<database_name>
    pub fn connection_string(&self) -> String {
        format!(
            "postgresql://{}:{}@{}:{}/{}",
            self.username, self.password, self.host, self.port, self.database_name,
        )
    }

    pub fn connection_string_without_db(&self) -> String {
        format!(
            "postgresql://{}:{}@{}:{}",
            self.username, self.password, self.host, self.port,
        )
    }
}

impl AmqpSettings {
    pub fn connection_string(&self) -> String {
        format!(
            "amqp://{}:{}@{}:{}/%2f",
            self.username, self.password, self.host, self.port,
        )
    }
}

/// Parses a boolean value from an environment variable string.
///
/// Recognizes common boolean representations: "1", "true", "TRUE"
/// Returns `true` if the value matches any of these, `false` otherwise.
pub fn parse_bool_env(value: &str) -> bool {
    matches!(value, "1" | "true" | "TRUE")
}

pub fn get_configuration() -> Result<Settings, config::ConfigError> {
    // Load environment variables from .env file
    dotenvy::dotenv().ok();

    // Start with defaults
    let mut config = Settings::default();

    // Prefer real config, fall back to dist samples; layer multiple formats
    let settings = config::Config::builder()
        // Primary local config
        .add_source(config::File::with_name("configuration.yaml").required(false))
        .add_source(config::File::with_name("configuration.yml").required(false))
        .add_source(config::File::with_name("configuration").required(false))
        // Fallback samples
        .add_source(config::File::with_name("configuration.yaml.dist").required(false))
        .add_source(config::File::with_name("configuration.yml.dist").required(false))
        .add_source(config::File::with_name("configuration.dist").required(false))
        .build()?;

    // Try to convert the configuration values it read into our Settings type
    if let Ok(loaded) = settings.try_deserialize::<Settings>() {
        config = loaded;
    }

    // Overlay Vault settings with environment variables if present
    config.vault = config.vault.overlay_env();

    if let Ok(timeout) = std::env::var("STACKER_AGENT_POLL_TIMEOUT_SECS") {
        if let Ok(parsed) = timeout.parse::<u64>() {
            config.agent_command_poll_timeout_secs = parsed;
        }
    }

    if let Ok(interval) = std::env::var("STACKER_AGENT_POLL_INTERVAL_SECS") {
        if let Ok(parsed) = interval.parse::<u64>() {
            config.agent_command_poll_interval_secs = parsed;
        }
    }

    if let Ok(timeout) = std::env::var("STACKER_AUTH_REQUEST_TIMEOUT_SECS") {
        if let Ok(parsed) = timeout.parse::<u64>() {
            config.auth_request_timeout_secs = parsed;
        }
    }

    if let Ok(timeout) = std::env::var("STACKER_AUTH_CONNECT_TIMEOUT_SECS") {
        if let Ok(parsed) = timeout.parse::<u64>() {
            config.auth_connect_timeout_secs = parsed;
        }
    }

    if let Ok(enabled) = std::env::var("STACKER_CASBIN_RELOAD_ENABLED") {
        config.casbin_reload_enabled = parse_bool_env(&enabled);
    }

    if let Ok(interval) = std::env::var("STACKER_CASBIN_RELOAD_INTERVAL_SECS") {
        if let Ok(parsed) = interval.parse::<u64>() {
            config.casbin_reload_interval_secs = parsed;
        }
    }

    // Overlay AMQP settings with environment variables if present
    if let Ok(host) = std::env::var("AMQP_HOST") {
        config.amqp.host = host;
    }
    if let Ok(port) = std::env::var("AMQP_PORT") {
        if let Ok(parsed) = port.parse::<u16>() {
            config.amqp.port = parsed;
        }
    }
    if let Ok(username) = std::env::var("AMQP_USERNAME") {
        config.amqp.username = username;
    }
    if let Ok(password) = std::env::var("AMQP_PASSWORD") {
        config.amqp.password = password;
    }

    // Overlay Deployment settings with environment variables if present
    if let Ok(base_path) = std::env::var("DEPLOYMENT_CONFIG_BASE_PATH") {
        config.deployment.config_base_path = base_path;
    }

    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_bool_env_true_values() {
        assert!(parse_bool_env("1"));
        assert!(parse_bool_env("true"));
        assert!(parse_bool_env("TRUE"));
    }

    #[test]
    fn test_parse_bool_env_false_values() {
        assert!(!parse_bool_env("0"));
        assert!(!parse_bool_env("false"));
        assert!(!parse_bool_env("FALSE"));
        assert!(!parse_bool_env(""));
        assert!(!parse_bool_env("yes"));
        assert!(!parse_bool_env("no"));
        assert!(!parse_bool_env("True")); // Case-sensitive
        assert!(!parse_bool_env("invalid"));
    }

    #[test]
    fn test_default_auth_timeouts_are_bounded() {
        let settings = Settings::default();

        assert_eq!(settings.auth_request_timeout_secs, 5);
        assert_eq!(settings.auth_connect_timeout_secs, 2);
    }
}
