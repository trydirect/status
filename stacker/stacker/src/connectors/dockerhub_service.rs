use super::config::{ConnectorConfig, DockerHubConnectorConfig};
use super::errors::ConnectorError;
use actix_web::web;
use async_trait::async_trait;
use base64::{engine::general_purpose, Engine as _};
use redis::aio::ConnectionManager;
use redis::AsyncCommands;
use reqwest::{Method, StatusCode};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tracing::Instrument;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NamespaceSummary {
    pub name: String,
    #[serde(default)]
    pub namespace_type: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    pub is_user: bool,
    pub is_organization: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RepositorySummary {
    pub name: String,
    pub namespace: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub last_updated: Option<String>,
    pub is_private: bool,
    #[serde(default)]
    pub star_count: Option<u64>,
    #[serde(default)]
    pub pull_count: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TagSummary {
    pub name: String,
    #[serde(default)]
    pub digest: Option<String>,
    #[serde(default)]
    pub last_updated: Option<String>,
    #[serde(default)]
    pub tag_status: Option<String>,
    #[serde(default)]
    pub content_type: Option<String>,
}

#[async_trait]
pub trait DockerHubConnector: Send + Sync {
    async fn search_namespaces(&self, query: &str)
        -> Result<Vec<NamespaceSummary>, ConnectorError>;
    async fn list_repositories(
        &self,
        namespace: &str,
        query: Option<&str>,
    ) -> Result<Vec<RepositorySummary>, ConnectorError>;
    async fn list_tags(
        &self,
        namespace: &str,
        repository: &str,
        query: Option<&str>,
    ) -> Result<Vec<TagSummary>, ConnectorError>;
}

#[derive(Clone)]
struct RedisCache {
    connection: Arc<Mutex<ConnectionManager>>,
}

impl RedisCache {
    async fn new(redis_url: &str) -> Result<Self, ConnectorError> {
        let client = redis::Client::open(redis_url).map_err(|err| {
            ConnectorError::Internal(format!("Invalid Redis URL for Docker Hub cache: {}", err))
        })?;

        let connection =
            tokio::time::timeout(Duration::from_secs(3), ConnectionManager::new(client))
                .await
                .map_err(|_| {
                    ConnectorError::ServiceUnavailable("Redis connection timed out".to_string())
                })?
                .map_err(|err| {
                    ConnectorError::ServiceUnavailable(format!("Redis unavailable: {}", err))
                })?;

        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
        })
    }

    async fn get<T>(&self, key: &str) -> Result<Option<T>, ConnectorError>
    where
        T: DeserializeOwned,
    {
        let mut conn = self.connection.lock().await;
        let value: Option<String> = conn.get(key).await.map_err(|err| {
            ConnectorError::ServiceUnavailable(format!("Redis GET failed: {}", err))
        })?;

        if let Some(payload) = value {
            if payload.is_empty() {
                return Ok(None);
            }
            serde_json::from_str::<T>(&payload)
                .map(Some)
                .map_err(|err| ConnectorError::Internal(format!("Cache decode failed: {}", err)))
        } else {
            Ok(None)
        }
    }

    async fn set<T>(&self, key: &str, value: &T, ttl_secs: u64) -> Result<(), ConnectorError>
    where
        T: Serialize,
    {
        if ttl_secs == 0 {
            return Ok(());
        }

        let payload = serde_json::to_string(value)
            .map_err(|err| ConnectorError::Internal(format!("Cache encode failed: {}", err)))?;

        let mut conn = self.connection.lock().await;
        let (): () = conn
            .set_ex(key, payload, ttl_secs as u64)
            .await
            .map_err(|err| {
                ConnectorError::ServiceUnavailable(format!("Redis SET failed: {}", err))
            })?;
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct CacheDurations {
    namespaces: u64,
    repositories: u64,
    tags: u64,
}

pub struct DockerHubClient {
    base_url: String,
    http_client: reqwest::Client,
    auth_header: Option<String>,
    retry_attempts: usize,
    cache: RedisCache,
    cache_ttls: CacheDurations,
    user_agent: String,
    page_size: u32,
}

impl DockerHubClient {
    pub async fn new(mut config: DockerHubConnectorConfig) -> Result<Self, ConnectorError> {
        if config.redis_url.is_none() {
            config.redis_url = std::env::var("DOCKERHUB_REDIS_URL")
                .ok()
                .or_else(|| std::env::var("REDIS_URL").ok());
        }

        let redis_url = config
            .redis_url
            .clone()
            .unwrap_or_else(|| "redis://127.0.0.1/0".to_string());
        let cache = RedisCache::new(&redis_url).await?;

        let timeout = Duration::from_secs(config.timeout_secs.max(1));
        let http_client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|err| ConnectorError::Internal(format!("HTTP client error: {}", err)))?;

        let auth_header = Self::build_auth_header(&config.username, &config.personal_access_token);
        let base_url = config.base_url.trim_end_matches('/').to_string();

        Ok(Self {
            base_url,
            http_client,
            auth_header,
            retry_attempts: config.retry_attempts.max(1),
            cache,
            cache_ttls: CacheDurations {
                namespaces: config.cache_ttl_namespaces_secs,
                repositories: config.cache_ttl_repositories_secs,
                tags: config.cache_ttl_tags_secs,
            },
            user_agent: format!("stacker-dockerhub-client/{}", env!("CARGO_PKG_VERSION")),
            page_size: config.page_size.clamp(1, 100),
        })
    }

    fn build_auth_header(username: &Option<String>, token: &Option<String>) -> Option<String> {
        match (username, token) {
            (Some(user), Some(token)) if !user.is_empty() && !token.is_empty() => {
                let encoded = general_purpose::STANDARD.encode(format!("{user}:{token}"));
                Some(format!("Basic {}", encoded))
            }
            (None, Some(token)) if !token.is_empty() => Some(format!("Bearer {}", token)),
            _ => None,
        }
    }

    fn encode_segment(segment: &str) -> String {
        urlencoding::encode(segment).into_owned()
    }

    fn cache_suffix(input: &str) -> String {
        let normalized = input.trim();
        if normalized.is_empty() {
            "all".to_string()
        } else {
            normalized.to_lowercase()
        }
    }

    async fn read_cache<T>(&self, key: &str) -> Option<T>
    where
        T: DeserializeOwned,
    {
        match self.cache.get(key).await {
            Ok(value) => value,
            Err(err) => {
                tracing::debug!(error = %err, cache_key = key, "Docker Hub cache read failed");
                None
            }
        }
    }

    async fn write_cache<T>(&self, key: &str, value: &T, ttl: u64)
    where
        T: Serialize,
    {
        if let Err(err) = self.cache.set(key, value, ttl).await {
            tracing::debug!(error = %err, cache_key = key, "Docker Hub cache write failed");
        }
    }

    async fn send_request(
        &self,
        method: Method,
        path: &str,
        query: Vec<(String, String)>,
    ) -> Result<Value, ConnectorError> {
        let mut attempt = 0usize;
        let mut last_error: Option<ConnectorError> = None;

        while attempt < self.retry_attempts {
            attempt += 1;
            let mut builder = self
                .http_client
                .request(method.clone(), format!("{}{}", self.base_url, path))
                .header("User-Agent", &self.user_agent);

            if let Some(auth) = &self.auth_header {
                builder = builder.header("Authorization", auth);
            }

            if !query.is_empty() {
                builder = builder.query(&query);
            }

            let span = tracing::info_span!(
                "dockerhub_http_request",
                path,
                attempt,
                method = %method,
            );

            match builder.send().instrument(span).await {
                Ok(resp) => {
                    let status = resp.status();
                    let text = resp
                        .text()
                        .await
                        .map_err(|err| ConnectorError::HttpError(err.to_string()))?;

                    if status.is_success() {
                        return serde_json::from_str::<Value>(&text)
                            .map_err(|_| ConnectorError::InvalidResponse(text));
                    }

                    let error = match status {
                        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
                            ConnectorError::Unauthorized(text)
                        }
                        StatusCode::NOT_FOUND => ConnectorError::NotFound(text),
                        StatusCode::TOO_MANY_REQUESTS => ConnectorError::RateLimited(text),
                        status if status.is_server_error() => ConnectorError::ServiceUnavailable(
                            format!("Docker Hub error {}: {}", status, text),
                        ),
                        status => ConnectorError::HttpError(format!(
                            "Docker Hub error {}: {}",
                            status, text
                        )),
                    };

                    if !status.is_server_error() {
                        return Err(error);
                    }
                    last_error = Some(error);
                }
                Err(err) => {
                    last_error = Some(ConnectorError::from(err));
                }
            }

            if attempt < self.retry_attempts {
                let backoff = Duration::from_millis(100 * (1_u64 << (attempt - 1)));
                tokio::time::sleep(backoff).await;
            }
        }

        Err(last_error.unwrap_or_else(|| {
            ConnectorError::ServiceUnavailable("Docker Hub request failed".to_string())
        }))
    }

    fn parse_repository_response(payload: Value) -> Vec<RepositorySummary> {
        Self::extract_items(&payload, &["results", "repositories"])
            .into_iter()
            .filter_map(|item| {
                let (namespace, name) = Self::resolve_namespace_and_name(&item)?;

                Some(RepositorySummary {
                    name,
                    namespace,
                    description: item
                        .get("description")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    last_updated: item
                        .get("last_updated")
                        .or_else(|| item.get("last_push"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    is_private: item
                        .get("is_private")
                        .or_else(|| item.get("private"))
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false),
                    star_count: item.get("star_count").and_then(|v| v.as_u64()),
                    pull_count: item.get("pull_count").and_then(|v| v.as_u64()),
                })
            })
            .collect()
    }

    fn parse_tag_response(payload: Value) -> Vec<TagSummary> {
        Self::extract_items(&payload, &["results", "tags"])
            .into_iter()
            .filter_map(|item| {
                let name = item.get("name")?.as_str()?.to_string();
                Some(TagSummary {
                    name,
                    digest: item
                        .get("digest")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    last_updated: item
                        .get("last_updated")
                        .or_else(|| item.get("tag_last_pushed"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    tag_status: item
                        .get("tag_status")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    content_type: item
                        .get("content_type")
                        .or_else(|| item.get("media_type"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                })
            })
            .collect()
    }

    fn extract_items(payload: &Value, keys: &[&str]) -> Vec<Value> {
        for key in keys {
            if let Some(array) = payload.get(*key).and_then(|value| value.as_array()) {
                return array.clone();
            }
        }

        payload.as_array().cloned().unwrap_or_default()
    }

    fn resolve_namespace_and_name(item: &Value) -> Option<(String, String)> {
        let mut namespace = item
            .get("namespace")
            .or_else(|| item.get("user"))
            .or_else(|| item.get("organization"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let mut repo_name = item
            .get("name")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())?;

        if namespace.as_ref().map(|s| s.is_empty()).unwrap_or(true) {
            if let Some(slug) = item
                .get("slug")
                .or_else(|| item.get("repo_name"))
                .and_then(|v| v.as_str())
            {
                if let Some((ns, repo)) = slug.split_once('/') {
                    namespace = Some(ns.to_string());
                    repo_name = repo.to_string();
                }
            }
        }

        if namespace.as_ref().map(|s| s.is_empty()).unwrap_or(true) && repo_name.contains('/') {
            if let Some((ns, repo)) = repo_name.split_once('/') {
                namespace = Some(ns.to_string());
                repo_name = repo.to_string();
            }
        }

        namespace.and_then(|ns| {
            if ns.is_empty() {
                None
            } else {
                Some((ns, repo_name))
            }
        })
    }
}

#[async_trait]
impl DockerHubConnector for DockerHubClient {
    async fn search_namespaces(
        &self,
        query: &str,
    ) -> Result<Vec<NamespaceSummary>, ConnectorError> {
        let cache_key = format!("dockerhub:namespaces:{}", Self::cache_suffix(query));
        if let Some(cached) = self.read_cache::<Vec<NamespaceSummary>>(&cache_key).await {
            return Ok(cached);
        }

        let mut query_params = vec![("page_size".to_string(), self.page_size.to_string())];
        let trimmed = query.trim();
        if !trimmed.is_empty() {
            query_params.push(("query".to_string(), trimmed.to_string()));
        }

        let payload = self
            .send_request(Method::GET, "/v2/search/repositories/", query_params)
            .await?;
        let repositories = Self::parse_repository_response(payload);

        let mut seen = HashSet::new();
        let mut namespaces = Vec::new();
        for repo in repositories {
            if repo.namespace.is_empty() || !seen.insert(repo.namespace.clone()) {
                continue;
            }

            namespaces.push(NamespaceSummary {
                name: repo.namespace.clone(),
                namespace_type: None,
                description: repo.description.clone(),
                is_user: false,
                is_organization: false,
            });
        }

        self.write_cache(&cache_key, &namespaces, self.cache_ttls.namespaces)
            .await;
        Ok(namespaces)
    }

    async fn list_repositories(
        &self,
        namespace: &str,
        query: Option<&str>,
    ) -> Result<Vec<RepositorySummary>, ConnectorError> {
        let cache_key = format!(
            "dockerhub:repos:{}:{}",
            Self::cache_suffix(namespace),
            Self::cache_suffix(query.unwrap_or_default())
        );

        if let Some(cached) = self.read_cache::<Vec<RepositorySummary>>(&cache_key).await {
            return Ok(cached);
        }

        let mut query_params = vec![("page_size".to_string(), self.page_size.to_string())];
        if let Some(filter) = query {
            let trimmed = filter.trim();
            if !trimmed.is_empty() {
                query_params.push(("name".to_string(), trimmed.to_string()));
            }
        }

        let path = format!(
            "/v2/namespaces/{}/repositories",
            Self::encode_segment(namespace)
        );

        let payload = self.send_request(Method::GET, &path, query_params).await?;
        let repositories = Self::parse_repository_response(payload);
        self.write_cache(&cache_key, &repositories, self.cache_ttls.repositories)
            .await;
        Ok(repositories)
    }

    async fn list_tags(
        &self,
        namespace: &str,
        repository: &str,
        query: Option<&str>,
    ) -> Result<Vec<TagSummary>, ConnectorError> {
        let cache_key = format!(
            "dockerhub:tags:{}:{}:{}",
            Self::cache_suffix(namespace),
            Self::cache_suffix(repository),
            Self::cache_suffix(query.unwrap_or_default())
        );

        if let Some(cached) = self.read_cache::<Vec<TagSummary>>(&cache_key).await {
            return Ok(cached);
        }

        let mut query_params = vec![("page_size".to_string(), self.page_size.to_string())];
        if let Some(filter) = query {
            let trimmed = filter.trim();
            if !trimmed.is_empty() {
                query_params.push(("name".to_string(), trimmed.to_string()));
            }
        }

        let path = format!(
            "/v2/namespaces/{}/repositories/{}/tags",
            Self::encode_segment(namespace),
            Self::encode_segment(repository)
        );

        let payload = self.send_request(Method::GET, &path, query_params).await?;
        let tags = Self::parse_tag_response(payload);
        self.write_cache(&cache_key, &tags, self.cache_ttls.tags)
            .await;
        Ok(tags)
    }
}

/// Initialize Docker Hub connector from app settings
pub async fn init(connector_config: &ConnectorConfig) -> web::Data<Arc<dyn DockerHubConnector>> {
    let connector: Arc<dyn DockerHubConnector> = if let Some(config) = connector_config
        .dockerhub_service
        .as_ref()
        .filter(|cfg| cfg.enabled)
    {
        let mut cfg = config.clone();

        if cfg.username.is_none() {
            cfg.username = std::env::var("DOCKERHUB_USERNAME").ok();
        }

        if cfg.personal_access_token.is_none() {
            cfg.personal_access_token = std::env::var("DOCKERHUB_TOKEN").ok();
        }

        if cfg.redis_url.is_none() {
            cfg.redis_url = std::env::var("DOCKERHUB_REDIS_URL")
                .ok()
                .or_else(|| std::env::var("REDIS_URL").ok());
        }

        match DockerHubClient::new(cfg.clone()).await {
            Ok(client) => {
                tracing::info!("Docker Hub connector initialized ({})", cfg.base_url);
                Arc::new(client)
            }
            Err(err) => {
                tracing::error!(
                    error = %err,
                    "Failed to initialize Docker Hub connector, falling back to mock"
                );
                Arc::new(mock::MockDockerHubConnector::default())
            }
        }
    } else {
        tracing::warn!("Docker Hub connector disabled - using mock responses");
        Arc::new(mock::MockDockerHubConnector::default())
    };

    web::Data::new(connector)
}

pub mod mock {
    use super::*;

    #[derive(Default)]
    pub struct MockDockerHubConnector;

    #[async_trait]
    impl DockerHubConnector for MockDockerHubConnector {
        async fn search_namespaces(
            &self,
            query: &str,
        ) -> Result<Vec<NamespaceSummary>, ConnectorError> {
            let mut namespaces = vec![
                NamespaceSummary {
                    name: "trydirect".to_string(),
                    namespace_type: Some("organization".to_string()),
                    description: Some("TryDirect maintained images".to_string()),
                    is_user: false,
                    is_organization: true,
                },
                NamespaceSummary {
                    name: "stacker-labs".to_string(),
                    namespace_type: Some("organization".to_string()),
                    description: Some("Stacker lab images".to_string()),
                    is_user: false,
                    is_organization: true,
                },
                NamespaceSummary {
                    name: "dev-user".to_string(),
                    namespace_type: Some("user".to_string()),
                    description: Some("Individual maintainer".to_string()),
                    is_user: true,
                    is_organization: false,
                },
            ];

            let needle = query.trim().to_lowercase();
            if !needle.is_empty() {
                namespaces.retain(|ns| ns.name.to_lowercase().contains(&needle));
            }
            Ok(namespaces)
        }

        async fn list_repositories(
            &self,
            namespace: &str,
            query: Option<&str>,
        ) -> Result<Vec<RepositorySummary>, ConnectorError> {
            let mut repositories = vec![
                RepositorySummary {
                    name: "stacker-api".to_string(),
                    namespace: namespace.to_string(),
                    description: Some("Stacker API service".to_string()),
                    last_updated: Some("2026-01-01T00:00:00Z".to_string()),
                    is_private: false,
                    star_count: Some(42),
                    pull_count: Some(10_000),
                },
                RepositorySummary {
                    name: "agent-runner".to_string(),
                    namespace: namespace.to_string(),
                    description: Some("Agent runtime image".to_string()),
                    last_updated: Some("2026-01-03T00:00:00Z".to_string()),
                    is_private: false,
                    star_count: Some(8),
                    pull_count: Some(1_200),
                },
            ];

            if let Some(filter) = query {
                let needle = filter.trim().to_lowercase();
                if !needle.is_empty() {
                    repositories.retain(|repo| repo.name.to_lowercase().contains(&needle));
                }
            }
            Ok(repositories)
        }

        async fn list_tags(
            &self,
            _namespace: &str,
            repository: &str,
            query: Option<&str>,
        ) -> Result<Vec<TagSummary>, ConnectorError> {
            let mut tags = vec![
                TagSummary {
                    name: "latest".to_string(),
                    digest: Some(format!("sha256:{:x}", 1)),
                    last_updated: Some("2026-01-03T12:00:00Z".to_string()),
                    tag_status: Some("active".to_string()),
                    content_type: Some(
                        "application/vnd.docker.distribution.manifest.v2+json".to_string(),
                    ),
                },
                TagSummary {
                    name: "v1.2.3".to_string(),
                    digest: Some(format!("sha256:{:x}", 2)),
                    last_updated: Some("2026-01-02T08:00:00Z".to_string()),
                    tag_status: Some("active".to_string()),
                    content_type: Some(
                        "application/vnd.docker.distribution.manifest.v2+json".to_string(),
                    ),
                },
            ];

            let needle = query.unwrap_or_default().trim().to_lowercase();
            if !needle.is_empty() {
                tags.retain(|tag| tag.name.to_lowercase().contains(&needle));
            }

            // Slightly mutate digests to include repository so tests can differentiate
            for (idx, tag) in tags.iter_mut().enumerate() {
                if tag.digest.is_some() {
                    tag.digest = Some(format!(
                        "sha256:{:x}{}",
                        idx,
                        repository
                            .to_lowercase()
                            .chars()
                            .take(4)
                            .collect::<String>()
                    ));
                }
            }

            Ok(tags)
        }
    }
}
