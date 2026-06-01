//! User Service Deployment Resolver
//!
//! This module provides a deployment resolver that can fetch deployment information
//! from the User Service for legacy installations.
//!
//! Stack Builder can work without this module - it's only needed when supporting
//! legacy User Service deployments (deployment_id instead of deployment_hash).
//!
//! # Example
//! ```rust,ignore
//! use crate::services::{DeploymentIdentifier, DeploymentResolver};
//! use crate::connectors::user_service::UserServiceDeploymentResolver;
//!
//! let resolver = UserServiceDeploymentResolver::new(&settings.user_service_url, token);
//!
//! // Works with both Stack Builder hashes and User Service IDs
//! let hash = resolver.resolve(&DeploymentIdentifier::from_id(13467)).await?;
//! ```

use async_trait::async_trait;

use crate::connectors::user_service::UserServiceClient;
use crate::services::{DeploymentIdentifier, DeploymentResolveError, DeploymentResolver};

/// Information about a resolved deployment (for diagnosis tools)
/// Contains additional metadata from User Service beyond just the hash.
#[derive(Debug, Clone, Default)]
pub struct ResolvedDeploymentInfo {
    pub deployment_hash: String,
    pub status: String,
    pub domain: Option<String>,
    pub server_ip: Option<String>,
    pub apps: Option<Vec<crate::connectors::user_service::install::InstallationApp>>,
}

impl ResolvedDeploymentInfo {
    /// Create minimal info from just a hash (Stack Builder native)
    pub fn from_hash(hash: String) -> Self {
        Self {
            deployment_hash: hash,
            status: "unknown".to_string(),
            domain: None,
            server_ip: None,
            apps: None,
        }
    }
}

/// Deployment resolver that fetches deployment information from User Service.
///
/// This resolver handles both:
/// - Direct hashes (Stack Builder) - returned immediately without HTTP call
/// - Installation IDs (User Service) - looked up via HTTP to User Service
///
/// Use this when you need to support legacy deployments from User Service.
/// For Stack Builder-only deployments, use `StackerDeploymentResolver` instead.
pub struct UserServiceDeploymentResolver {
    user_service_url: String,
    user_token: String,
}

impl UserServiceDeploymentResolver {
    /// Create a new resolver with User Service connection info
    pub fn new(user_service_url: &str, user_token: &str) -> Self {
        Self {
            user_service_url: user_service_url.to_string(),
            user_token: user_token.to_string(),
        }
    }

    /// Create from configuration and token
    pub fn from_context(user_service_url: &str, access_token: Option<&str>) -> Self {
        Self::new(user_service_url, access_token.unwrap_or(""))
    }

    /// Resolve with full deployment info (for diagnosis tools)
    /// Returns deployment hash plus additional metadata if available from User Service
    pub async fn resolve_with_info(
        &self,
        identifier: &DeploymentIdentifier,
    ) -> Result<ResolvedDeploymentInfo, DeploymentResolveError> {
        match identifier {
            DeploymentIdentifier::Hash(hash) => {
                // Stack Builder deployment - minimal info (no User Service call)
                Ok(ResolvedDeploymentInfo::from_hash(hash.clone()))
            }
            DeploymentIdentifier::InstallationId(id) => {
                // Legacy installation - fetch full details from User Service
                let client = UserServiceClient::new_public(&self.user_service_url);

                let installation = client
                    .get_installation(&self.user_token, *id)
                    .await
                    .map_err(|e| DeploymentResolveError::ServiceError(e.to_string()))?;

                let hash = installation.deployment_hash.clone().ok_or_else(|| {
                    DeploymentResolveError::NoHash(format!(
                        "Installation {} has no deployment_hash",
                        id
                    ))
                })?;

                Ok(ResolvedDeploymentInfo {
                    deployment_hash: hash,
                    status: installation.status.unwrap_or_else(|| "unknown".to_string()),
                    domain: installation.domain,
                    server_ip: installation.server_ip,
                    apps: installation.apps,
                })
            }
        }
    }
}

#[async_trait]
impl DeploymentResolver for UserServiceDeploymentResolver {
    async fn resolve(
        &self,
        identifier: &DeploymentIdentifier,
    ) -> Result<String, DeploymentResolveError> {
        match identifier {
            DeploymentIdentifier::Hash(hash) => {
                // Stack Builder deployment - hash is already known
                Ok(hash.clone())
            }
            DeploymentIdentifier::InstallationId(id) => {
                // Legacy installation - fetch from User Service
                let client = UserServiceClient::new_public(&self.user_service_url);

                let installation = client
                    .get_installation(&self.user_token, *id)
                    .await
                    .map_err(|e| DeploymentResolveError::ServiceError(e.to_string()))?;

                installation.deployment_hash.ok_or_else(|| {
                    DeploymentResolveError::NoHash(format!(
                        "Installation {} has no deployment_hash",
                        id
                    ))
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::StackerDeploymentResolver;

    // ============================================================
    // UserServiceDeploymentResolver tests
    // ============================================================

    #[tokio::test]
    async fn test_hash_returns_immediately() {
        // Hash identifiers are returned immediately without HTTP calls
        let resolver = UserServiceDeploymentResolver::new("http://unused", "unused_token");
        let id = DeploymentIdentifier::from_hash("test_hash_123");

        let result = resolver.resolve(&id).await;
        assert_eq!(result.unwrap(), "test_hash_123");
    }

    #[tokio::test]
    async fn test_resolve_with_info_hash() {
        let resolver = UserServiceDeploymentResolver::new("http://unused", "unused_token");
        let id = DeploymentIdentifier::from_hash("test_hash_456");

        let result = resolver.resolve_with_info(&id).await;
        let info = result.unwrap();

        assert_eq!(info.deployment_hash, "test_hash_456");
        assert_eq!(info.status, "unknown"); // No User Service call for hash
        assert!(info.domain.is_none());
        assert!(info.apps.is_none());
    }

    #[tokio::test]
    async fn test_empty_hash_is_valid() {
        // Edge case: empty string is technically a valid hash
        let resolver = UserServiceDeploymentResolver::new("http://unused", "unused_token");
        let id = DeploymentIdentifier::from_hash("");

        let result = resolver.resolve(&id).await;
        assert_eq!(result.unwrap(), "");
    }

    #[tokio::test]
    async fn test_hash_with_special_characters() {
        let resolver = UserServiceDeploymentResolver::new("http://unused", "unused_token");
        let id = DeploymentIdentifier::from_hash("hash-with_special.chars/123");

        let result = resolver.resolve(&id).await;
        assert_eq!(result.unwrap(), "hash-with_special.chars/123");
    }

    // ============================================================
    // StackerDeploymentResolver tests (native, no external deps)
    // ============================================================

    #[tokio::test]
    async fn test_stacker_resolver_hash_success() {
        let resolver = StackerDeploymentResolver::new();
        let id = DeploymentIdentifier::from_hash("native_hash");

        let result = resolver.resolve(&id).await;
        assert_eq!(result.unwrap(), "native_hash");
    }

    #[tokio::test]
    async fn test_stacker_resolver_rejects_installation_id() {
        // StackerDeploymentResolver doesn't support installation IDs
        let resolver = StackerDeploymentResolver::new();
        let id = DeploymentIdentifier::from_id(12345);

        let result = resolver.resolve(&id).await;
        assert!(result.is_err());

        let err = result.unwrap_err();
        match err {
            DeploymentResolveError::NotSupported(msg) => {
                assert!(msg.contains("12345"));
                assert!(msg.contains("User Service"));
            }
            _ => panic!("Expected NotSupported error, got {:?}", err),
        }
    }

    // ============================================================
    // DeploymentIdentifier tests
    // ============================================================

    #[test]
    fn test_identifier_from_hash() {
        let id = DeploymentIdentifier::from_hash("abc123");
        assert!(id.is_hash());
        assert!(!id.requires_resolution());
        assert_eq!(id.as_hash(), Some("abc123"));
        assert_eq!(id.as_installation_id(), None);
    }

    #[test]
    fn test_identifier_from_id() {
        let id = DeploymentIdentifier::from_id(99999);
        assert!(!id.is_hash());
        assert!(id.requires_resolution());
        assert_eq!(id.as_hash(), None);
        assert_eq!(id.as_installation_id(), Some(99999));
    }

    #[test]
    fn test_into_hash_success() {
        let id = DeploymentIdentifier::from_hash("convert_me");
        let result = id.into_hash();
        assert_eq!(result.unwrap(), "convert_me");
    }

    #[test]
    fn test_into_hash_fails_for_installation_id() {
        let id = DeploymentIdentifier::from_id(123);
        let result = id.into_hash();
        assert!(result.is_err());

        // The error returns the original identifier
        let returned_id = result.unwrap_err();
        assert_eq!(returned_id.as_installation_id(), Some(123));
    }

    #[test]
    fn test_try_from_options_prefers_hash() {
        // When both are provided, hash takes priority
        let id =
            DeploymentIdentifier::try_from_options(Some("my_hash".to_string()), Some(999)).unwrap();

        assert!(id.is_hash());
        assert_eq!(id.as_hash(), Some("my_hash"));
    }

    #[test]
    fn test_try_from_options_uses_id_when_no_hash() {
        let id = DeploymentIdentifier::try_from_options(None, Some(42)).unwrap();

        assert!(!id.is_hash());
        assert_eq!(id.as_installation_id(), Some(42));
    }

    #[test]
    fn test_try_from_options_fails_when_both_none() {
        let result = DeploymentIdentifier::try_from_options(None, None);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "Either deployment_hash or deployment_id is required"
        );
    }

    #[test]
    fn test_from_traits() {
        // Test From<String>
        let id: DeploymentIdentifier = "string_hash".to_string().into();
        assert!(id.is_hash());

        // Test From<&str>
        let id: DeploymentIdentifier = "str_hash".into();
        assert!(id.is_hash());

        // Test From<i64>
        let id: DeploymentIdentifier = 12345i64.into();
        assert!(!id.is_hash());

        // Test From<i32>
        let id: DeploymentIdentifier = 42i32.into();
        assert!(!id.is_hash());
        assert_eq!(id.as_installation_id(), Some(42));
    }

    // ============================================================
    // ResolvedDeploymentInfo tests
    // ============================================================

    #[test]
    fn test_resolved_info_from_hash() {
        let info = ResolvedDeploymentInfo::from_hash("test_hash".to_string());

        assert_eq!(info.deployment_hash, "test_hash");
        assert_eq!(info.status, "unknown");
        assert!(info.domain.is_none());
        assert!(info.server_ip.is_none());
        assert!(info.apps.is_none());
    }

    #[test]
    fn test_resolved_info_default() {
        let info = ResolvedDeploymentInfo::default();

        assert!(info.deployment_hash.is_empty());
        assert!(info.status.is_empty());
        assert!(info.domain.is_none());
    }
}
