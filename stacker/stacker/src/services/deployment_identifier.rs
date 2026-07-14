//! Deployment Identifier abstraction for resolving deployments.
//!
//! This module provides core types for deployment identification.
//! These types are **independent of any external service** - Stack Builder
//! works fully with just the types defined here.
//!
//! For User Service (legacy installations) integration, see:
//! `connectors::user_service::deployment_resolver`
//!
//! # Example (Stack Builder Native)
//! ```rust,ignore
//! use crate::services::DeploymentIdentifier;
//!
//! // From deployment_hash (Stack Builder - native)
//! let id = DeploymentIdentifier::from_hash("abc123");
//!
//! // Direct resolution for Stack Builder (no external service needed)
//! let hash = id.into_hash().expect("Stack Builder always has hash");
//! ```
//!
//! # Example (With User Service)
//! ```rust,ignore
//! use crate::services::DeploymentIdentifier;
//! use crate::connectors::user_service::UserServiceDeploymentResolver;
//!
//! // From installation ID (requires User Service)
//! let id = DeploymentIdentifier::from_id(13467);
//!
//! // Resolve via User Service
//! let resolver = UserServiceDeploymentResolver::new(&settings.user_service_url, token);
//! let hash = resolver.resolve(&id).await?;
//! ```

use async_trait::async_trait;
use serde::Deserialize;

/// Represents a deployment identifier that can be resolved to a deployment_hash.
///
/// This enum abstracts the difference between:
/// - Stack Builder deployments (identified by hash directly)
/// - Legacy User Service installations (identified by numeric ID)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeploymentIdentifier {
    /// Direct deployment hash (Stack Builder deployments)
    Hash(String),
    /// User Service installation ID (legacy deployments)
    InstallationId(i64),
}

impl DeploymentIdentifier {
    /// Create from deployment hash (Stack Builder)
    pub fn from_hash(hash: impl Into<String>) -> Self {
        Self::Hash(hash.into())
    }

    /// Create from installation ID (User Service)
    pub fn from_id(id: i64) -> Self {
        Self::InstallationId(id)
    }

    /// Try to create from optional hash and id.
    /// Prefers hash if both are provided (Stack Builder takes priority).
    pub fn try_from_options(hash: Option<String>, id: Option<i64>) -> Result<Self, &'static str> {
        match (hash, id) {
            (Some(h), _) => Ok(Self::Hash(h)),
            (None, Some(i)) => Ok(Self::InstallationId(i)),
            (None, None) => Err("Either deployment_hash or deployment_id is required"),
        }
    }

    /// Check if this is a direct hash (no external resolution needed)
    pub fn is_hash(&self) -> bool {
        matches!(self, Self::Hash(_))
    }

    /// Check if this requires external resolution (User Service)
    pub fn requires_resolution(&self) -> bool {
        matches!(self, Self::InstallationId(_))
    }

    /// Get the hash directly if available (no async resolution)
    /// Returns None if this is an InstallationId that needs resolution
    pub fn as_hash(&self) -> Option<&str> {
        match self {
            Self::Hash(h) => Some(h),
            _ => None,
        }
    }

    /// Get the installation ID if this is a legacy deployment
    pub fn as_installation_id(&self) -> Option<i64> {
        match self {
            Self::InstallationId(id) => Some(*id),
            _ => None,
        }
    }

    /// Convert to hash, failing if this requires external resolution.
    /// Use this for Stack Builder native deployments only.
    pub fn into_hash(self) -> Result<String, Self> {
        match self {
            Self::Hash(h) => Ok(h),
            other => Err(other),
        }
    }
}

// Implement From traits for ergonomic conversion

impl From<String> for DeploymentIdentifier {
    fn from(hash: String) -> Self {
        Self::Hash(hash)
    }
}

impl From<&str> for DeploymentIdentifier {
    fn from(hash: &str) -> Self {
        Self::Hash(hash.to_string())
    }
}

impl From<i64> for DeploymentIdentifier {
    fn from(id: i64) -> Self {
        Self::InstallationId(id)
    }
}

impl From<i32> for DeploymentIdentifier {
    fn from(id: i32) -> Self {
        Self::InstallationId(id as i64)
    }
}

/// Errors that can occur during deployment resolution
#[derive(Debug)]
pub enum DeploymentResolveError {
    /// Deployment/Installation not found
    NotFound(String),
    /// Deployment exists but has no deployment_hash
    NoHash(String),
    /// External service error (User Service, etc.)
    ServiceError(String),
    /// Resolution not supported for this identifier type
    NotSupported(String),
}

impl std::fmt::Display for DeploymentResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound(msg) => write!(f, "Deployment not found: {}", msg),
            Self::NoHash(msg) => write!(f, "Deployment has no hash: {}", msg),
            Self::ServiceError(msg) => write!(f, "Service error: {}", msg),
            Self::NotSupported(msg) => write!(f, "Resolution not supported: {}", msg),
        }
    }
}

impl std::error::Error for DeploymentResolveError {}

// Allow easy conversion to String for MCP tool errors
impl From<DeploymentResolveError> for String {
    fn from(err: DeploymentResolveError) -> String {
        err.to_string()
    }
}

/// Trait for resolving deployment identifiers to deployment hashes.
///
/// Different implementations can resolve from different sources:
/// - `StackerDeploymentResolver`: Native Stack Builder (hash-only, no external deps)
/// - `UserServiceDeploymentResolver`: Resolves via User Service (in connectors/)
#[async_trait]
pub trait DeploymentResolver: Send + Sync {
    /// Resolve a deployment identifier to its deployment_hash
    async fn resolve(
        &self,
        identifier: &DeploymentIdentifier,
    ) -> Result<String, DeploymentResolveError>;
}

/// Native Stack Builder resolver - no external dependencies.
/// Only supports direct hash identifiers (Stack Builder deployments).
/// For User Service installations, use `UserServiceDeploymentResolver` from connectors.
pub struct StackerDeploymentResolver;

impl StackerDeploymentResolver {
    pub fn new() -> Self {
        Self
    }
}

impl Default for StackerDeploymentResolver {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl DeploymentResolver for StackerDeploymentResolver {
    async fn resolve(
        &self,
        identifier: &DeploymentIdentifier,
    ) -> Result<String, DeploymentResolveError> {
        match identifier {
            DeploymentIdentifier::Hash(hash) => Ok(hash.clone()),
            DeploymentIdentifier::InstallationId(id) => {
                Err(DeploymentResolveError::NotSupported(format!(
                    "Installation ID {} requires User Service. Enable user_service connector.",
                    id
                )))
            }
        }
    }
}

/// Helper struct for deserializing deployment identifier from MCP tool args
#[derive(Debug, Deserialize, Default)]
pub struct DeploymentIdentifierArgs {
    #[serde(default)]
    pub deployment_id: Option<i64>,
    #[serde(default)]
    pub deployment_hash: Option<String>,
}

impl DeploymentIdentifierArgs {
    /// Convert to DeploymentIdentifier, preferring hash if both provided
    pub fn into_identifier(self) -> Result<DeploymentIdentifier, &'static str> {
        DeploymentIdentifier::try_from_options(self.deployment_hash, self.deployment_id)
    }
}

impl TryFrom<DeploymentIdentifierArgs> for DeploymentIdentifier {
    type Error = &'static str;

    fn try_from(args: DeploymentIdentifierArgs) -> Result<Self, Self::Error> {
        args.into_identifier()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_hash() {
        let id = DeploymentIdentifier::from_hash("abc123");
        assert!(id.is_hash());
        assert!(!id.requires_resolution());
        assert_eq!(id.as_hash(), Some("abc123"));
    }

    #[test]
    fn test_from_id() {
        let id = DeploymentIdentifier::from_id(12345);
        assert!(!id.is_hash());
        assert!(id.requires_resolution());
        assert_eq!(id.as_hash(), None);
        assert_eq!(id.as_installation_id(), Some(12345));
    }

    #[test]
    fn test_into_hash_success() {
        let id = DeploymentIdentifier::from_hash("hash123");
        assert_eq!(id.into_hash(), Ok("hash123".to_string()));
    }

    #[test]
    fn test_into_hash_failure() {
        let id = DeploymentIdentifier::from_id(123);
        assert!(id.into_hash().is_err());
    }

    #[test]
    fn test_from_string() {
        let id: DeploymentIdentifier = "hash123".into();
        assert!(id.is_hash());
    }

    #[test]
    fn test_from_i64() {
        let id: DeploymentIdentifier = 12345i64.into();
        assert!(!id.is_hash());
    }

    #[test]
    fn test_try_from_options_prefers_hash() {
        let id =
            DeploymentIdentifier::try_from_options(Some("hash".to_string()), Some(123)).unwrap();
        assert!(id.is_hash());
    }

    #[test]
    fn test_try_from_options_uses_id_when_no_hash() {
        let id = DeploymentIdentifier::try_from_options(None, Some(123)).unwrap();
        assert!(!id.is_hash());
    }

    #[test]
    fn test_try_from_options_fails_when_both_none() {
        let result = DeploymentIdentifier::try_from_options(None, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_args_into_identifier() {
        let args = DeploymentIdentifierArgs {
            deployment_id: Some(123),
            deployment_hash: None,
        };
        let id = args.into_identifier().unwrap();
        assert!(!id.is_hash());
    }

    #[tokio::test]
    async fn test_stacker_resolver_hash() {
        let resolver = StackerDeploymentResolver::new();
        let id = DeploymentIdentifier::from_hash("test_hash");
        let result = resolver.resolve(&id).await;
        assert_eq!(result.unwrap(), "test_hash");
    }

    #[tokio::test]
    async fn test_stacker_resolver_rejects_installation_id() {
        let resolver = StackerDeploymentResolver::new();
        let id = DeploymentIdentifier::from_id(123);
        let result = resolver.resolve(&id).await;
        assert!(result.is_err());
    }
}
