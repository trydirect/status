use std::collections::BTreeMap;
use std::fmt;

use actix_web::http::StatusCode;
use actix_web::{HttpResponse, ResponseError};
use serde::{Deserialize, Serialize};

pub const TYPED_ERROR_SCHEMA_VERSION: &str = "v1alpha1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TypedErrorCode {
    ComposePathUnresolved,
    DeploymentCapabilityMissing,
    DeploymentNotFound,
    InternalError,
    InvalidRequest,
    PermissionDenied,
    PlanStale,
    RegistryAuthMissing,
    RollbackTargetUnavailable,
    RuntimeEnvDriftDetected,
    VaultSecretNotFound,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TypedRemediationClass {
    Auth,
    Capability,
    Configuration,
    Internal,
    Permissions,
    Secret,
    State,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TypedErrorEnvelope {
    pub schema_version: String,
    pub code: TypedErrorCode,
    pub message: String,
    pub retryable: bool,
    pub remediation_class: TypedRemediationClass,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub context: BTreeMap<String, String>,
}

impl TypedErrorEnvelope {
    pub fn new(
        code: TypedErrorCode,
        message: impl Into<String>,
        retryable: bool,
        remediation_class: TypedRemediationClass,
    ) -> Self {
        Self {
            schema_version: TYPED_ERROR_SCHEMA_VERSION.to_string(),
            code,
            message: message.into(),
            retryable,
            remediation_class,
            context: BTreeMap::new(),
        }
    }

    pub fn invalid_request(message: impl Into<String>) -> Self {
        Self::new(
            TypedErrorCode::InvalidRequest,
            message,
            false,
            TypedRemediationClass::Configuration,
        )
    }

    pub fn deployment_not_found(message: impl Into<String>) -> Self {
        Self::new(
            TypedErrorCode::DeploymentNotFound,
            message,
            false,
            TypedRemediationClass::State,
        )
    }

    pub fn deployment_capability_missing(message: impl Into<String>) -> Self {
        Self::new(
            TypedErrorCode::DeploymentCapabilityMissing,
            message,
            false,
            TypedRemediationClass::Capability,
        )
    }

    pub fn compose_path_unresolved(message: impl Into<String>) -> Self {
        Self::new(
            TypedErrorCode::ComposePathUnresolved,
            message,
            false,
            TypedRemediationClass::Configuration,
        )
    }

    pub fn vault_secret_not_found(message: impl Into<String>) -> Self {
        Self::new(
            TypedErrorCode::VaultSecretNotFound,
            message,
            false,
            TypedRemediationClass::Secret,
        )
    }

    pub fn permission_denied(message: impl Into<String>) -> Self {
        Self::new(
            TypedErrorCode::PermissionDenied,
            message,
            false,
            TypedRemediationClass::Permissions,
        )
    }

    pub fn internal_error(message: impl Into<String>) -> Self {
        Self::new(
            TypedErrorCode::InternalError,
            message,
            true,
            TypedRemediationClass::Internal,
        )
    }

    pub fn with_context(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.context.insert(key.into(), value.into());
        self
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| {
            format!(
                r#"{{"schemaVersion":"{TYPED_ERROR_SCHEMA_VERSION}","code":"internal_error","message":"failed to serialize typed error","retryable":true,"remediationClass":"internal"}}"#
            )
        })
    }

    pub fn to_pretty_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| self.to_json())
    }

    pub fn from_mcp_error_message(message: &str) -> Self {
        if let Ok(error) = serde_json::from_str::<Self>(message) {
            return error;
        }
        if message.starts_with("Deployment not found") {
            return Self::deployment_not_found(message);
        }
        if message.starts_with("Forbidden:")
            || message.contains("Two-factor authentication is required")
        {
            return Self::permission_denied(message);
        }
        if message.starts_with("Invalid arguments:")
            || message.starts_with("No deployment apps found")
            || message.contains("App or service")
            || message.contains("Missing params")
        {
            return Self::invalid_request(message);
        }
        Self::internal_error(message)
    }
}

#[derive(Debug, Clone)]
pub struct ApiTypedError {
    status: StatusCode,
    envelope: TypedErrorEnvelope,
}

impl ApiTypedError {
    pub fn bad_request(envelope: TypedErrorEnvelope) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            envelope,
        }
    }

    pub fn not_found(envelope: TypedErrorEnvelope) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            envelope,
        }
    }

    pub fn forbidden(envelope: TypedErrorEnvelope) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            envelope,
        }
    }

    pub fn conflict(envelope: TypedErrorEnvelope) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            envelope,
        }
    }

    pub fn internal(envelope: TypedErrorEnvelope) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            envelope,
        }
    }
}

impl fmt::Display for ApiTypedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.envelope.message)
    }
}

impl std::error::Error for ApiTypedError {}

impl ResponseError for ApiTypedError {
    fn status_code(&self) -> StatusCode {
        self.status
    }

    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(self.status).json(&self.envelope)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal_errors_are_retryable() {
        let error = TypedErrorEnvelope::internal_error("temporary backend issue");
        assert!(error.retryable);
        assert_eq!(error.remediation_class, TypedRemediationClass::Internal);
    }

    #[test]
    fn deployment_capability_errors_are_not_retryable() {
        let error = TypedErrorEnvelope::deployment_capability_missing("compose logs unsupported");
        assert!(!error.retryable);
        assert_eq!(error.remediation_class, TypedRemediationClass::Capability);
    }

    #[test]
    fn mcp_error_mapping_prefers_known_not_found_code() {
        let error = TypedErrorEnvelope::from_mcp_error_message("Deployment not found");
        assert_eq!(error.code, TypedErrorCode::DeploymentNotFound);
    }

    #[test]
    fn mcp_error_mapping_preserves_pre_serialized_typed_errors() {
        let envelope = TypedErrorEnvelope::invalid_request("confirm=true is required")
            .with_context("tool", "apply_deployment_plan");
        let error = TypedErrorEnvelope::from_mcp_error_message(&envelope.to_pretty_json());

        assert_eq!(error, envelope);
    }
}
