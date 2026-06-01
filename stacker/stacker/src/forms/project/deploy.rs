use crate::forms;
use crate::forms::{CloudForm, ServerForm};
use serde_derive::{Deserialize, Serialize};
use serde_json::Value;
use serde_valid::Validate;

/// Docker registry credentials for pulling private images during deployment.
#[derive(Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct RegistryForm {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub docker_username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub docker_password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub docker_registry: Option<String>,
}

impl std::fmt::Debug for RegistryForm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegistryForm")
            .field("docker_username", &self.docker_username)
            .field("docker_password", &"[REDACTED]")
            .field("docker_registry", &self.docker_registry)
            .finish()
    }
}

/// Validates that cloud deployments have required instance configuration
fn validate_cloud_instance_config(deploy: &Deploy) -> Result<(), serde_valid::validation::Error> {
    // Skip validation for "own" server deployments
    if deploy.cloud.provider == "own" {
        return Ok(());
    }

    let mut missing = Vec::new();

    if deploy.server.region.as_ref().is_none_or(|s| s.is_empty()) {
        missing.push("region");
    }
    if deploy.server.server.as_ref().is_none_or(|s| s.is_empty()) {
        missing.push("server");
    }
    if deploy.server.os.as_ref().is_none_or(|s| s.is_empty()) {
        missing.push("os");
    }

    if missing.is_empty() {
        Ok(())
    } else {
        Err(serde_valid::validation::Error::Custom(format!(
            "Instance configuration incomplete. Missing: {}. Select datacenter, hardware, and OS before deploying.",
            missing.join(", ")
        )))
    }
}

#[derive(Default, Clone, PartialEq, Serialize, Deserialize, Validate)]
#[validate(custom(validate_cloud_instance_config))]
pub struct Deploy {
    #[validate]
    pub(crate) stack: Stack,
    #[validate]
    pub(crate) server: ServerForm,
    #[validate]
    pub(crate) cloud: CloudForm,
    /// Optional Docker registry credentials for pulling private images.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) registry: Option<RegistryForm>,
    /// Optional selected deploy environment, e.g. development/staging/production.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) environment: Option<String>,
    /// Config files uploaded by the CLI. Contents may include secrets and must not be logged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) config_files: Option<Value>,
    /// Safe metadata for Stack Builder artifact/config-file visibility.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) config_bundle: Option<Value>,
}

impl std::fmt::Debug for Deploy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Deploy")
            .field("stack", &self.stack)
            .field("server", &self.server)
            .field("cloud", &self.cloud)
            .field("registry", &self.registry)
            .field("environment", &self.environment)
            .field("config_files", &"[REDACTED]")
            .field("config_bundle", &self.config_bundle)
            .finish()
    }
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize, Validate)]
pub struct Stack {
    #[validate(min_length = 2)]
    #[validate(max_length = 255)]
    pub stack_code: Option<String>,
    pub vars: Option<Vec<forms::project::Var>>,
    pub integrated_features: Option<Vec<Value>>,
    pub extended_features: Option<Vec<Value>>,
    pub subscriptions: Option<Vec<String>>,
    pub form_app: Option<Vec<String>>,
}
