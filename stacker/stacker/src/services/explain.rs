use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::services::config_renderer::{render_env, EnvRenderError, EnvRenderInput};

pub const EXPLAIN_SCHEMA_VERSION: &str = "v1alpha1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ExplainEnv {
    pub schema_version: String,
    pub deployment_hash: String,
    pub app_code: String,
    pub local_authoring_env_path: String,
    pub runtime_env_path: String,
    pub runtime_compose_path: String,
    pub layers: Vec<ExplainEnvLayer>,
    pub destination: ExplainDestination,
    pub rendered_env: ExplainRenderedEnv,
    pub reasoning: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ExplainEnvLayer {
    pub name: String,
    pub key_names: Vec<String>,
    pub key_count: usize,
    pub hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ExplainDestination {
    pub path: String,
    pub write_policy: String,
    pub drift_protection: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ExplainRenderedEnv {
    pub hash: String,
    pub inputs: Vec<String>,
    pub server_secrets_inherited: bool,
    pub service_secrets_override_server_secrets: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ExplainTopology {
    pub schema_version: String,
    pub deployment_hash: String,
    pub target: String,
    pub local_compose_path: String,
    pub runtime_compose_path: String,
    pub local_authoring_env_path: String,
    pub runtime_env_path: String,
    pub services: Vec<ExplainTopologyService>,
    pub reasoning: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ExplainTopologyService {
    pub code: String,
    pub name: String,
    pub enabled: bool,
}

pub fn build_explain_env(
    deployment_hash: &str,
    app_code: &str,
    local_authoring_env_path: &str,
    runtime_env_path: &str,
    runtime_compose_path: &str,
    input: EnvRenderInput,
) -> Result<ExplainEnv, EnvRenderError> {
    let rendered = render_env(input.clone())?;
    let overlapping_keys = input
        .service
        .keys()
        .any(|key| input.server.contains_key(key) && input.inherit_server_secrets);

    Ok(ExplainEnv {
        schema_version: EXPLAIN_SCHEMA_VERSION.to_string(),
        deployment_hash: deployment_hash.to_string(),
        app_code: app_code.to_string(),
        local_authoring_env_path: local_authoring_env_path.to_string(),
        runtime_env_path: runtime_env_path.to_string(),
        runtime_compose_path: runtime_compose_path.to_string(),
        layers: env_layers(&input),
        destination: ExplainDestination {
            path: runtime_env_path.to_string(),
            write_policy: "drift-protected".to_string(),
            drift_protection: true,
        },
        rendered_env: ExplainRenderedEnv {
            hash: rendered.hash,
            inputs: rendered
                .inputs
                .iter()
                .map(|item| item.to_string())
                .collect(),
            server_secrets_inherited: input.inherit_server_secrets,
            service_secrets_override_server_secrets: overlapping_keys,
        },
        reasoning: vec![
            "runtime env path is resolved from the canonical remote env path helper".to_string(),
            "env layers are merged in precedence order: base -> generated -> server -> service -> compose"
                .to_string(),
        ],
    })
}

pub fn build_explain_topology(
    deployment_hash: &str,
    target: &str,
    local_compose_path: &str,
    runtime_compose_path: &str,
    local_authoring_env_path: &str,
    runtime_env_path: &str,
    services: Vec<ExplainTopologyService>,
) -> ExplainTopology {
    ExplainTopology {
        schema_version: EXPLAIN_SCHEMA_VERSION.to_string(),
        deployment_hash: deployment_hash.to_string(),
        target: target.to_string(),
        local_compose_path: local_compose_path.to_string(),
        runtime_compose_path: runtime_compose_path.to_string(),
        local_authoring_env_path: local_authoring_env_path.to_string(),
        runtime_env_path: runtime_env_path.to_string(),
        services,
        reasoning: vec![
            "runtime compose path is fixed to the canonical remote deployment location".to_string(),
            "runtime env path is shared across deployed services for the target deployment"
                .to_string(),
        ],
    }
}

fn env_layers(input: &EnvRenderInput) -> Vec<ExplainEnvLayer> {
    let mut layers = Vec::new();

    if !input.base.is_empty() {
        layers.push(to_layer("base", &input.base));
    }
    if !input.generated.is_empty() {
        layers.push(to_layer("generated", &input.generated));
    }
    if input.inherit_server_secrets && !input.server.is_empty() {
        layers.push(to_layer("server", &input.server));
    }
    if !input.service.is_empty() {
        layers.push(to_layer("service", &input.service));
    }
    if !input.compose_environment.is_empty() {
        layers.push(to_layer("compose", &input.compose_environment));
    }

    layers
}

fn to_layer(name: &str, layer: &HashMap<String, String>) -> ExplainEnvLayer {
    let ordered = layer
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect::<BTreeMap<_, _>>();
    let digest_source = ordered
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join("\n");

    ExplainEnvLayer {
        name: name.to_string(),
        key_names: ordered.keys().cloned().collect(),
        key_count: ordered.len(),
        hash: format!("{:x}", Sha256::digest(digest_source.as_bytes())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helpers::{remote_runtime_compose_path, remote_runtime_env_path};

    fn sample_input() -> EnvRenderInput {
        let mut input = EnvRenderInput {
            inherit_server_secrets: true,
            ..EnvRenderInput::default()
        };
        input.base.insert("HOST".to_string(), "0.0.0.0".to_string());
        input.base.insert("PORT".to_string(), "8080".to_string());
        input.server.insert(
            "DATABASE_URL".to_string(),
            "SUPER_SECRET_SHOULD_NOT_LEAK".to_string(),
        );
        input
            .service
            .insert("DATABASE_URL".to_string(), "service-override".to_string());
        input
            .compose_environment
            .insert("RUST_LOG".to_string(), "debug".to_string());
        input.generated.insert(
            "DEPLOYMENT_HASH".to_string(),
            "deployment_state_online".to_string(),
        );
        input
    }

    #[test]
    fn build_explain_env_uses_hashes_and_paths_without_secret_values() {
        let explain = build_explain_env(
            "deployment_state_online",
            "device-api",
            "docker/prod/.env",
            remote_runtime_env_path(),
            remote_runtime_compose_path(),
            sample_input(),
        )
        .expect("explain env should build");

        assert_eq!(explain.schema_version, EXPLAIN_SCHEMA_VERSION);
        assert_eq!(explain.destination.path, remote_runtime_env_path());
        assert!(explain.rendered_env.service_secrets_override_server_secrets);
        assert!(explain.layers.iter().any(|layer| layer.name == "generated"));
        assert!(!explain
            .rendered_env
            .inputs
            .contains(&"generated".to_string()));

        let serialized = serde_json::to_string(&explain).expect("serialize explain env");
        assert!(!serialized.contains("SUPER_SECRET_SHOULD_NOT_LEAK"));
        assert!(serialized.contains("DATABASE_URL"));
    }

    #[test]
    fn build_explain_topology_uses_canonical_runtime_paths() {
        let topology = build_explain_topology(
            "deployment_state_online",
            "cloud",
            "docker/prod/compose.yml",
            remote_runtime_compose_path(),
            "docker/prod/.env",
            remote_runtime_env_path(),
            vec![
                ExplainTopologyService {
                    code: "device-api".to_string(),
                    name: "Device API".to_string(),
                    enabled: true,
                },
                ExplainTopologyService {
                    code: "upload".to_string(),
                    name: "Upload".to_string(),
                    enabled: true,
                },
            ],
        );

        assert_eq!(topology.runtime_compose_path, remote_runtime_compose_path());
        assert_eq!(topology.runtime_env_path, remote_runtime_env_path());
        assert_eq!(topology.services.len(), 2);
    }
}
