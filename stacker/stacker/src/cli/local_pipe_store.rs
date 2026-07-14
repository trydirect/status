use std::fs;
use std::path::{Path, PathBuf};

use chrono::Utc;
use pipe_adapter_sdk::PipeAdapterReference;
use serde::{Deserialize, Serialize};

use crate::cli::error::CliError;
use crate::cli::stacker_client::{CreatePipeInstanceApiRequest, CreatePipeTemplateApiRequest};
use crate::helpers::fs::write_atomic;

pub const LOCAL_PIPE_SCHEMA_VERSION: u32 = 1;
const LOCAL_PIPE_FILE_MODE: u32 = 0o600;
const LOCAL_PIPE_DIR: &str = ".stacker/pipes";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LocalPipeBinding {
    pub selector: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub adapter: Option<PipeAdapterReference>,
    pub method: String,
    pub path: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LocalPipeTemplate {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub source_app_type: String,
    pub source_endpoint: serde_json::Value,
    pub target_app_type: String,
    pub target_endpoint: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_external_url: Option<String>,
    pub field_mapping: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<serde_json::Value>,
    pub is_public: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LocalPipeInstance {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_adapter: Option<PipeAdapterReference>,
    pub source_container: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_adapter: Option<PipeAdapterReference>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_container: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field_mapping_override: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_override: Option<serde_json::Value>,
    #[serde(default)]
    pub trigger_count: i64,
    #[serde(default)]
    pub error_count: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_triggered_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct LocalPipePromotion {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_deployment_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_template_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_instance_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub promoted_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct LocalPipeDiagnostics {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct NewLocalPipeDocument {
    pub name: String,
    pub source: LocalPipeBinding,
    pub target: LocalPipeBinding,
    pub template: LocalPipeTemplate,
    pub instance: LocalPipeInstance,
    pub diagnostics: LocalPipeDiagnostics,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LocalPipeDocument {
    pub schema_version: u32,
    pub id: String,
    pub name: String,
    pub created_at: String,
    pub updated_at: String,
    pub status: String,
    pub source: LocalPipeBinding,
    pub target: LocalPipeBinding,
    pub template: LocalPipeTemplate,
    pub instance: LocalPipeInstance,
    #[serde(default)]
    pub promotion: LocalPipePromotion,
    #[serde(default)]
    pub diagnostics: LocalPipeDiagnostics,
}

impl LocalPipeDocument {
    pub fn draft(input: NewLocalPipeDocument) -> Result<Self, CliError> {
        let id = local_pipe_id_from_name(&input.name)?;
        let now = Utc::now().to_rfc3339();
        let document = Self {
            schema_version: LOCAL_PIPE_SCHEMA_VERSION,
            id,
            name: input.name,
            created_at: now.clone(),
            updated_at: now,
            status: "draft".to_string(),
            source: input.source,
            target: input.target,
            template: input.template,
            instance: input.instance,
            promotion: LocalPipePromotion::default(),
            diagnostics: input.diagnostics,
        };
        document.validate()?;
        Ok(document)
    }

    pub fn validate(&self) -> Result<(), CliError> {
        if self.schema_version != LOCAL_PIPE_SCHEMA_VERSION {
            return Err(CliError::ConfigValidation(format!(
                "Unsupported local pipe schema version {} for '{}'",
                self.schema_version, self.id
            )));
        }
        if self.name.trim().is_empty() {
            return Err(CliError::ConfigValidation(
                "Local pipe name cannot be empty".to_string(),
            ));
        }
        validate_local_pipe_id(&self.id)?;
        if self.source.selector.trim().is_empty() || self.target.selector.trim().is_empty() {
            return Err(CliError::ConfigValidation(
                "Local pipe source and target selectors are required".to_string(),
            ));
        }
        if self.instance.source_container.trim().is_empty() {
            return Err(CliError::ConfigValidation(format!(
                "Local pipe '{}' is missing a source container",
                self.id
            )));
        }
        if self.instance.target_adapter.is_none()
            && self.instance.target_container.is_none()
            && self.instance.target_url.is_none()
        {
            return Err(CliError::ConfigValidation(format!(
                "Local pipe '{}' must define a target adapter, target container, or target URL",
                self.id
            )));
        }

        if let Some(adapter) = &self.instance.source_adapter {
            validate_adapter_config(adapter.config.as_ref(), "source_adapter.config")?;
        }
        if let Some(adapter) = &self.instance.target_adapter {
            validate_adapter_config(adapter.config.as_ref(), "target_adapter.config")?;
        }
        validate_adapter_config(self.template.config.as_ref(), "template.config")?;
        validate_adapter_config(
            self.instance.config_override.as_ref(),
            "instance.config_override",
        )?;

        Ok(())
    }

    pub fn to_template_request(&self) -> CreatePipeTemplateApiRequest {
        CreatePipeTemplateApiRequest {
            name: self.name.clone(),
            description: self.template.description.clone(),
            source_app_type: self.template.source_app_type.clone(),
            source_endpoint: self.template.source_endpoint.clone(),
            target_app_type: self.template.target_app_type.clone(),
            target_endpoint: self.template.target_endpoint.clone(),
            target_external_url: self.template.target_external_url.clone(),
            field_mapping: self.template.field_mapping.clone(),
            config: self.template.config.clone(),
            is_public: Some(self.template.is_public),
        }
    }

    pub fn to_instance_request(
        &self,
        deployment_hash: String,
        template_id: String,
    ) -> CreatePipeInstanceApiRequest {
        CreatePipeInstanceApiRequest {
            deployment_hash: Some(deployment_hash),
            source_adapter: self.instance.source_adapter.clone(),
            source_container: self.instance.source_container.clone(),
            target_adapter: self.instance.target_adapter.clone(),
            target_container: self.instance.target_container.clone(),
            target_url: self.instance.target_url.clone(),
            template_id: Some(template_id),
            field_mapping_override: self.instance.field_mapping_override.clone(),
            config_override: self.instance.config_override.clone(),
        }
    }

    pub fn record_promotion(
        &mut self,
        deployment_hash: &str,
        template_id: &str,
        instance_id: &str,
    ) {
        let promoted_at = Utc::now().to_rfc3339();
        self.updated_at = promoted_at.clone();
        self.promotion.last_deployment_hash = Some(deployment_hash.to_string());
        self.promotion.remote_template_id = Some(template_id.to_string());
        self.promotion.remote_instance_id = Some(instance_id.to_string());
        self.promotion.promoted_at = Some(promoted_at);
    }

    pub fn effective_field_mapping(&self) -> &serde_json::Value {
        self.instance
            .field_mapping_override
            .as_ref()
            .unwrap_or(&self.template.field_mapping)
    }

    pub fn set_status(&mut self, status: &str) {
        self.status = status.to_string();
        self.updated_at = Utc::now().to_rfc3339();
    }

    pub fn record_trigger_success(&mut self) {
        let now = Utc::now().to_rfc3339();
        self.updated_at = now.clone();
        self.instance.last_triggered_at = Some(now);
        self.instance.trigger_count += 1;
    }

    pub fn record_trigger_failure(&mut self) {
        self.instance.error_count += 1;
        self.set_status("error");
    }

    pub fn source_display(&self) -> &str {
        self.instance
            .source_adapter
            .as_ref()
            .map(|adapter| adapter.code.as_str())
            .unwrap_or(self.instance.source_container.as_str())
    }

    pub fn target_display(&self) -> &str {
        self.instance
            .target_adapter
            .as_ref()
            .map(|adapter| adapter.code.as_str())
            .or(self.instance.target_container.as_deref())
            .or(self.instance.target_url.as_deref())
            .unwrap_or("-")
    }
}

#[derive(Debug, Clone)]
pub struct LocalPipeStore {
    project_dir: PathBuf,
}

impl LocalPipeStore {
    pub fn new(project_dir: impl Into<PathBuf>) -> Self {
        Self {
            project_dir: project_dir.into(),
        }
    }

    pub fn pipes_dir(&self) -> PathBuf {
        self.project_dir.join(LOCAL_PIPE_DIR)
    }

    pub fn pipe_path(&self, id: &str) -> PathBuf {
        self.pipes_dir().join(format!("{id}.json"))
    }

    pub fn list(&self) -> Result<Vec<LocalPipeDocument>, CliError> {
        let dir = self.pipes_dir();
        if !dir.exists() {
            return Ok(Vec::new());
        }

        let mut entries = Vec::new();
        for entry in fs::read_dir(&dir).map_err(CliError::Io)? {
            let entry = entry.map_err(CliError::Io)?;
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            let content = fs::read_to_string(&path).map_err(CliError::Io)?;
            let document: LocalPipeDocument = serde_json::from_str(&content).map_err(|err| {
                CliError::ConfigValidation(format!(
                    "Failed to parse local pipe file {}: {}",
                    path.display(),
                    err
                ))
            })?;
            document.validate()?;
            entries.push(document);
        }

        entries.sort_by(|left, right| left.name.to_lowercase().cmp(&right.name.to_lowercase()));
        Ok(entries)
    }

    pub fn save_new(&self, document: &LocalPipeDocument) -> Result<PathBuf, CliError> {
        document.validate()?;
        let path = self.pipe_path(&document.id);
        if path.exists() {
            return Err(CliError::ConfigValidation(format!(
                "Local pipe '{}' already exists at {}",
                document.id,
                path.display()
            )));
        }

        let duplicate_name = self
            .list()?
            .into_iter()
            .find(|existing| existing.name.eq_ignore_ascii_case(&document.name));
        if let Some(existing) = duplicate_name {
            return Err(CliError::ConfigValidation(format!(
                "Local pipe name '{}' is already used by '{}'. Choose a different name or update the existing local pipe once edit support lands.",
                document.name,
                existing.id
            )));
        }

        self.save(document)
    }

    pub fn save(&self, document: &LocalPipeDocument) -> Result<PathBuf, CliError> {
        document.validate()?;
        let path = self.pipe_path(&document.id);
        let bytes = serde_json::to_vec_pretty(document).map_err(|err| {
            CliError::ConfigValidation(format!(
                "Failed to serialize local pipe '{}': {}",
                document.id, err
            ))
        })?;
        write_atomic(&path, &bytes, LOCAL_PIPE_FILE_MODE).map_err(CliError::Io)?;
        Ok(path)
    }

    pub fn resolve(&self, selector: &str) -> Result<LocalPipeDocument, CliError> {
        let matches = self
            .list()?
            .into_iter()
            .filter(|document| document.id == selector || document.name == selector)
            .collect::<Vec<_>>();

        match matches.len() {
            0 => Err(CliError::ConfigValidation(format!(
                "Local pipe '{}' was not found under {}. Recreate it with `stacker pipe create <source> <target>` if it only exists in the legacy server-backed local pipe list.",
                selector,
                self.pipes_dir().display()
            ))),
            1 => Ok(matches.into_iter().next().expect("single match")),
            _ => Err(CliError::ConfigValidation(format!(
                "Local pipe selector '{}' is ambiguous; use the local pipe ID",
                selector
            ))),
        }
    }
}

pub fn local_pipe_id_from_name(name: &str) -> Result<String, CliError> {
    let mut id = String::with_capacity(name.len());
    let mut previous_was_separator = false;

    for ch in name.trim().chars() {
        if ch.is_ascii_alphanumeric() {
            id.push(ch.to_ascii_lowercase());
            previous_was_separator = false;
        } else if matches!(ch, '-' | '_' | ' ' | '.' | '/' | ':') && !previous_was_separator {
            id.push('-');
            previous_was_separator = true;
        }
    }

    let normalized = id.trim_matches('-').to_string();
    validate_local_pipe_id(&normalized)?;
    Ok(normalized)
}

fn validate_local_pipe_id(id: &str) -> Result<(), CliError> {
    if id.is_empty() {
        return Err(CliError::ConfigValidation(
            "Local pipe ID cannot be empty".to_string(),
        ));
    }
    if !id
        .chars()
        .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '-' | '_'))
    {
        return Err(CliError::ConfigValidation(format!(
            "Local pipe ID '{}' must use lowercase ASCII letters, digits, '-' or '_'",
            id
        )));
    }
    Ok(())
}

fn validate_adapter_config(value: Option<&serde_json::Value>, path: &str) -> Result<(), CliError> {
    if let Some(value) = value {
        reject_plaintext_secret_values(value, path)?;
    }
    Ok(())
}

fn reject_plaintext_secret_values(value: &serde_json::Value, path: &str) -> Result<(), CliError> {
    match value {
        serde_json::Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                reject_plaintext_secret_values(item, &format!("{path}[{index}]"))?;
            }
        }
        serde_json::Value::Object(map) => {
            for (key, nested) in map {
                let nested_path = format!("{path}.{key}");
                if is_sensitive_adapter_key(key) && !is_secret_reference(nested) {
                    return Err(CliError::ConfigValidation(format!(
                        "Sensitive adapter config '{nested_path}' must use a secret reference instead of a plaintext value"
                    )));
                }
                reject_plaintext_secret_values(nested, &nested_path)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn is_secret_reference(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Object(map) => {
            map.contains_key("secret_ref")
                || map.contains_key("$env")
                || map.contains_key("env")
                || (map.contains_key("scope")
                    && map.contains_key("name")
                    && (map.contains_key("service") || map.contains_key("app")))
        }
        _ => false,
    }
}

fn is_sensitive_adapter_key(key: &str) -> bool {
    let lowered = key.trim().to_ascii_lowercase();
    lowered.contains("password")
        || lowered.contains("secret")
        || lowered.contains("token")
        || lowered.contains("credential")
        || lowered == "auth"
        || lowered.ends_with("_auth")
        || lowered.contains("api_key")
        || lowered.ends_with("_key")
        || lowered.contains("private_key")
        || lowered.ends_with("cert")
}

#[cfg(test)]
mod tests {
    use super::*;
    use pipe_adapter_sdk::PipeAdapterRole;
    use tempfile::TempDir;

    fn sample_document() -> LocalPipeDocument {
        LocalPipeDocument::draft(NewLocalPipeDocument {
            name: "status-panel-web-to-smtp".to_string(),
            source: LocalPipeBinding {
                selector: "status-panel-web".to_string(),
                container: Some("status-panel-web".to_string()),
                adapter: None,
                method: "POST".to_string(),
                path: "/contact".to_string(),
                fields: vec!["email".to_string(), "message".to_string()],
            },
            target: LocalPipeBinding {
                selector: "smtp".to_string(),
                container: Some("smtp".to_string()),
                adapter: Some(
                    PipeAdapterReference::new("smtp")
                        .with_role(PipeAdapterRole::Target)
                        .with_config(serde_json::json!({
                            "host": "smtp",
                            "port": 1025,
                            "to": ["ops@example.com"],
                            "tls": false
                        })),
                ),
                method: "SEND".to_string(),
                path: "adapter:smtp".to_string(),
                fields: vec!["from_email".to_string(), "body_text".to_string()],
            },
            template: LocalPipeTemplate {
                description: Some("POST /contact -> SEND adapter:smtp".to_string()),
                source_app_type: "status-panel-web".to_string(),
                source_endpoint: serde_json::json!({"path": "/contact", "method": "POST"}),
                target_app_type: "smtp".to_string(),
                target_endpoint: serde_json::json!({
                    "mode": "adapter",
                    "adapter": "smtp",
                    "display_name": "SMTP target"
                }),
                target_external_url: None,
                field_mapping: serde_json::json!({"body_text": "$.message"}),
                config: Some(serde_json::json!({"retry_count": 3})),
                is_public: false,
            },
            instance: LocalPipeInstance {
                source_adapter: None,
                source_container: "status-panel-web".to_string(),
                target_adapter: Some(
                    PipeAdapterReference::new("smtp")
                        .with_role(PipeAdapterRole::Target)
                        .with_config(serde_json::json!({
                            "host": "smtp",
                            "port": 1025,
                            "to": ["ops@example.com"],
                            "tls": false
                        })),
                ),
                target_container: Some("smtp".to_string()),
                target_url: None,
                field_mapping_override: None,
                config_override: None,
                trigger_count: 0,
                error_count: 0,
                last_triggered_at: None,
            },
            diagnostics: LocalPipeDiagnostics {
                notes: vec!["local discovery cached".to_string()],
            },
        })
        .expect("sample local pipe should be valid")
    }

    #[test]
    fn local_pipe_id_is_slugified() {
        assert_eq!(
            local_pipe_id_from_name("Status Panel Web: SMTP / Prod").unwrap(),
            "status-panel-web-smtp-prod"
        );
    }

    #[test]
    fn store_round_trips_local_pipe_document() {
        let dir = TempDir::new().unwrap();
        let store = LocalPipeStore::new(dir.path());
        let document = sample_document();

        let path = store.save_new(&document).unwrap();
        assert!(path.ends_with("status-panel-web-to-smtp.json"));

        let stored = store.resolve("status-panel-web-to-smtp").unwrap();
        assert_eq!(stored.id, document.id);
        assert_eq!(stored.name, document.name);
        assert_eq!(stored.instance.target_container, Some("smtp".to_string()));
    }

    #[test]
    fn duplicate_name_is_rejected() {
        let dir = TempDir::new().unwrap();
        let store = LocalPipeStore::new(dir.path());
        let first = sample_document();
        let second = sample_document();

        store.save_new(&first).unwrap();
        let err = store.save_new(&second).unwrap_err();
        assert!(err.to_string().contains("already exists"));
    }

    #[test]
    fn plaintext_secret_values_are_rejected() {
        let result = LocalPipeDocument::draft(NewLocalPipeDocument {
            instance: LocalPipeInstance {
                target_adapter: Some(
                    PipeAdapterReference::new("smtp")
                        .with_role(PipeAdapterRole::Target)
                        .with_config(serde_json::json!({
                            "host": "smtp",
                            "password": "super-secret"
                        })),
                ),
                ..sample_document().instance
            },
            ..NewLocalPipeDocument {
                name: sample_document().name,
                source: sample_document().source,
                target: sample_document().target,
                template: sample_document().template,
                instance: sample_document().instance,
                diagnostics: sample_document().diagnostics,
            }
        });

        let err = result.unwrap_err();
        assert!(err
            .to_string()
            .contains("must use a secret reference instead of a plaintext value"));
    }

    #[test]
    fn secret_reference_values_are_allowed() {
        let mut document = sample_document();
        document.instance.target_adapter = Some(
            PipeAdapterReference::new("smtp")
                .with_role(PipeAdapterRole::Target)
                .with_config(serde_json::json!({
                    "host": "smtp",
                    "password": {
                        "secret_ref": {
                            "scope": "service",
                            "service": "smtp",
                            "name": "SMTP_PASSWORD"
                        }
                    }
                })),
        );

        assert!(document.validate().is_ok());
    }
}
