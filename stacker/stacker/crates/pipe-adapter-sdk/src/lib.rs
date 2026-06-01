use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum PipeAdapterRole {
    Source,
    Target,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum PipeAdapterKind {
    HttpEndpoint,
    HtmlForm,
    WebhookBridge,
    SmtpTarget,
    Pop3Source,
    ImapSource,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PipeAdapterReference {
    pub code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<PipeAdapterRole>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<serde_json::Value>,
}

impl PipeAdapterReference {
    pub fn new(code: impl Into<String>) -> Self {
        Self {
            code: normalize_adapter_code(&code.into()),
            role: None,
            config: None,
        }
    }

    pub fn with_role(mut self, role: PipeAdapterRole) -> Self {
        self.role = Some(role);
        self
    }

    pub fn with_config(mut self, config: serde_json::Value) -> Self {
        self.config = Some(config);
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PipeAdapterMetadata {
    pub code: String,
    pub display_name: String,
    pub description: String,
    pub kind: PipeAdapterKind,
    pub roles: Vec<PipeAdapterRole>,
}

impl PipeAdapterMetadata {
    pub fn supports_role(&self, role: PipeAdapterRole) -> bool {
        self.roles.contains(&role)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct NormalizedMailAddress {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub email: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct NormalizedMailBody {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub html: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct NormalizedMailAttachment {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct NormalizedMailMessage {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mailbox: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sent_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub received_at: Option<String>,
    #[serde(default)]
    pub from: Vec<NormalizedMailAddress>,
    #[serde(default)]
    pub to: Vec<NormalizedMailAddress>,
    #[serde(default)]
    pub cc: Vec<NormalizedMailAddress>,
    #[serde(default)]
    pub bcc: Vec<NormalizedMailAddress>,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub body: NormalizedMailBody,
    #[serde(default)]
    pub attachments: Vec<NormalizedMailAttachment>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum PipeAdapterPayload {
    Json(serde_json::Value),
    MailMessage(Box<NormalizedMailMessage>),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PipeAdapterDispatch {
    pub adapter: PipeAdapterReference,
    pub payload: PipeAdapterPayload,
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum PipeAdapterError {
    #[error("{0}")]
    Message(String),
}

#[async_trait]
pub trait PipeSourceAdapter: Send + Sync {
    fn metadata(&self) -> &PipeAdapterMetadata;

    async fn poll(&self) -> Result<Vec<PipeAdapterDispatch>, PipeAdapterError>;
}

#[async_trait]
pub trait PipeTargetAdapter: Send + Sync {
    fn metadata(&self) -> &PipeAdapterMetadata;

    async fn deliver(
        &self,
        payload: PipeAdapterPayload,
    ) -> Result<serde_json::Value, PipeAdapterError>;
}

pub trait PipeAdapterCatalog: Send + Sync {
    fn adapters(&self) -> Vec<PipeAdapterMetadata>;
    fn find(&self, code: &str) -> Option<PipeAdapterMetadata>;
}

#[derive(Debug, Clone, Default)]
pub struct InMemoryPipeAdapterRegistry {
    adapters: BTreeMap<String, PipeAdapterMetadata>,
}

impl InMemoryPipeAdapterRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, metadata: PipeAdapterMetadata) {
        self.adapters
            .insert(normalize_adapter_code(&metadata.code), metadata);
    }
}

impl PipeAdapterCatalog for InMemoryPipeAdapterRegistry {
    fn adapters(&self) -> Vec<PipeAdapterMetadata> {
        self.adapters.values().cloned().collect()
    }

    fn find(&self, code: &str) -> Option<PipeAdapterMetadata> {
        self.adapters.get(&normalize_adapter_code(code)).cloned()
    }
}

pub fn normalize_adapter_code(code: &str) -> String {
    code.trim().to_ascii_lowercase()
}

pub fn builtin_registry() -> InMemoryPipeAdapterRegistry {
    let mut registry = InMemoryPipeAdapterRegistry::new();
    for metadata in [
        PipeAdapterMetadata {
            code: "webhook".to_string(),
            display_name: "Webhook bridge".to_string(),
            description: "Generic HTTP webhook target adapter".to_string(),
            kind: PipeAdapterKind::WebhookBridge,
            roles: vec![PipeAdapterRole::Target],
        },
        PipeAdapterMetadata {
            code: "smtp".to_string(),
            display_name: "SMTP target".to_string(),
            description: "Outbound SMTP delivery target adapter".to_string(),
            kind: PipeAdapterKind::SmtpTarget,
            roles: vec![PipeAdapterRole::Target],
        },
        PipeAdapterMetadata {
            code: "pop3".to_string(),
            display_name: "POP3 source".to_string(),
            description: "Inbound POP3 mailbox polling source adapter".to_string(),
            kind: PipeAdapterKind::Pop3Source,
            roles: vec![PipeAdapterRole::Source],
        },
        PipeAdapterMetadata {
            code: "imap".to_string(),
            display_name: "IMAP source".to_string(),
            description: "Inbound IMAP mailbox polling source adapter".to_string(),
            kind: PipeAdapterKind::ImapSource,
            roles: vec![PipeAdapterRole::Source],
        },
        PipeAdapterMetadata {
            code: "mailhog".to_string(),
            display_name: "MailHog SMTP target".to_string(),
            description: "SMTP-compatible target alias for MailHog-style services".to_string(),
            kind: PipeAdapterKind::SmtpTarget,
            roles: vec![PipeAdapterRole::Target],
        },
    ] {
        registry.register(metadata);
    }
    registry
}

pub fn builtin_adapter_kind(code: &str) -> Option<PipeAdapterKind> {
    builtin_registry().find(code).map(|metadata| metadata.kind)
}

pub fn selector_matches_builtin_kind(selector: &str, kind: PipeAdapterKind) -> bool {
    let canonical = normalize_adapter_code(selector);
    if builtin_adapter_kind(&canonical) == Some(kind) {
        return true;
    }

    selector
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter(|token| !token.is_empty())
        .map(normalize_adapter_code)
        .any(|token| builtin_adapter_kind(&token) == Some(kind))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_registry_exposes_first_party_adapters() {
        let registry = builtin_registry();

        assert_eq!(
            registry.find("smtp").map(|metadata| metadata.kind),
            Some(PipeAdapterKind::SmtpTarget)
        );
        assert_eq!(
            registry.find("imap").map(|metadata| metadata.kind),
            Some(PipeAdapterKind::ImapSource)
        );
    }

    #[test]
    fn selector_matching_detects_mail_aliases() {
        assert!(selector_matches_builtin_kind(
            "smtp",
            PipeAdapterKind::SmtpTarget
        ));
        assert!(selector_matches_builtin_kind(
            "mailhog",
            PipeAdapterKind::SmtpTarget
        ));
        assert!(selector_matches_builtin_kind(
            "status-mailhog-1",
            PipeAdapterKind::SmtpTarget
        ));
        assert!(!selector_matches_builtin_kind(
            "status-panel-web",
            PipeAdapterKind::SmtpTarget
        ));
    }

    #[test]
    fn adapter_reference_normalizes_codes() {
        let reference = PipeAdapterReference::new("  SMTP  ");

        assert_eq!(reference.code, "smtp");
    }
}
