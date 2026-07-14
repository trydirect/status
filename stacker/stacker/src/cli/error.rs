use std::fmt;
use std::path::PathBuf;

use crate::cli::config_parser::DeployTarget;
use crate::services::TypedErrorEnvelope;

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// CliError — unified error hierarchy for all CLI operations
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug)]
pub enum CliError {
    // Config errors
    ConfigNotFound {
        path: PathBuf,
    },
    ConfigParseFailed {
        source: serde_yaml::Error,
    },
    ConfigValidation(String),
    EnvVarNotFound {
        var_name: String,
    },

    // Detection errors
    DetectionFailed {
        path: PathBuf,
        reason: String,
    },

    // Generator errors
    GeneratorError(String),
    DockerfileExists {
        path: PathBuf,
    },

    // Deployment errors
    DeployFailed {
        target: DeployTarget,
        reason: String,
    },
    LoginRequired {
        feature: String,
    },
    CloudProviderMissing,
    ServerHostMissing,

    // Runtime errors
    ContainerRuntimeUnavailable,
    CommandFailed {
        command: String,
        exit_code: i32,
    },

    // Auth errors
    AuthFailed(String),
    TokenExpired,

    // AI errors
    AiNotConfigured,
    AiProviderError {
        provider: String,
        message: String,
    },

    // Proxy errors
    ProxyConfigFailed(String),

    // Feature-scoped command errors
    FeatureFailed {
        feature: String,
        reason: String,
    },

    // Secrets/env errors
    EnvFileNotFound {
        path: std::path::PathBuf,
    },
    SecretKeyNotFound {
        key: String,
    },

    // Marketplace errors
    MarketplaceFailed(String),

    // Agent errors
    AgentNotFound {
        deployment_hash: String,
    },
    AgentOffline {
        deployment_hash: String,
    },
    AgentCommandTimeout {
        command_id: String,
        /// Human-readable label for the command (e.g. "Fetching containers")
        command_type: String,
        /// Last observed status from polling ("pending" = never picked up, "running" = started but didn't finish)
        last_status: String,
        deployment_hash: String,
    },
    AgentCommandFailed {
        command_id: String,
        error: String,
    },

    // IO errors
    Io(std::io::Error),
    Typed(TypedErrorEnvelope),
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConfigNotFound { path } => {
                write!(f, "Configuration file not found: {}", path.display())
            }
            Self::ConfigParseFailed { source } => {
                write!(f, "Failed to parse stacker.yml: {source}")
            }
            Self::ConfigValidation(msg) => {
                write!(f, "Configuration validation error: {msg}")
            }
            Self::EnvVarNotFound { var_name } => {
                write!(f, "Environment variable not found: ${var_name}")
            }
            Self::DetectionFailed { path, reason } => {
                write!(
                    f,
                    "Project detection failed in {}: {reason}",
                    path.display()
                )
            }
            Self::GeneratorError(msg) => {
                write!(f, "Generator error: {msg}")
            }
            Self::DockerfileExists { path } => {
                write!(
                    f,
                    "Dockerfile already exists: {}. Use --force to overwrite.",
                    path.display()
                )
            }
            Self::DeployFailed { target, reason } => {
                write!(f, "Deployment to {target} failed: {reason}")
            }
            Self::LoginRequired { feature } => {
                write!(f, "Login required for {feature}. Run: stacker login")
            }
            Self::CloudProviderMissing => {
                write!(f, "Cloud provider is required for cloud deployment. Set deploy.cloud.provider in stacker.yml")
            }
            Self::ServerHostMissing => {
                write!(f, "Server host is required for server deployment. Set deploy.server.host in stacker.yml")
            }
            Self::ContainerRuntimeUnavailable => {
                write!(
                    f,
                    "Docker is not running. Install Docker or start the Docker daemon."
                )
            }
            Self::CommandFailed { command, exit_code } => {
                write!(f, "Command '{command}' failed with exit code {exit_code}")
            }
            Self::AuthFailed(msg) => {
                write!(f, "Authentication failed: {msg}")
            }
            Self::TokenExpired => {
                write!(f, "Authentication token expired. Run: stacker login")
            }
            Self::AiNotConfigured => {
                write!(
                    f,
                    "AI is not configured in stacker.yml.\n\
                     Quick fix: run `stacker init --with-ai` (in your project root),\n\
                     or add this section:\n\
                     ai:\n\
                       enabled: true\n\
                       provider: ollama   # openai | anthropic | ollama | custom\n\
                       timeout: 300\n\
                       tasks: [\"dockerfile\", \"compose\"]"
                )
            }
            Self::AiProviderError { provider, message } => {
                write!(f, "AI provider '{provider}' error: {message}")
            }
            Self::ProxyConfigFailed(msg) => {
                write!(f, "Proxy configuration failed: {msg}")
            }
            Self::FeatureFailed { feature, reason } => {
                write!(f, "{feature} failed: {reason}")
            }
            Self::EnvFileNotFound { path } => {
                write!(f, "Env file not found: {}", path.display())
            }
            Self::SecretKeyNotFound { key } => {
                write!(f, "Secret key not found: {key}")
            }
            Self::MarketplaceFailed(msg) => {
                write!(f, "Marketplace error: {msg}")
            }
            Self::AgentNotFound { deployment_hash } => {
                write!(
                    f,
                    "No Status Panel agent registered for deployment '{deployment_hash}'.\n\
                     Ensure the agent is installed and has registered with Stacker."
                )
            }
            Self::AgentOffline { deployment_hash } => {
                write!(
                    f,
                    "Status Panel agent for deployment '{deployment_hash}' appears offline.\n\
                     Check that the server is running and the agent process is active."
                )
            }
            Self::AgentCommandTimeout {
                command_id,
                command_type,
                last_status,
                deployment_hash,
            } => {
                let (diagnosis, suggestions) = if last_status == "pending" {
                    (
                        "The agent never picked up this command — it may be offline or unreachable.",
                        format!(
                            "  Check if the agent is alive:\n\
                                 stacker agent health --deployment={deployment_hash}\n\n\
                             \x20 Check the agent's last known state:\n\
                             \x20   stacker agent status --deployment={deployment_hash}"
                        ),
                    )
                } else {
                    (
                        "The agent started the command but did not finish in time — it may be busy or slow.",
                        format!(
                            "  Retry the command (it may succeed now):\n\
                             \x20   stacker agent status --deployment={deployment_hash}\n\n\
                             \x20 Or wait and check the result:\n\
                             \x20   stacker agent history --deployment={deployment_hash}"
                        ),
                    )
                };
                write!(
                    f,
                    "{command_type} timed out (last status: {last_status}, id: {command_id})\n\n\
                     {diagnosis}\n\n\
                     {suggestions}"
                )
            }
            Self::AgentCommandFailed { command_id, error } => {
                write!(f, "Agent command '{command_id}' failed: {error}")
            }
            Self::Io(err) => {
                write!(f, "I/O error: {err}")
            }
            Self::Typed(envelope) => {
                write!(f, "{}", envelope.to_json())
            }
        }
    }
}

impl std::error::Error for CliError {}

impl From<std::io::Error> for CliError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<serde_yaml::Error> for CliError {
    fn from(err: serde_yaml::Error) -> Self {
        Self::ConfigParseFailed { source: err }
    }
}

impl From<TypedErrorEnvelope> for CliError {
    fn from(envelope: TypedErrorEnvelope) -> Self {
        Self::Typed(envelope)
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// ValidationIssue — structured validation results
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationIssue {
    pub severity: Severity,
    pub code: String,
    pub message: String,
    pub field: Option<String>,
}

impl fmt::Display for ValidationIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.field {
            Some(field) => write!(
                f,
                "[{}] {}: {} ({})",
                self.severity, self.code, self.message, field
            ),
            None => write!(f, "[{}] {}: {}", self.severity, self.code, self.message),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Error,
    Warning,
    Info,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Error => write!(f, "error"),
            Self::Warning => write!(f, "warning"),
            Self::Info => write!(f, "info"),
        }
    }
}

impl Default for Severity {
    fn default() -> Self {
        Self::Info
    }
}

use serde::{Deserialize, Serialize};

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Tests — Phase 0
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_cli_error_display_config_not_found() {
        let err = CliError::ConfigNotFound {
            path: PathBuf::from("/tmp/stacker.yml"),
        };
        let msg = format!("{err}");
        assert!(
            msg.contains("Configuration file not found"),
            "Expected 'Configuration file not found' in: {msg}"
        );
        assert!(msg.contains("/tmp/stacker.yml"), "Expected path in: {msg}");
    }

    #[test]
    fn test_cli_error_display_env_var_not_found() {
        let err = CliError::EnvVarNotFound {
            var_name: "DB_PASSWORD".to_string(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("DB_PASSWORD"), "Expected var name in: {msg}");
    }

    #[test]
    fn test_cli_error_display_login_required() {
        let err = CliError::LoginRequired {
            feature: "cloud deploy".to_string(),
        };
        let msg = format!("{err}");
        assert!(
            msg.contains("cloud deploy"),
            "Expected feature name in: {msg}"
        );
        assert!(
            msg.contains("stacker login"),
            "Expected command hint in: {msg}"
        );
    }

    #[test]
    fn test_cli_error_display_container_runtime_unavailable() {
        let err = CliError::ContainerRuntimeUnavailable;
        let msg = format!("{err}");
        assert!(
            msg.contains("Docker is not running"),
            "Expected docker message in: {msg}"
        );
    }

    #[test]
    fn test_cli_error_display_generator_error() {
        let err = CliError::GeneratorError("base_image is required".to_string());
        let msg = format!("{err}");
        assert!(
            msg.contains("base_image is required"),
            "Expected reason in: {msg}"
        );
    }

    #[test]
    fn test_cli_error_from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file missing");
        let cli_err = CliError::from(io_err);
        assert!(
            matches!(cli_err, CliError::Io(_)),
            "Expected CliError::Io variant"
        );
    }

    #[test]
    fn test_cli_error_from_yaml_error() {
        let yaml_result: Result<String, serde_yaml::Error> =
            serde_yaml::from_str("{{invalid: yaml:");
        let yaml_err = yaml_result.unwrap_err();
        let cli_err = CliError::from(yaml_err);
        assert!(
            matches!(cli_err, CliError::ConfigParseFailed { .. }),
            "Expected CliError::ConfigParseFailed variant"
        );
    }

    #[test]
    fn test_severity_display() {
        assert_eq!(format!("{}", Severity::Error), "error");
        assert_eq!(format!("{}", Severity::Warning), "warning");
        assert_eq!(format!("{}", Severity::Info), "info");
    }

    #[test]
    fn test_severity_default_is_info() {
        assert_eq!(Severity::default(), Severity::Info);
    }

    #[test]
    fn test_severity_serde_roundtrip() {
        let json = serde_json::to_string(&Severity::Warning).unwrap();
        assert_eq!(json, "\"warning\"");
        let parsed: Severity = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, Severity::Warning);
    }

    #[test]
    fn test_validation_issue_display_with_field() {
        let issue = ValidationIssue {
            severity: Severity::Error,
            code: "E001".to_string(),
            message: "port conflict".to_string(),
            field: Some("services[0].ports".to_string()),
        };
        let msg = format!("{issue}");
        assert!(msg.contains("[error]"), "Expected severity in: {msg}");
        assert!(msg.contains("E001"), "Expected code in: {msg}");
        assert!(msg.contains("port conflict"), "Expected message in: {msg}");
        assert!(
            msg.contains("services[0].ports"),
            "Expected field in: {msg}"
        );
    }

    #[test]
    fn test_validation_issue_display_without_field() {
        let issue = ValidationIssue {
            severity: Severity::Warning,
            code: "W001".to_string(),
            message: "no healthcheck".to_string(),
            field: None,
        };
        let msg = format!("{issue}");
        assert!(msg.contains("[warning]"), "Expected severity in: {msg}");
        assert!(!msg.contains("("), "Expected no field parens in: {msg}");
    }

    #[test]
    fn test_validation_issue_serialize() {
        let issue = ValidationIssue {
            severity: Severity::Error,
            code: "E001".to_string(),
            message: "missing field".to_string(),
            field: Some("name".to_string()),
        };
        let json = serde_json::to_value(&issue).unwrap();
        assert_eq!(json["severity"], "error");
        assert_eq!(json["code"], "E001");
        assert_eq!(json["message"], "missing field");
        assert_eq!(json["field"], "name");
    }
}
