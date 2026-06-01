use chrono::{DateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::OnceLock;
use uuid::Uuid;

/// Regex for valid Unix directory names (cached on first use)
fn valid_dir_name_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        // Must start with alphanumeric or underscore
        // Can contain alphanumeric, underscore, hyphen, dot
        // Length 1-255 characters
        Regex::new(r"^[a-zA-Z0-9_][a-zA-Z0-9_\-.]{0,254}$").unwrap()
    })
}

/// Error type for project name validation
#[derive(Debug, Clone, PartialEq)]
pub enum ProjectNameError {
    Empty,
    TooLong(usize),
    InvalidCharacters(String),
    ReservedName(String),
}

impl std::fmt::Display for ProjectNameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProjectNameError::Empty => write!(f, "Project name cannot be empty"),
            ProjectNameError::TooLong(len) => {
                write!(f, "Project name too long ({} chars, max 255)", len)
            }
            ProjectNameError::InvalidCharacters(name) => {
                write!(
                    f,
                    "Project name '{}' contains invalid characters. Use only alphanumeric, underscore, hyphen, or dot",
                    name
                )
            }
            ProjectNameError::ReservedName(name) => {
                write!(f, "Project name '{}' is reserved", name)
            }
        }
    }
}

impl std::error::Error for ProjectNameError {}

/// Reserved directory names that should not be used as project names
const RESERVED_NAMES: &[&str] = &[
    ".",
    "..",
    "root",
    "home",
    "etc",
    "var",
    "tmp",
    "usr",
    "bin",
    "sbin",
    "lib",
    "lib64",
    "opt",
    "proc",
    "sys",
    "dev",
    "boot",
    "mnt",
    "media",
    "srv",
    "run",
    "lost+found",
    "trydirect",
];

/// Validate a project name for use as a Unix directory name
pub fn validate_project_name(name: &str) -> Result<(), ProjectNameError> {
    // Check empty
    if name.is_empty() {
        return Err(ProjectNameError::Empty);
    }

    // Check length
    if name.len() > 255 {
        return Err(ProjectNameError::TooLong(name.len()));
    }

    // Check reserved names (case-insensitive)
    let lower = name.to_lowercase();
    if RESERVED_NAMES.contains(&lower.as_str()) {
        return Err(ProjectNameError::ReservedName(name.to_string()));
    }

    // Check valid characters
    if !valid_dir_name_regex().is_match(name) {
        return Err(ProjectNameError::InvalidCharacters(name.to_string()));
    }

    Ok(())
}

/// Sanitize a project name to be a valid Unix directory name
/// Replaces invalid characters and ensures the result is valid
pub fn sanitize_project_name(name: &str) -> String {
    if name.is_empty() {
        return "project".to_string();
    }

    // Convert to lowercase and replace invalid chars with underscore
    let sanitized: String = name
        .to_lowercase()
        .chars()
        .enumerate()
        .map(|(i, c)| {
            if i == 0 {
                // First char must be alphanumeric or underscore
                if c.is_ascii_alphanumeric() || c == '_' {
                    c
                } else {
                    '_'
                }
            } else {
                // Subsequent chars can also include hyphen and dot
                if c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.' {
                    c
                } else {
                    '_'
                }
            }
        })
        .collect();

    // Truncate if too long
    let truncated: String = sanitized.chars().take(255).collect();

    // Check if it's a reserved name
    if RESERVED_NAMES.contains(&truncated.as_str()) {
        return format!("project_{}", truncated);
    }

    if truncated.is_empty() {
        "project".to_string()
    } else {
        truncated
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Project {
    pub id: i32,         // id - is a unique identifier for the app project
    pub stack_id: Uuid,  // external project ID
    pub user_id: String, // external unique identifier for the user
    pub name: String,
    // pub metadata: sqlx::types::Json<String>,
    pub metadata: Value, //json type
    pub request_json: Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub source_template_id: Option<Uuid>, // marketplace template UUID
    pub template_version: Option<String>, // marketplace template version
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, sqlx::FromRow)]
pub struct SharedProjectSummary {
    pub id: i32,
    pub name: String,
    pub role: String,
    pub shared_at: DateTime<Utc>,
}

impl Project {
    pub fn new(user_id: String, name: String, metadata: Value, request_json: Value) -> Self {
        Self {
            id: 0,
            stack_id: Uuid::new_v4(),
            user_id,
            name,
            metadata,
            request_json,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            source_template_id: None,
            template_version: None,
        }
    }

    /// Validate the project name for use as a directory
    pub fn validate_name(&self) -> Result<(), ProjectNameError> {
        validate_project_name(&self.name)
    }

    /// Get the sanitized directory name for this project (lowercase, safe for Unix)
    pub fn safe_dir_name(&self) -> String {
        sanitize_project_name(&self.name)
    }

    /// Get the full deploy directory path for this project
    /// Uses the provided base_dir, or DEFAULT_DEPLOY_DIR env var, or defaults to /home/trydirect
    pub fn deploy_dir(&self, base_dir: Option<&str>) -> String {
        let default_base =
            std::env::var("DEFAULT_DEPLOY_DIR").unwrap_or_else(|_| "/home/trydirect".to_string());
        let base = base_dir.unwrap_or(&default_base);
        format!("{}/{}", base.trim_end_matches('/'), self.safe_dir_name())
    }

    /// Get the deploy directory using deployment_hash (for backwards compatibility)
    pub fn deploy_dir_with_hash(&self, base_dir: Option<&str>, deployment_hash: &str) -> String {
        let default_base =
            std::env::var("DEFAULT_DEPLOY_DIR").unwrap_or_else(|_| "/home/trydirect".to_string());
        let base = base_dir.unwrap_or(&default_base);
        format!("{}/{}", base.trim_end_matches('/'), deployment_hash)
    }
}

impl Default for Project {
    fn default() -> Self {
        Project {
            id: 0,
            stack_id: Default::default(),
            user_id: "".to_string(),
            name: "".to_string(),
            metadata: Default::default(),
            request_json: Default::default(),
            created_at: Default::default(),
            updated_at: Default::default(),
            source_template_id: None,
            template_version: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test validate_project_name
    #[test]
    fn test_validate_empty_name() {
        assert_eq!(validate_project_name(""), Err(ProjectNameError::Empty));
    }

    #[test]
    fn test_validate_too_long_name() {
        let long_name = "a".repeat(256);
        assert_eq!(
            validate_project_name(&long_name),
            Err(ProjectNameError::TooLong(256))
        );
    }

    #[test]
    fn test_validate_reserved_names() {
        for name in &["root", "tmp", "etc", "var", "dev", ".", ".."] {
            assert!(matches!(
                validate_project_name(name),
                Err(ProjectNameError::ReservedName(_))
            ));
        }
    }

    #[test]
    fn test_validate_reserved_names_case_insensitive() {
        assert!(matches!(
            validate_project_name("ROOT"),
            Err(ProjectNameError::ReservedName(_))
        ));
        assert!(matches!(
            validate_project_name("Tmp"),
            Err(ProjectNameError::ReservedName(_))
        ));
    }

    #[test]
    fn test_validate_invalid_characters() {
        assert!(matches!(
            validate_project_name("my project"),
            Err(ProjectNameError::InvalidCharacters(_))
        ));
        assert!(matches!(
            validate_project_name("name/path"),
            Err(ProjectNameError::InvalidCharacters(_))
        ));
        assert!(matches!(
            validate_project_name("-starts-with-dash"),
            Err(ProjectNameError::InvalidCharacters(_))
        ));
    }

    #[test]
    fn test_validate_valid_names() {
        assert!(validate_project_name("myproject").is_ok());
        assert!(validate_project_name("my-project").is_ok());
        assert!(validate_project_name("my_project").is_ok());
        assert!(validate_project_name("my.project").is_ok());
        assert!(validate_project_name("Project123").is_ok());
        assert!(validate_project_name("_private").is_ok());
    }

    #[test]
    fn test_validate_max_length_name() {
        let name = "a".repeat(255);
        assert!(validate_project_name(&name).is_ok());
    }

    // Test sanitize_project_name
    #[test]
    fn test_sanitize_empty() {
        assert_eq!(sanitize_project_name(""), "project");
    }

    #[test]
    fn test_sanitize_lowercases() {
        assert_eq!(sanitize_project_name("MyProject"), "myproject");
    }

    #[test]
    fn test_sanitize_replaces_invalid_chars() {
        assert_eq!(sanitize_project_name("my project"), "my_project");
        assert_eq!(sanitize_project_name("my/project"), "my_project");
    }

    #[test]
    fn test_sanitize_reserved_name() {
        assert_eq!(sanitize_project_name("root"), "project_root");
        assert_eq!(sanitize_project_name("tmp"), "project_tmp");
    }

    #[test]
    fn test_sanitize_first_char_special() {
        assert_eq!(sanitize_project_name("-myproject"), "_myproject");
        assert_eq!(sanitize_project_name(".myproject"), "_myproject");
    }

    #[test]
    fn test_sanitize_truncates_long_name() {
        let long_name = "a".repeat(300);
        let result = sanitize_project_name(&long_name);
        assert_eq!(result.len(), 255);
    }

    // Test ProjectNameError Display
    #[test]
    fn test_error_display() {
        assert_eq!(
            ProjectNameError::Empty.to_string(),
            "Project name cannot be empty"
        );
        assert_eq!(
            ProjectNameError::TooLong(300).to_string(),
            "Project name too long (300 chars, max 255)"
        );
        assert!(ProjectNameError::InvalidCharacters("bad name".to_string())
            .to_string()
            .contains("bad name"));
        assert!(ProjectNameError::ReservedName("root".to_string())
            .to_string()
            .contains("root"));
    }

    // Test Project methods
    #[test]
    fn test_project_new() {
        let project = Project::new(
            "user1".to_string(),
            "test-project".to_string(),
            serde_json::json!({}),
            serde_json::json!({}),
        );
        assert_eq!(project.id, 0);
        assert_eq!(project.user_id, "user1");
        assert_eq!(project.name, "test-project");
        assert!(project.source_template_id.is_none());
    }

    #[test]
    fn test_project_validate_name() {
        let project = Project::new(
            "u".to_string(),
            "valid-name".to_string(),
            Value::Null,
            Value::Null,
        );
        assert!(project.validate_name().is_ok());

        let bad_project = Project::new("u".to_string(), "".to_string(), Value::Null, Value::Null);
        assert!(bad_project.validate_name().is_err());
    }

    #[test]
    fn test_project_safe_dir_name() {
        let project = Project::new(
            "u".to_string(),
            "My Project".to_string(),
            Value::Null,
            Value::Null,
        );
        assert_eq!(project.safe_dir_name(), "my_project");
    }

    #[test]
    fn test_project_deploy_dir() {
        let project = Project::new(
            "u".to_string(),
            "myapp".to_string(),
            Value::Null,
            Value::Null,
        );
        assert_eq!(project.deploy_dir(Some("/deploy")), "/deploy/myapp");
        assert_eq!(project.deploy_dir(Some("/deploy/")), "/deploy/myapp");
    }

    #[test]
    fn test_project_deploy_dir_with_hash() {
        let project = Project::new(
            "u".to_string(),
            "myapp".to_string(),
            Value::Null,
            Value::Null,
        );
        assert_eq!(
            project.deploy_dir_with_hash(Some("/deploy"), "abc123"),
            "/deploy/abc123"
        );
    }

    #[test]
    fn test_project_default() {
        let project = Project::default();
        assert_eq!(project.id, 0);
        assert_eq!(project.user_id, "");
        assert_eq!(project.name, "");
    }
}
