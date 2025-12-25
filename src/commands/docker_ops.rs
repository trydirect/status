use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

/// Allowed Docker operations that can be executed via command API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DockerOperation {
    /// Restart a container: docker:restart:nginx
    Restart(String),
    /// Stop a container: docker:stop:redis
    Stop(String),
    /// View container logs: docker:logs:nginx:50 (tail 50 lines, default 100)
    Logs(String, Option<u32>),
    /// Inspect container: docker:inspect:nginx
    Inspect(String),
    /// Pause a container: docker:pause:nginx
    Pause(String),
}

impl DockerOperation {
    /// Parse command string in format "docker:operation:args"
    /// Examples:
    /// - "docker:restart:nginx"
    /// - "docker:stop:redis"
    /// - "docker:logs:nginx:50"
    /// - "docker:inspect:nginx"
    pub fn parse(cmd: &str) -> Result<Self> {
        let parts: Vec<&str> = cmd.split(':').collect();

        match (parts.first(), parts.get(1), parts.get(2)) {
            (Some(&"docker"), Some(&"restart"), Some(&name)) => {
                validate_container_name(name)?;
                Ok(DockerOperation::Restart(name.to_string()))
            }
            (Some(&"docker"), Some(&"stop"), Some(&name)) => {
                validate_container_name(name)?;
                Ok(DockerOperation::Stop(name.to_string()))
            }
            (Some(&"docker"), Some(&"logs"), Some(&name)) => {
                validate_container_name(name)?;
                let tail = parts.get(3).and_then(|s| s.parse::<u32>().ok());
                Ok(DockerOperation::Logs(name.to_string(), tail))
            }
            (Some(&"docker"), Some(&"inspect"), Some(&name)) => {
                validate_container_name(name)?;
                Ok(DockerOperation::Inspect(name.to_string()))
            }
            (Some(&"docker"), Some(&"pause"), Some(&name)) => {
                validate_container_name(name)?;
                Ok(DockerOperation::Pause(name.to_string()))
            }
            _ => bail!("Invalid docker operation. Use format: docker:operation:container_name"),
        }
    }

    /// Get container name for this operation
    pub fn container_name(&self) -> &str {
        match self {
            DockerOperation::Restart(name) => name,
            DockerOperation::Stop(name) => name,
            DockerOperation::Logs(name, _) => name,
            DockerOperation::Inspect(name) => name,
            DockerOperation::Pause(name) => name,
        }
    }

    /// Get operation type as string
    pub fn operation_type(&self) -> &str {
        match self {
            DockerOperation::Restart(_) => "restart",
            DockerOperation::Stop(_) => "stop",
            DockerOperation::Logs(_, _) => "logs",
            DockerOperation::Inspect(_) => "inspect",
            DockerOperation::Pause(_) => "pause",
        }
    }
}

/// Validate container name: alphanumeric, dash, underscore, max 63 chars
fn validate_container_name(name: &str) -> Result<()> {
    if name.is_empty() {
        bail!("Container name cannot be empty");
    }

    if name.len() > 63 {
        bail!("Container name too long (max 63 chars)");
    }

    // Docker allows alphanumeric, dash, underscore
    if !name
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        bail!("Container name contains invalid characters (only alphanumeric, dash, underscore allowed)");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_restart() {
        let op = DockerOperation::parse("docker:restart:nginx").unwrap();
        match op {
            DockerOperation::Restart(name) => assert_eq!(name, "nginx"),
            _ => panic!("Expected Restart"),
        }
    }

    #[test]
    fn test_parse_stop() {
        let op = DockerOperation::parse("docker:stop:redis").unwrap();
        match op {
            DockerOperation::Stop(name) => assert_eq!(name, "redis"),
            _ => panic!("Expected Stop"),
        }
    }

    #[test]
    fn test_parse_logs_with_tail() {
        let op = DockerOperation::parse("docker:logs:nginx:50").unwrap();
        match op {
            DockerOperation::Logs(name, tail) => {
                assert_eq!(name, "nginx");
                assert_eq!(tail, Some(50));
            }
            _ => panic!("Expected Logs"),
        }
    }

    #[test]
    fn test_parse_logs_without_tail() {
        let op = DockerOperation::parse("docker:logs:nginx").unwrap();
        match op {
            DockerOperation::Logs(name, tail) => {
                assert_eq!(name, "nginx");
                assert_eq!(tail, None);
            }
            _ => panic!("Expected Logs"),
        }
    }

    #[test]
    fn test_parse_invalid_format() {
        let result = DockerOperation::parse("docker:restart");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_invalid_characters() {
        let result = DockerOperation::parse("docker:restart:nginx; rm -rf /");
        assert!(result.is_err());
    }

    #[test]
    fn test_container_name_too_long() {
        let long_name = "a".repeat(64);
        let result = DockerOperation::parse(&format!("docker:restart:{}", long_name));
        assert!(result.is_err());
    }
}
