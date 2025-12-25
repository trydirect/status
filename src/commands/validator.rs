use anyhow::{bail, Context, Result};
use std::collections::HashSet;
use std::path::Path;

use crate::transport::Command as AgentCommand;

/// Configuration for command validation rules
#[derive(Debug, Clone)]
pub struct ValidatorConfig {
    pub allowed_programs: HashSet<String>,
    pub allow_shell: bool,
    pub max_args: usize,
    pub max_arg_len: usize,
    pub allowed_path_prefixes: Vec<String>,
}

impl Default for ValidatorConfig {
    fn default() -> Self {
        let mut allowed_programs = HashSet::new();
        // Minimal safe defaults; expand as needed
        for p in [
            "echo", "sleep", "ls", "tar", "gzip", "uname", "date", "df", "du",
        ]
        .iter()
        {
            allowed_programs.insert(p.to_string());
        }

        Self {
            allowed_programs,
            allow_shell: false,
            max_args: 16,
            max_arg_len: 4096,
            allowed_path_prefixes: vec!["/tmp".to_string(), "/var/tmp".to_string()],
        }
    }
}

/// Validates commands for safety prior to execution
#[derive(Debug, Clone)]
pub struct CommandValidator {
    config: ValidatorConfig,
}

impl CommandValidator {
    pub fn new(config: ValidatorConfig) -> Self {
        Self { config }
    }

    pub fn default_secure() -> Self {
        Self {
            config: ValidatorConfig::default(),
        }
    }

    /// Validate a command; returns Ok if safe else Err explaining the issue
    pub fn validate(&self, command: &AgentCommand) -> Result<()> {
        // Check for Docker operation first (special case: docker:operation:name)
        if command.name.starts_with("docker:") {
            return self.validate_docker_command(&command.name);
        }

        let (program, args) = self.parse_command(&command.name)?;

        // Basic program checks
        if program.is_empty() {
            bail!("empty command");
        }

        // Disallow environment assignment hijacks like FOO=bar cmd
        if program.contains('=') {
            bail!("environment assignment in program not allowed");
        }

        // Shell usage restricted unless explicitly allowed
        if ["sh", "bash", "zsh"].contains(&program.as_str()) && !self.config.allow_shell {
            bail!("shell execution is disabled by policy");
        }

        // Enforce whitelist for non-shell programs
        if !["sh", "bash", "zsh"].contains(&program.as_str()) {
            if !self.config.allowed_programs.contains(&program) {
                bail!(format!("program '{}' is not allowed", program));
            }
        }

        // Argument constraints
        if args.len() > self.config.max_args {
            bail!(format!(
                "too many arguments: {} > {}",
                args.len(),
                self.config.max_args
            ));
        }

        // Disallowed metacharacters commonly used for command injection
        const DISALLOWED_CHARS: &[char] = &[';', '|', '&', '`', '$', '>', '<'];

        for arg in &args {
            if arg.len() > self.config.max_arg_len {
                bail!("argument too long");
            }

            if arg.chars().any(|c| DISALLOWED_CHARS.contains(&c)) {
                bail!(format!("unsafe characters in argument: {}", arg));
            }

            // Simple path validation
            if arg.contains('/') {
                // Prevent traversal
                if arg.contains("../") || arg.starts_with("../") || arg.contains("/..") {
                    bail!("path traversal detected in argument");
                }

                // Disallow absolute paths outside allowed prefixes
                if arg.starts_with('/') {
                    let allowed = self
                        .config
                        .allowed_path_prefixes
                        .iter()
                        .any(|prefix| arg.starts_with(prefix));
                    if !allowed {
                        bail!(format!("absolute path not permitted: {}", arg));
                    }
                }
            }

            // Conservative character policy: allow common filename chars
            if !self.is_safe_string(arg) {
                bail!(format!("argument contains unsafe characters: {}", arg));
            }
        }

        Ok(())
    }

    fn parse_command(&self, cmd: &str) -> Result<(String, Vec<String>)> {
        let parts: Vec<&str> = cmd.split_whitespace().collect();
        if parts.is_empty() {
            bail!("empty command");
        }
        let program = parts[0].to_string();
        let args = parts[1..].iter().map(|s| s.to_string()).collect();
        Ok((program, args))
    }

    fn is_safe_string(&self, s: &str) -> bool {
        // Allow letters, numbers, space, underscore, dash, dot, slash, colon, equals
        s.chars()
            .all(|c| c.is_alphanumeric() || matches!(c, ' ' | '_' | '-' | '.' | '/' | ':' | '='))
    }

    /// Validate Docker command in format: docker:operation:container_name
    fn validate_docker_command(&self, cmd: &str) -> Result<()> {
        use crate::commands::DockerOperation;

        // Parse and validate the Docker operation
        let _op = DockerOperation::parse(cmd)?;

        // If parsing succeeds, the command is valid
        Ok(())
    }
}

impl Default for CommandValidator {
    fn default() -> Self {
        Self::default_secure()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cmd(id: &str, name: &str) -> AgentCommand {
        AgentCommand {
            id: id.to_string(),
            name: name.to_string(),
            params: serde_json::json!({}),
        }
    }

    #[test]
    fn allows_simple_echo() {
        let v = CommandValidator::default_secure();
        assert!(v.validate(&cmd("1", "echo hello")).is_ok());
    }

    #[test]
    fn blocks_shell_when_disabled() {
        let v = CommandValidator::default_secure();
        assert!(v.validate(&cmd("2", "bash -c echo hi")).is_err());
    }

    #[test]
    fn blocks_metachars() {
        let v = CommandValidator::default_secure();
        assert!(v.validate(&cmd("3", "echo hello && ls")).is_err());
        assert!(v.validate(&cmd("4", "echo `whoami`")).is_err());
    }

    #[test]
    fn blocks_absolute_path_outside_whitelist() {
        let v = CommandValidator::default_secure();
        assert!(v.validate(&cmd("5", "ls /etc")).is_err());
    }

    #[test]
    fn allows_sleep_numeric() {
        let v = CommandValidator::default_secure();
        assert!(v.validate(&cmd("6", "sleep 1")).is_ok());
    }
}
