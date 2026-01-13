use anyhow::{Context, Result};
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::time::{sleep, timeout as tokio_timeout, Duration};
use tracing::{debug, error, info, warn};

use crate::commands::timeout::{TimeoutPhase, TimeoutStrategy, TimeoutTracker};
use crate::transport::{Command as AgentCommand, CommandResult};

/// Result of command execution
#[derive(Debug, Clone)]
pub struct ExecutionResult {
    pub command_id: String,
    pub status: ExecutionStatus,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub duration_secs: u64,
    pub timeout_phase_reached: Option<TimeoutPhase>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionStatus {
    Success,
    Failed,
    Timeout,
    Killed,
}

impl ExecutionResult {
    pub fn to_command_result(&self) -> CommandResult {
        let status = match self.status {
            ExecutionStatus::Success => "success",
            ExecutionStatus::Failed => "failed",
            ExecutionStatus::Timeout => "timeout",
            ExecutionStatus::Killed => "killed",
        }
        .to_string();

        let mut result_data = serde_json::json!({
            "exit_code": self.exit_code,
            "duration_secs": self.duration_secs,
        });

        if !self.stdout.is_empty() {
            result_data["stdout"] = serde_json::json!(self.stdout);
        }
        if !self.stderr.is_empty() {
            result_data["stderr"] = serde_json::json!(self.stderr);
        }

        CommandResult {
            command_id: self.command_id.clone(),
            status,
            result: Some(result_data),
            error: if self.status == ExecutionStatus::Success {
                None
            } else {
                Some(self.stderr.clone())
            },
            ..CommandResult::default()
        }
    }
}

/// Progress callback for command execution
pub type ProgressCallback = Box<dyn Fn(TimeoutPhase, u64) + Send + Sync>;

/// Executes commands with timeout management and signal handling
pub struct CommandExecutor {
    /// Optional callback for progress updates
    progress_callback: Option<ProgressCallback>,
}

impl CommandExecutor {
    pub fn new() -> Self {
        Self {
            progress_callback: None,
        }
    }

    /// Set progress callback for dashboard updates
    pub fn with_progress_callback<F>(mut self, callback: F) -> Self
    where
        F: Fn(TimeoutPhase, u64) + Send + Sync + 'static,
    {
        self.progress_callback = Some(Box::new(callback));
        self
    }

    /// Execute a command with timeout monitoring
    pub async fn execute(
        &self,
        command: &AgentCommand,
        strategy: TimeoutStrategy,
    ) -> Result<ExecutionResult> {
        info!("Executing command: {} (id: {})", command.name, command.id);

        let mut tracker = TimeoutTracker::new(strategy.clone());
        let start = std::time::Instant::now();

        // Parse command and arguments
        let (cmd_name, args) = self.parse_command(&command.name)?;

        // Spawn the process
        let mut child = Command::new(&cmd_name)
            .args(&args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .context("failed to spawn command")?;

        let child_id = child.id();
        debug!("Spawned process with PID: {:?}", child_id);

        // Capture output streams
        let stdout = child.stdout.take().context("failed to capture stdout")?;
        let stderr = child.stderr.take().context("failed to capture stderr")?;

        let stdout_reader = BufReader::new(stdout);
        let stderr_reader = BufReader::new(stderr);

        let mut stdout_lines = stdout_reader.lines();
        let mut stderr_lines = stderr_reader.lines();

        let mut stdout_output = String::new();
        let mut stderr_output = String::new();
        let mut last_phase = TimeoutPhase::Normal;

        // Monitor execution with timeout phases
        let execution_result = loop {
            let current_phase = tracker.current_phase();

            // Report phase transitions
            if current_phase != last_phase {
                let elapsed = tracker.elapsed().as_secs();
                info!(
                    "Command {} entered phase {:?} after {}s",
                    command.id, current_phase, elapsed
                );

                if let Some(ref callback) = self.progress_callback {
                    callback(current_phase, elapsed);
                }

                last_phase = current_phase;
            }

            match current_phase {
                TimeoutPhase::Normal | TimeoutPhase::Warning => {
                    // Continue monitoring
                    tokio::select! {
                        result = child.wait() => {
                            // Process completed
                            let status = result.context("failed to wait for child")?;

                            // Drain remaining output
                            while let Ok(Some(line)) = stdout_lines.next_line().await {
                                stdout_output.push_str(&line);
                                stdout_output.push('\n');
                            }
                            while let Ok(Some(line)) = stderr_lines.next_line().await {
                                stderr_output.push_str(&line);
                                stderr_output.push('\n');
                            }

                            let exec_status = if status.success() {
                                ExecutionStatus::Success
                            } else {
                                ExecutionStatus::Failed
                            };

                            break ExecutionResult {
                                command_id: command.id.clone(),
                                status: exec_status,
                                exit_code: status.code(),
                                stdout: stdout_output,
                                stderr: stderr_output,
                                duration_secs: start.elapsed().as_secs(),
                                timeout_phase_reached: Some(current_phase),
                            };
                        }

                        Ok(Some(line)) = stdout_lines.next_line() => {
                            stdout_output.push_str(&line);
                            stdout_output.push('\n');
                            tracker.report_progress();
                        }

                        Ok(Some(line)) = stderr_lines.next_line() => {
                            stderr_output.push_str(&line);
                            stderr_output.push('\n');
                            tracker.report_progress();
                        }

                        _ = sleep(strategy.progress_interval()) => {
                            // Check for stalls
                            if tracker.is_stalled() {
                                warn!("Command {} has stalled (no output for {}s)",
                                    command.id, strategy.stall_threshold_secs);
                            }
                        }
                    }
                }

                TimeoutPhase::HardTermination => {
                    warn!(
                        "Command {} reached hard timeout, attempting graceful termination",
                        command.id
                    );

                    if strategy.allow_graceful_termination {
                        // Send SIGTERM and wait 30 seconds
                        self.send_sigterm(&mut child, child_id)?;

                        match tokio_timeout(Duration::from_secs(30), child.wait()).await {
                            Ok(Ok(status)) => {
                                info!("Command {} terminated gracefully", command.id);
                                break ExecutionResult {
                                    command_id: command.id.clone(),
                                    status: ExecutionStatus::Timeout,
                                    exit_code: status.code(),
                                    stdout: stdout_output,
                                    stderr: stderr_output,
                                    duration_secs: start.elapsed().as_secs(),
                                    timeout_phase_reached: Some(TimeoutPhase::HardTermination),
                                };
                            }
                            _ => {
                                // Fall through to force kill
                                continue;
                            }
                        }
                    } else {
                        // Skip to force kill
                        continue;
                    }
                }

                TimeoutPhase::ForceKill => {
                    error!(
                        "Command {} reached kill timeout, force terminating",
                        command.id
                    );
                    self.send_sigkill(&mut child, child_id).await?;

                    // Wait a brief moment for kill to take effect
                    let _ = tokio_timeout(Duration::from_secs(2), child.wait()).await;

                    break ExecutionResult {
                        command_id: command.id.clone(),
                        status: ExecutionStatus::Killed,
                        exit_code: None,
                        stdout: stdout_output,
                        stderr: stderr_output,
                        duration_secs: start.elapsed().as_secs(),
                        timeout_phase_reached: Some(TimeoutPhase::ForceKill),
                    };
                }
            }
        };

        info!(
            "Command {} completed with status: {:?}",
            command.id, execution_result.status
        );
        Ok(execution_result)
    }

    /// Parse command string into program and arguments
    fn parse_command(&self, cmd: &str) -> Result<(String, Vec<String>)> {
        let parts: Vec<&str> = cmd.split_whitespace().collect();
        if parts.is_empty() {
            anyhow::bail!("empty command");
        }

        let program = parts[0].to_string();
        let args = parts[1..].iter().map(|s| s.to_string()).collect();

        Ok((program, args))
    }

    /// Send SIGTERM to process
    #[cfg(unix)]
    fn send_sigterm(&self, child: &mut Child, pid: Option<u32>) -> Result<()> {
        if let Some(pid) = pid {
            use nix::sys::signal::{kill, Signal};
            use nix::unistd::Pid;

            debug!("Sending SIGTERM to PID {}", pid);
            kill(Pid::from_raw(pid as i32), Signal::SIGTERM).context("failed to send SIGTERM")?;
        } else {
            child.start_kill().context("failed to send SIGTERM")?;
        }
        Ok(())
    }

    #[cfg(not(unix))]
    fn send_sigterm(&self, child: &mut Child, _pid: Option<u32>) -> Result<()> {
        child.start_kill().context("failed to terminate process")?;
        Ok(())
    }

    /// Send SIGKILL to process
    #[cfg(unix)]
    async fn send_sigkill(&self, child: &mut Child, pid: Option<u32>) -> Result<()> {
        if let Some(pid) = pid {
            use nix::sys::signal::{kill, Signal};
            use nix::unistd::Pid;

            debug!("Sending SIGKILL to PID {}", pid);
            kill(Pid::from_raw(pid as i32), Signal::SIGKILL).context("failed to send SIGKILL")?;
        } else {
            child.kill().await.context("failed to kill process")?;
        }
        Ok(())
    }

    #[cfg(not(unix))]
    async fn send_sigkill(&self, child: &mut Child, _pid: Option<u32>) -> Result<()> {
        child.kill().await.context("failed to kill process")?;
        Ok(())
    }
}

impl Default for CommandExecutor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_execute_simple_command() {
        let executor = CommandExecutor::new();
        let command = AgentCommand {
            id: "test-1".to_string(),
            name: "echo hello".to_string(),
            params: serde_json::json!({}),
            deployment_hash: None,
            app_code: None,
        };

        let strategy = TimeoutStrategy::quick_strategy(10);
        let result = executor.execute(&command, strategy).await.unwrap();

        assert_eq!(result.status, ExecutionStatus::Success);
        assert!(result.stdout.contains("hello"));
    }

    #[tokio::test]
    async fn test_command_timeout() {
        let executor = CommandExecutor::new();
        let command = AgentCommand {
            id: "test-2".to_string(),
            name: "sleep 100".to_string(),
            params: serde_json::json!({}),
            deployment_hash: None,
            app_code: None,
        };

        let strategy = TimeoutStrategy {
            base_timeout_secs: 2,
            soft_multiplier: 0.5,
            hard_multiplier: 0.8,
            kill_multiplier: 1.0,
            allow_graceful_termination: false,
            ..Default::default()
        };

        let result = executor.execute(&command, strategy).await.unwrap();

        assert!(matches!(
            result.status,
            ExecutionStatus::Timeout | ExecutionStatus::Killed
        ));
    }

    #[tokio::test]
    async fn test_failed_command() {
        let executor = CommandExecutor::new();
        let command = AgentCommand {
            id: "test-3".to_string(),
            name: "false".to_string(),
            params: serde_json::json!({}),
            deployment_hash: None,
            app_code: None,
        };

        let strategy = TimeoutStrategy::quick_strategy(10);
        let result = executor.execute(&command, strategy).await.unwrap();

        assert_eq!(result.status, ExecutionStatus::Failed);
        assert_eq!(result.exit_code, Some(1));
    }
}
