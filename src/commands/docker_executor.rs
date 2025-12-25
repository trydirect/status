use crate::commands::DockerOperation;
use crate::transport::CommandResult;
use anyhow::Result;

#[cfg(feature = "docker")]
use std::time::Instant;
#[cfg(feature = "docker")]
use tracing::{error, info};

#[cfg(feature = "docker")]
use crate::agent::docker;

/// Execute Docker operations via command API
#[cfg(feature = "docker")]
pub async fn execute_docker_operation(
    command_id: &str,
    operation: DockerOperation,
) -> Result<CommandResult> {
    let start = Instant::now();
    let container_name = operation.container_name().to_string();
    let op_type = operation.operation_type().to_string();

    info!(
        "Executing Docker operation: {} on container: {}",
        op_type, container_name
    );

    let (exit_code, stdout, stderr) = match operation {
        DockerOperation::Restart(ref name) => match docker::restart(name).await {
            Ok(_) => {
                let msg = format!("Container '{}' restarted successfully", name);
                info!("{}", msg);
                (0, msg, String::new())
            }
            Err(e) => {
                let err_msg = e.to_string();
                error!("Failed to restart container '{}': {}", name, err_msg);
                (1, String::new(), err_msg)
            }
        },

        DockerOperation::Stop(ref name) => match docker::stop(name).await {
            Ok(_) => {
                let msg = format!("Container '{}' stopped successfully", name);
                info!("{}", msg);
                (0, msg, String::new())
            }
            Err(e) => {
                let err_msg = e.to_string();
                error!("Failed to stop container '{}': {}", name, err_msg);
                (1, String::new(), err_msg)
            }
        },

        DockerOperation::Logs(ref name, tail) => {
            match docker::list_containers_with_logs(
                tail.map(|t| t.to_string()).as_deref().unwrap_or("100"),
            )
            .await
            {
                Ok(containers) => {
                    if let Some(container) = containers.iter().find(|c| c.name == *name) {
                        let logs = container.logs.clone();
                        let msg = format!(
                            "Retrieved {} bytes of logs from container '{}'",
                            logs.len(),
                            name
                        );
                        info!("{}", msg);
                        (0, logs, String::new())
                    } else {
                        let err_msg = format!("Container '{}' not found", name);
                        error!("{}", err_msg);
                        (1, String::new(), err_msg)
                    }
                }
                Err(e) => {
                    let err_msg = e.to_string();
                    error!("Failed to get logs for container '{}': {}", name, err_msg);
                    (1, String::new(), err_msg)
                }
            }
        }

        DockerOperation::Inspect(ref name) => match docker::list_containers().await {
            Ok(containers) => {
                if let Some(container) = containers.iter().find(|c| c.name == *name) {
                    let inspect_json = serde_json::to_string_pretty(container)
                        .unwrap_or_else(|_| format!("Container: {}", container.name));
                    info!("Inspected container '{}'", name);
                    (0, inspect_json, String::new())
                } else {
                    let err_msg = format!("Container '{}' not found", name);
                    error!("{}", err_msg);
                    (1, String::new(), err_msg)
                }
            }
            Err(e) => {
                let err_msg = e.to_string();
                error!("Failed to inspect container '{}': {}", name, err_msg);
                (1, String::new(), err_msg)
            }
        },

        DockerOperation::Pause(ref name) => match docker::pause(name).await {
            Ok(_) => {
                let msg = format!("Container '{}' paused successfully", name);
                info!("{}", msg);
                (0, msg, String::new())
            }
            Err(e) => {
                let err_msg = e.to_string();
                error!("Failed to pause container '{}': {}", name, err_msg);
                (1, String::new(), err_msg)
            }
        },
    };

    let duration_secs = start.elapsed().as_secs();
    let status = if exit_code == 0 { "success" } else { "failed" };

    Ok(CommandResult {
        command_id: command_id.to_string(),
        status: status.to_string(),
        result: Some(serde_json::json!({
            "exit_code": exit_code,
            "duration_secs": duration_secs,
            "operation": op_type,
            "container": container_name,
            "stdout": stdout,
        })),
        error: if exit_code != 0 { Some(stderr) } else { None },
    })
}

/// Fallback for non-Docker builds
#[cfg(not(feature = "docker"))]
pub async fn execute_docker_operation(
    _command_id: &str,
    _operation: DockerOperation,
) -> Result<CommandResult> {
    use anyhow::anyhow;
    Err(anyhow!(
        "Docker operations not available: build without docker feature"
    ))
}
