#![cfg(feature = "docker")]
use anyhow::{Context, Result};
use bollard::container::LogOutput;
use bollard::exec::CreateExecOptions;
use bollard::models::{ContainerStatsResponse, ContainerSummaryStateEnum};
use bollard::query_parameters::{
    ListContainersOptions, ListContainersOptionsBuilder, RestartContainerOptions,
    StopContainerOptions,
};
use bollard::Docker;
use serde::Serialize;
use std::collections::HashMap;
use tracing::{debug, error};

#[derive(Serialize, Clone, Debug)]
pub struct ContainerInfo {
    pub name: String,
    pub status: String,
    pub logs: String,
    pub ports: Vec<PortInfo>,
}

#[derive(Serialize, Clone, Debug, Default)]
pub struct ContainerHealth {
    pub name: String,
    pub status: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub image: String,
    pub cpu_pct: f32,
    pub mem_usage_bytes: u64,
    pub mem_limit_bytes: u64,
    pub mem_pct: f32,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub restart_count: Option<i64>,
    #[serde(skip_serializing_if = "HashMap::is_empty", default)]
    pub labels: HashMap<String, String>,
}

#[derive(Serialize, Clone, Debug)]
pub struct LogFrame {
    pub stream: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
}

#[derive(Serialize, Clone, Debug, Default)]
pub struct LogWindow {
    pub frames: Vec<LogFrame>,
    pub truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Serialize, Clone, Debug)]
pub struct PortInfo {
    pub port: String,
    pub title: Option<String>,
}

fn docker_client() -> Result<Docker> {
    Docker::connect_with_defaults().context("docker client connect")
}

fn name_matches(container_name: &str, app_code: &str) -> bool {
    let normalized = container_name.trim_start_matches('/');
    normalized == app_code
        || normalized == format!("{}_1", app_code)
        || normalized.ends_with(&format!("-{}", app_code))
        || normalized.ends_with(&format!("_{}", app_code))
        || normalized.ends_with(&format!("_{}_1", app_code))
        || normalized.ends_with(&format!("-{}-1", app_code))
}

async fn resolve_container_name(name: &str) -> Result<String> {
    let docker = docker_client()?;
    let opts: Option<ListContainersOptions> =
        Some(ListContainersOptionsBuilder::default().all(true).build());
    let list = docker
        .list_containers(opts)
        .await
        .context("list containers")?;

    for container in list {
        if let Some(names) = container.names {
            for entry in names {
                if name_matches(&entry, name) {
                    return Ok(entry.trim_start_matches('/').to_string());
                }
            }
        }
    }

    Ok(name.to_string())
}

pub async fn list_containers() -> Result<Vec<ContainerInfo>> {
    let docker = docker_client()?;
    let opts: Option<ListContainersOptions> =
        Some(ListContainersOptionsBuilder::default().all(true).build());
    let list = docker
        .list_containers(opts)
        .await
        .context("list containers")?;
    Ok(list
        .into_iter()
        .map(|c| {
            let name = c
                .names
                .unwrap_or_default()
                .first()
                .cloned()
                .unwrap_or_default()
                .trim_start_matches('/')
                .to_string();
            let status = c
                .state
                .as_ref()
                .map(|s| format!("{:?}", s))
                .unwrap_or_else(|| "unknown".to_string());
            ContainerInfo {
                name,
                status,
                logs: String::new(),
                ports: vec![],
            }
        })
        .collect())
}

pub async fn list_containers_with_logs(tail: &str) -> Result<Vec<ContainerInfo>> {
    let docker = docker_client()?;
    let opts: Option<ListContainersOptions> =
        Some(ListContainersOptionsBuilder::default().all(true).build());
    let list = docker
        .list_containers(opts)
        .await
        .context("list containers")?;

    let mut result = Vec::with_capacity(list.len());

    for c in list.into_iter() {
        let name = c
            .names
            .as_ref()
            .and_then(|v| v.first().cloned())
            .unwrap_or_default()
            .trim_start_matches('/')
            .to_string();

        let status = c
            .state
            .as_ref()
            .map(|s| s.to_string())
            .unwrap_or_else(|| "unknown".to_string());

        let logs = get_container_logs(&name, tail).await.unwrap_or_default();

        result.push(ContainerInfo {
            name,
            status,
            logs,
            ports: vec![],
        });
    }

    Ok(result)
}

fn calc_cpu_percent(stats: &ContainerStatsResponse) -> f32 {
    let (cpu_stats, precpu_stats) = match (&stats.cpu_stats, &stats.precpu_stats) {
        (Some(cpu), Some(precpu)) => (cpu, precpu),
        _ => return 0.0,
    };

    let total_delta = cpu_stats
        .cpu_usage
        .as_ref()
        .and_then(|c| c.total_usage)
        .unwrap_or(0)
        .saturating_sub(
            precpu_stats
                .cpu_usage
                .as_ref()
                .and_then(|c| c.total_usage)
                .unwrap_or(0),
        );

    let system_delta = cpu_stats
        .system_cpu_usage
        .unwrap_or(0)
        .saturating_sub(precpu_stats.system_cpu_usage.unwrap_or(0));

    if system_delta == 0 || total_delta == 0 {
        return 0.0;
    }

    let online_cpus = cpu_stats.online_cpus.map(|v| v as f64).unwrap_or_else(|| {
        cpu_stats
            .cpu_usage
            .as_ref()
            .and_then(|c| c.percpu_usage.as_ref())
            .map(|v: &Vec<u64>| v.len() as f64)
            .unwrap_or(1.0)
    });

    ((total_delta as f64 / system_delta as f64) * online_cpus * 100.0) as f32
}

fn calc_memory(stats: &ContainerStatsResponse) -> (u64, u64, f32) {
    let usage = stats
        .memory_stats
        .as_ref()
        .and_then(|m| m.usage)
        .unwrap_or(0);
    let limit = stats
        .memory_stats
        .as_ref()
        .and_then(|m| m.limit)
        .unwrap_or(0);

    let pct = if limit > 0 {
        (usage as f64 / limit as f64 * 100.0) as f32
    } else {
        0.0
    };

    (usage, limit, pct)
}

fn calc_network(stats: &ContainerStatsResponse) -> (u64, u64) {
    if let Some(networks) = &stats.networks {
        let mut rx = 0u64;
        let mut tx = 0u64;
        for (_iface, data) in networks.iter() {
            rx = rx.saturating_add(data.rx_bytes.unwrap_or(0));
            tx = tx.saturating_add(data.tx_bytes.unwrap_or(0));
        }
        (rx, tx)
    } else {
        (0, 0)
    }
}

async fn fetch_stats_for(docker: &Docker, name: &str) -> Result<ContainerHealth> {
    use futures_util::StreamExt;

    let mut stream = docker.stats(
        name,
        Some(bollard::query_parameters::StatsOptions {
            stream: false,
            one_shot: true,
        }),
    );
    let mut health = ContainerHealth {
        name: name.to_string(),
        status: "unknown".to_string(),
        image: String::new(),
        labels: HashMap::new(),
        ..Default::default()
    };

    if let Some(next) = stream.next().await {
        match next {
            Ok(stats) => {
                health.cpu_pct = calc_cpu_percent(&stats);
                let (usage, limit, pct) = calc_memory(&stats);
                health.mem_usage_bytes = usage;
                health.mem_limit_bytes = limit;
                health.mem_pct = pct;
                let (rx, tx) = calc_network(&stats);
                health.rx_bytes = rx;
                health.tx_bytes = tx;

                if let Some(cont) = stats.name.clone() {
                    health.name = cont.trim_start_matches('/').to_string();
                }
            }
            Err(e) => {
                error!("failed to read stats for {}: {}", name, e);
            }
        }
    }

    Ok(health)
}

pub async fn list_container_health() -> Result<Vec<ContainerHealth>> {
    let docker = docker_client()?;
    let opts: Option<ListContainersOptions> =
        Some(ListContainersOptionsBuilder::default().all(true).build());
    let list = docker
        .list_containers(opts)
        .await
        .context("list containers")?;

    let mut health = Vec::with_capacity(list.len());

    for c in list.into_iter() {
        let name = c
            .names
            .as_ref()
            .and_then(|v| v.first().cloned())
            .unwrap_or_default()
            .trim_start_matches('/')
            .to_string();

        let status = c
            .state
            .as_ref()
            .map(|s| s.to_string())
            .unwrap_or_else(|| "unknown".to_string());

        let mut item = ContainerHealth {
            name: name.clone(),
            status,
            image: c.image.unwrap_or_default(),
            labels: c.labels.unwrap_or_default(),
            ..Default::default()
        };

        // Only attempt stats if container is running or paused
        if matches!(
            c.state,
            Some(
                ContainerSummaryStateEnum::RUNNING
                    | ContainerSummaryStateEnum::RESTARTING
                    | ContainerSummaryStateEnum::PAUSED
            )
        ) {
            match fetch_stats_for(&docker, &name).await {
                Ok(stats) => {
                    item.cpu_pct = stats.cpu_pct;
                    item.mem_usage_bytes = stats.mem_usage_bytes;
                    item.mem_limit_bytes = stats.mem_limit_bytes;
                    item.mem_pct = stats.mem_pct;
                    item.rx_bytes = stats.rx_bytes;
                    item.tx_bytes = stats.tx_bytes;
                }
                Err(e) => {
                    error!("failed to fetch stats for {}: {}", name, e);
                }
            }
        }

        health.push(item);
    }

    Ok(health)
}

/// Fetch container logs with stream labels, cursor pagination, and truncation awareness.
pub async fn get_container_logs_window(
    name: &str,
    cursor: Option<String>,
    limit: Option<usize>,
) -> Result<LogWindow> {
    use bollard::query_parameters::LogsOptionsBuilder;
    use futures_util::StreamExt;

    let docker = docker_client()?;
    let resolved_name = resolve_container_name(name)
        .await
        .unwrap_or_else(|_| name.to_string());
    let mut builder = LogsOptionsBuilder::default();
    builder = builder
        .stdout(true)
        .stderr(true)
        .follow(false)
        .timestamps(true);

    if let Some(ts) = cursor.as_deref() {
        if let Some(epoch) = parse_cursor_to_epoch(ts) {
            // bollard expects i32 seconds since epoch; clamp to avoid overflow
            let since = i32::try_from(epoch).unwrap_or(i32::MAX);
            builder = builder.since(since);
        }
    } else if let Some(max) = limit {
        let tail = max.to_string();
        builder = builder.tail(&tail);
    }

    let opts = builder.build();
    let mut logs = docker.logs(&resolved_name, Some(opts));
    let mut frames: Vec<LogFrame> = Vec::new();
    let mut truncated = false;
    let mut last_cursor: Option<String> = None;

    while let Some(item) = logs.next().await {
        let output = match item {
            Ok(v) => v,
            Err(e) => {
                error!(container = name, error = %e, "error reading log stream");
                continue;
            }
        };

        let (stream, bytes) = match output {
            LogOutput::StdOut { message, .. } => ("stdout", message),
            LogOutput::StdErr { message, .. } => ("stderr", message),
            LogOutput::StdIn { message, .. } => ("stdin", message),
            LogOutput::Console { message, .. } => ("console", message),
        };

        let text = String::from_utf8_lossy(&bytes).to_string();
        let trimmed = text.trim_end_matches('\n');
        let (timestamp, message) = if let Some((ts, rest)) = trimmed.split_once(' ') {
            (Some(ts.to_string()), rest.to_string())
        } else {
            (None, trimmed.to_string())
        };

        if let Some(ts) = timestamp.clone() {
            last_cursor = Some(ts);
        }

        frames.push(LogFrame {
            stream: stream.to_string(),
            message,
            timestamp,
        });

        if let Some(max) = limit {
            if frames.len() >= max {
                truncated = true;
                break;
            }
        }
    }

    Ok(LogWindow {
        frames,
        truncated,
        next_cursor: last_cursor,
    })
}

fn parse_cursor_to_epoch(cursor: &str) -> Option<i64> {
    if let Ok(value) = cursor.parse::<i64>() {
        return Some(value);
    }
    chrono::DateTime::parse_from_rfc3339(cursor)
        .map(|dt| dt.timestamp())
        .ok()
}

pub async fn get_container_logs(name: &str, tail: &str) -> Result<String> {
    let docker = docker_client()?;
    let resolved_name = resolve_container_name(name)
        .await
        .unwrap_or_else(|_| name.to_string());
    use bollard::query_parameters::LogsOptionsBuilder;
    use futures_util::StreamExt;
    let opts = LogsOptionsBuilder::default()
        .stdout(true)
        .stderr(true)
        .follow(false)
        .tail(tail)
        .build();
    let mut logs = docker.logs(&resolved_name, Some(opts));
    let mut log_text = String::new();
    while let Some(log_line) = logs.next().await {
        match log_line {
            Ok(output) => log_text.push_str(&output.to_string()),
            Err(e) => error!("error reading log: {}", e),
        }
    }
    Ok(log_text)
}

pub async fn restart(name: &str) -> Result<()> {
    let docker = docker_client()?;
    let resolved_name = resolve_container_name(name)
        .await
        .unwrap_or_else(|_| name.to_string());
    docker
        .restart_container(&resolved_name, None::<RestartContainerOptions>)
        .await
        .context("restart container")?;
    debug!("restarted container: {}", name);
    Ok(())
}

pub async fn stop(name: &str) -> Result<()> {
    let docker = docker_client()?;
    let resolved_name = resolve_container_name(name)
        .await
        .unwrap_or_else(|_| name.to_string());
    docker
        .stop_container(&resolved_name, None::<StopContainerOptions>)
        .await
        .context("stop container")?;
    debug!("stopped container: {}", name);
    Ok(())
}

pub async fn stop_with_timeout(name: &str, timeout_secs: u32) -> Result<()> {
    let docker = docker_client()?;
    let resolved_name = resolve_container_name(name)
        .await
        .unwrap_or_else(|_| name.to_string());
    let opts = StopContainerOptions {
        t: Some(timeout_secs as i32),
        signal: None,
    };
    docker
        .stop_container(&resolved_name, Some(opts))
        .await
        .context("stop container with timeout")?;
    debug!("stopped container: {} (timeout: {}s)", name, timeout_secs);
    Ok(())
}

pub async fn start(name: &str) -> Result<()> {
    let docker = docker_client()?;
    let resolved_name = resolve_container_name(name)
        .await
        .unwrap_or_else(|_| name.to_string());
    docker
        .start_container(
            &resolved_name,
            None::<bollard::query_parameters::StartContainerOptions>,
        )
        .await
        .context("start container")?;
    debug!("started container: {}", name);
    Ok(())
}

pub async fn pause(name: &str) -> Result<()> {
    let docker = docker_client()?;
    let resolved_name = resolve_container_name(name)
        .await
        .unwrap_or_else(|_| name.to_string());
    docker
        .pause_container(&resolved_name)
        .await
        .context("pause container")?;
    debug!("paused container: {}", name);
    Ok(())
}

/// Execute a shell command inside a running container.
/// Returns Ok(()) on success (exit code 0), Err otherwise.
pub async fn exec_in_container(name: &str, cmd: &str) -> Result<()> {
    use bollard::exec::StartExecResults;
    use futures_util::StreamExt;

    let docker = docker_client()?;
    let resolved_name = resolve_container_name(name)
        .await
        .unwrap_or_else(|_| name.to_string());
    // Create exec instance
    let exec = docker
        .create_exec(
            &resolved_name,
            CreateExecOptions {
                attach_stdout: Some(true),
                attach_stderr: Some(true),
                tty: Some(false),
                cmd: Some(vec![
                    "/bin/sh".to_string(),
                    "-c".to_string(),
                    cmd.to_string(),
                ]),
                ..Default::default()
            },
        )
        .await
        .context("create exec")?;

    // Start exec and capture output
    let start = docker
        .start_exec(&exec.id, None)
        .await
        .context("start exec")?;

    let mut combined = String::new();
    match start {
        StartExecResults::Detached => {
            debug!(container = name, command = cmd, "exec detached");
        }
        StartExecResults::Attached { mut output, .. } => {
            while let Some(item) = output.next().await {
                match item {
                    Ok(log) => {
                        let s = format!("{}", log);
                        combined.push_str(&s);
                    }
                    Err(e) => error!("exec output stream error: {}", e),
                }
            }
        }
    }

    // Inspect exec to get exit code
    let info = docker
        .inspect_exec(&exec.id)
        .await
        .context("inspect exec")?;
    let exit_code = info.exit_code.unwrap_or_default();
    if exit_code == 0 {
        debug!(
            container = name,
            command = cmd,
            "exec completed successfully"
        );
        Ok(())
    } else {
        error!(
            container = name,
            command = cmd,
            exit_code,
            output = combined,
            "exec failed"
        );
        Err(anyhow::anyhow!("exec failed with code {}", exit_code))
    }
}
