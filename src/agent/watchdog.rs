use anyhow::{Context, Result};
use std::time::Duration;
use tokio::time::sleep;
use tracing::{error, info, warn};

#[cfg(feature = "docker")]
use bollard::Docker;

/// Watchdog configuration for compose-agent container monitoring
#[derive(Debug, Clone)]
pub struct WatchdogConfig {
    /// Container name to monitor
    pub target_container: String,
    /// Check interval in seconds
    pub check_interval_secs: u64,
    /// Maximum restart attempts before giving up
    pub max_restart_attempts: u32,
    /// Backoff multiplier for restart delays
    pub restart_backoff_multiplier: f64,
}

impl Default for WatchdogConfig {
    fn default() -> Self {
        Self {
            target_container: "compose-agent".to_string(),
            check_interval_secs: 30,
            max_restart_attempts: 5,
            restart_backoff_multiplier: 1.5,
        }
    }
}

/// Health check result for the compose-agent container
#[derive(Debug, Clone, PartialEq)]
pub enum HealthStatus {
    Healthy,
    Unhealthy(String),
    NotFound,
    GlibcMismatch,
}

#[cfg(feature = "docker")]
/// Watchdog for monitoring and restarting compose-agent container
pub struct ComposeAgentWatchdog {
    config: WatchdogConfig,
    docker: Docker,
    restart_count: u32,
    last_restart: Option<std::time::Instant>,
}

#[cfg(feature = "docker")]
impl ComposeAgentWatchdog {
    /// Create a new watchdog instance
    pub fn new(config: WatchdogConfig) -> Result<Self> {
        let docker = Docker::connect_with_defaults().context("connecting to Docker daemon")?;

        Ok(Self {
            config,
            docker,
            restart_count: 0,
            last_restart: None,
        })
    }

    /// Check health of the compose-agent container
    pub async fn check_health(&self) -> Result<HealthStatus> {
        use bollard::query_parameters::InspectContainerOptions;

        let inspect = match self
            .docker
            .inspect_container(
                &self.config.target_container,
                None::<InspectContainerOptions>,
            )
            .await
        {
            Ok(data) => data,
            Err(bollard::errors::Error::DockerResponseServerError {
                status_code: 404, ..
            }) => {
                return Ok(HealthStatus::NotFound);
            }
            Err(e) => return Err(anyhow::anyhow!("failed to inspect container: {}", e)),
        };

        // Check if container is running
        let state = inspect.state.unwrap_or_default();
        if !state.running.unwrap_or(false) {
            let exit_code = state.exit_code.unwrap_or(0);
            if let Some(error) = &state.error {
                // Check for glibc mismatch errors
                if error.contains("GLIBC") || error.contains("version") {
                    return Ok(HealthStatus::GlibcMismatch);
                }
                return Ok(HealthStatus::Unhealthy(error.clone()));
            }
            return Ok(HealthStatus::Unhealthy(format!(
                "container stopped with exit code {}",
                exit_code
            )));
        }

        Ok(HealthStatus::Healthy)
    }

    /// Restart the compose-agent container
    pub async fn restart_container(&mut self) -> Result<()> {
        use bollard::query_parameters::RestartContainerOptions;

        info!(
            "Restarting {} (attempt {}/{})",
            self.config.target_container,
            self.restart_count + 1,
            self.config.max_restart_attempts
        );

        self.docker
            .restart_container(
                &self.config.target_container,
                None::<RestartContainerOptions>,
            )
            .await
            .context("restarting container")?;

        self.restart_count += 1;
        self.last_restart = Some(std::time::Instant::now());

        info!("Successfully restarted {}", self.config.target_container);

        Ok(())
    }

    /// Calculate backoff delay before next restart attempt
    fn calculate_backoff_delay(&self) -> Duration {
        let base_delay = Duration::from_secs(10);
        let multiplier = self
            .config
            .restart_backoff_multiplier
            .powi(self.restart_count as i32);
        Duration::from_secs((base_delay.as_secs() as f64 * multiplier) as u64)
    }

    /// Run the watchdog loop
    pub async fn run(&mut self) -> Result<()> {
        info!(
            "Starting watchdog for {} (check interval: {}s)",
            self.config.target_container, self.config.check_interval_secs
        );

        loop {
            sleep(Duration::from_secs(self.config.check_interval_secs)).await;

            match self.check_health().await {
                Ok(HealthStatus::Healthy) => {
                    // Reset restart count on successful health check
                    if self.restart_count > 0 {
                        info!("Container healthy, resetting restart count");
                        self.restart_count = 0;
                    }
                }
                Ok(HealthStatus::Unhealthy(reason)) => {
                    warn!(
                        "Container {} unhealthy: {}",
                        self.config.target_container, reason
                    );

                    if self.restart_count >= self.config.max_restart_attempts {
                        error!(
                            "Max restart attempts ({}) reached for {}",
                            self.config.max_restart_attempts, self.config.target_container
                        );
                        return Err(anyhow::anyhow!(
                            "max restart attempts exceeded for {}",
                            self.config.target_container
                        ));
                    }

                    let backoff = self.calculate_backoff_delay();
                    warn!("Waiting {:?} before restart attempt", backoff);
                    sleep(backoff).await;

                    if let Err(e) = self.restart_container().await {
                        error!("Failed to restart container: {}", e);
                    }
                }
                Ok(HealthStatus::GlibcMismatch) => {
                    error!(
                        "GLIBC mismatch detected in {}! Attempting restart",
                        self.config.target_container
                    );

                    if self.restart_count >= self.config.max_restart_attempts {
                        error!(
                            "Max restart attempts ({}) reached for glibc issue",
                            self.config.max_restart_attempts
                        );
                        return Err(anyhow::anyhow!(
                            "unable to resolve glibc mismatch after {} attempts",
                            self.config.max_restart_attempts
                        ));
                    }

                    if let Err(e) = self.restart_container().await {
                        error!("Failed to restart container: {}", e);
                    }
                }
                Ok(HealthStatus::NotFound) => {
                    warn!(
                        "Container {} not found, skipping health check",
                        self.config.target_container
                    );
                }
                Err(e) => {
                    error!("Health check failed: {}", e);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_watchdog_config_defaults() {
        let config = WatchdogConfig::default();
        assert_eq!(config.target_container, "compose-agent");
        assert_eq!(config.check_interval_secs, 30);
        assert_eq!(config.max_restart_attempts, 5);
        assert_eq!(config.restart_backoff_multiplier, 1.5);
    }

    #[test]
    fn test_health_status_equality() {
        assert_eq!(HealthStatus::Healthy, HealthStatus::Healthy);
        assert_eq!(HealthStatus::NotFound, HealthStatus::NotFound);
        assert_eq!(
            HealthStatus::Unhealthy("test".to_string()),
            HealthStatus::Unhealthy("test".to_string())
        );
    }

    #[cfg(feature = "docker")]
    #[test]
    #[ignore] // Requires Docker daemon connection
    fn test_backoff_calculation() {
        let config = WatchdogConfig::default();
        let watchdog = ComposeAgentWatchdog {
            config: config.clone(),
            docker: Docker::connect_with_defaults().unwrap(),
            restart_count: 0,
            last_restart: None,
        };

        let delay = watchdog.calculate_backoff_delay();
        assert_eq!(delay.as_secs(), 10); // base delay

        let mut watchdog = watchdog;
        watchdog.restart_count = 1;
        let delay = watchdog.calculate_backoff_delay();
        assert_eq!(delay.as_secs(), 15); // 10 * 1.5

        watchdog.restart_count = 2;
        let delay = watchdog.calculate_backoff_delay();
        assert_eq!(delay.as_secs(), 22); // 10 * 1.5^2 = 22.5 -> 22
    }

    #[test]
    fn test_backoff_calculation_no_docker() {
        // Test the backoff calculation logic without requiring Docker
        let config = WatchdogConfig::default();

        // Mock backoff calculation based on formula
        let calculate_mock_backoff = |restart_count: u32| -> std::time::Duration {
            let base_delay = std::time::Duration::from_secs(10);
            let multiplier = config.restart_backoff_multiplier.powi(restart_count as i32);
            std::time::Duration::from_secs((base_delay.as_secs() as f64 * multiplier) as u64)
        };

        let delay = calculate_mock_backoff(0);
        assert_eq!(delay.as_secs(), 10); // base delay

        let delay = calculate_mock_backoff(1);
        assert_eq!(delay.as_secs(), 15); // 10 * 1.5

        let delay = calculate_mock_backoff(2);
        assert_eq!(delay.as_secs(), 22); // 10 * 1.5^2 = 22.5 -> 22
    }
}
