use super::models::{ComponentHealth, HealthCheckResponse};
use crate::configuration::Settings;
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::timeout;

const CHECK_TIMEOUT: Duration = Duration::from_secs(5);
const SLOW_RESPONSE_THRESHOLD_MS: u64 = 1000;

pub struct HealthChecker {
    pg_pool: Arc<PgPool>,
    settings: Arc<Settings>,
    start_time: Instant,
}

impl HealthChecker {
    pub fn new(pg_pool: Arc<PgPool>, settings: Arc<Settings>) -> Self {
        Self {
            pg_pool,
            settings,
            start_time: Instant::now(),
        }
    }

    pub async fn check_all(&self) -> HealthCheckResponse {
        let version = env!("CARGO_PKG_VERSION").to_string();
        let uptime = self.start_time.elapsed().as_secs();
        let mut response = HealthCheckResponse::new(version, uptime);

        let db_check = timeout(CHECK_TIMEOUT, self.check_database());
        let mq_check = timeout(CHECK_TIMEOUT, self.check_rabbitmq());
        let hub_check = timeout(CHECK_TIMEOUT, self.check_dockerhub());
        let redis_check = timeout(CHECK_TIMEOUT, self.check_redis());
        let vault_check = timeout(CHECK_TIMEOUT, self.check_vault());
        let user_service_check = timeout(CHECK_TIMEOUT, self.check_user_service());
        let install_service_check = timeout(CHECK_TIMEOUT, self.check_install_service());

        let (
            db_result,
            mq_result,
            hub_result,
            redis_result,
            vault_result,
            user_result,
            install_result,
        ) = tokio::join!(
            db_check,
            mq_check,
            hub_check,
            redis_check,
            vault_check,
            user_service_check,
            install_service_check
        );

        let db_health =
            db_result.unwrap_or_else(|_| ComponentHealth::unhealthy("Timeout".to_string()));
        let mq_health =
            mq_result.unwrap_or_else(|_| ComponentHealth::unhealthy("Timeout".to_string()));
        let hub_health =
            hub_result.unwrap_or_else(|_| ComponentHealth::unhealthy("Timeout".to_string()));
        let redis_health =
            redis_result.unwrap_or_else(|_| ComponentHealth::unhealthy("Timeout".to_string()));
        let vault_health =
            vault_result.unwrap_or_else(|_| ComponentHealth::unhealthy("Timeout".to_string()));
        let user_health =
            user_result.unwrap_or_else(|_| ComponentHealth::unhealthy("Timeout".to_string()));
        let install_health =
            install_result.unwrap_or_else(|_| ComponentHealth::unhealthy("Timeout".to_string()));

        response.add_component("database".to_string(), db_health);
        response.add_component("rabbitmq".to_string(), mq_health);
        response.add_component("dockerhub".to_string(), hub_health);
        response.add_component("redis".to_string(), redis_health);
        response.add_component("vault".to_string(), vault_health);
        response.add_component("user_service".to_string(), user_health);
        response.add_component("install_service".to_string(), install_health);

        response
    }

    #[tracing::instrument(name = "Check database health", skip(self))]
    async fn check_database(&self) -> ComponentHealth {
        let start = Instant::now();

        match sqlx::query("SELECT 1 as health_check")
            .fetch_one(self.pg_pool.as_ref())
            .await
        {
            Ok(_) => {
                let elapsed = start.elapsed().as_millis() as u64;
                let mut health = ComponentHealth::healthy(elapsed);

                if elapsed > SLOW_RESPONSE_THRESHOLD_MS {
                    health = ComponentHealth::degraded(
                        "Database responding slowly".to_string(),
                        Some(elapsed),
                    );
                }

                let pool_size = self.pg_pool.size();
                let idle_connections = self.pg_pool.num_idle();
                let mut details = HashMap::new();
                details.insert("pool_size".to_string(), serde_json::json!(pool_size));
                details.insert(
                    "idle_connections".to_string(),
                    serde_json::json!(idle_connections),
                );
                details.insert(
                    "active_connections".to_string(),
                    serde_json::json!(pool_size as i64 - idle_connections as i64),
                );

                health.with_details(details)
            }
            Err(e) => {
                tracing::error!("Database health check failed: {:?}", e);
                ComponentHealth::unhealthy(format!("Database error: {}", e))
            }
        }
    }

    #[tracing::instrument(name = "Check RabbitMQ health", skip(self))]
    async fn check_rabbitmq(&self) -> ComponentHealth {
        let start = Instant::now();
        let connection_string = self.settings.amqp.connection_string();

        let mut config = deadpool_lapin::Config::default();
        config.url = Some(connection_string.clone());

        match config.create_pool(Some(deadpool_lapin::Runtime::Tokio1)) {
            Ok(pool) => match pool.get().await {
                Ok(conn) => match conn.create_channel().await {
                    Ok(_channel) => {
                        let elapsed = start.elapsed().as_millis() as u64;
                        let mut health = ComponentHealth::healthy(elapsed);

                        if elapsed > SLOW_RESPONSE_THRESHOLD_MS {
                            health = ComponentHealth::degraded(
                                "RabbitMQ responding slowly".to_string(),
                                Some(elapsed),
                            );
                        }

                        let mut details = HashMap::new();
                        details.insert(
                            "host".to_string(),
                            serde_json::json!(self.settings.amqp.host),
                        );
                        details.insert(
                            "port".to_string(),
                            serde_json::json!(self.settings.amqp.port),
                        );

                        health.with_details(details)
                    }
                    Err(e) => {
                        tracing::warn!("Failed to create RabbitMQ channel: {:?}", e);
                        ComponentHealth::degraded(
                            format!("RabbitMQ optional service unavailable: {}", e),
                            None,
                        )
                    }
                },
                Err(e) => {
                    tracing::warn!("Failed to get RabbitMQ connection: {:?}", e);
                    ComponentHealth::degraded(
                        format!("RabbitMQ optional service unavailable: {}", e),
                        None,
                    )
                }
            },
            Err(e) => {
                tracing::warn!("Failed to create RabbitMQ pool: {:?}", e);
                ComponentHealth::degraded(
                    format!("RabbitMQ optional service unavailable: {}", e),
                    None,
                )
            }
        }
    }

    #[tracing::instrument(name = "Check Docker Hub health", skip(self))]
    async fn check_dockerhub(&self) -> ComponentHealth {
        let start = Instant::now();
        let url = "https://hub.docker.com/v2/";

        match reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
        {
            Ok(client) => match client.get(url).send().await {
                Ok(response) => {
                    let elapsed = start.elapsed().as_millis() as u64;

                    if response.status().is_success() {
                        let mut health = ComponentHealth::healthy(elapsed);

                        if elapsed > SLOW_RESPONSE_THRESHOLD_MS {
                            health = ComponentHealth::degraded(
                                "Docker Hub responding slowly".to_string(),
                                Some(elapsed),
                            );
                        }

                        let mut details = HashMap::new();
                        details.insert("api_version".to_string(), serde_json::json!("v2"));
                        details.insert(
                            "status_code".to_string(),
                            serde_json::json!(response.status().as_u16()),
                        );

                        health.with_details(details)
                    } else {
                        ComponentHealth::degraded(
                            format!(
                                "Docker Hub returned status: {} (optional service)",
                                response.status()
                            ),
                            Some(start.elapsed().as_millis() as u64),
                        )
                    }
                }
                Err(e) => {
                    tracing::warn!("Docker Hub health check failed: {:?}", e);
                    ComponentHealth::degraded(
                        format!("Docker Hub optional service unavailable: {}", e),
                        None,
                    )
                }
            },
            Err(e) => {
                tracing::warn!("Failed to create HTTP client for Docker Hub: {:?}", e);
                ComponentHealth::degraded(format!("HTTP client error: {}", e), None)
            }
        }
    }

    #[tracing::instrument(name = "Check Redis health", skip(self))]
    async fn check_redis(&self) -> ComponentHealth {
        let redis_url =
            std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1/".to_string());
        let start = Instant::now();

        match redis::Client::open(redis_url.as_str()) {
            Ok(client) => {
                let conn_result =
                    tokio::task::spawn_blocking(move || client.get_connection()).await;

                match conn_result {
                    Ok(Ok(mut conn)) => {
                        let ping_result: Result<String, redis::RedisError> =
                            tokio::task::spawn_blocking(move || {
                                redis::cmd("PING").query(&mut conn)
                            })
                            .await
                            .unwrap_or_else(|_| {
                                Err(redis::RedisError::from((
                                    redis::ErrorKind::IoError,
                                    "Task join error",
                                )))
                            });

                        match ping_result {
                            Ok(_) => {
                                let elapsed = start.elapsed().as_millis() as u64;
                                let mut health = ComponentHealth::healthy(elapsed);

                                if elapsed > SLOW_RESPONSE_THRESHOLD_MS {
                                    health = ComponentHealth::degraded(
                                        "Redis responding slowly".to_string(),
                                        Some(elapsed),
                                    );
                                }

                                let mut details = HashMap::new();
                                details.insert("url".to_string(), serde_json::json!(redis_url));

                                health.with_details(details)
                            }
                            Err(e) => {
                                tracing::warn!("Redis PING failed: {:?}", e);
                                ComponentHealth::degraded(
                                    format!("Redis optional service unavailable: {}", e),
                                    None,
                                )
                            }
                        }
                    }
                    Ok(Err(e)) => {
                        tracing::warn!("Redis connection failed: {:?}", e);
                        ComponentHealth::degraded(
                            format!("Redis optional service unavailable: {}", e),
                            None,
                        )
                    }
                    Err(e) => {
                        tracing::warn!("Redis task failed: {:?}", e);
                        ComponentHealth::degraded(
                            format!("Redis optional service unavailable: {}", e),
                            None,
                        )
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Redis client creation failed: {:?}", e);
                ComponentHealth::degraded(
                    format!("Redis optional service unavailable: {}", e),
                    None,
                )
            }
        }
    }

    #[tracing::instrument(name = "Check Vault health", skip(self))]
    async fn check_vault(&self) -> ComponentHealth {
        let start = Instant::now();
        let vault_address = &self.settings.vault.address;
        let health_url = format!("{}/v1/sys/health", vault_address);

        match reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
        {
            Ok(client) => match client.get(&health_url).send().await {
                Ok(response) => {
                    let elapsed = start.elapsed().as_millis() as u64;
                    let status_code = response.status().as_u16();

                    match status_code {
                        200 | 429 | 472 | 473 => {
                            let mut health = ComponentHealth::healthy(elapsed);

                            if elapsed > SLOW_RESPONSE_THRESHOLD_MS {
                                health = ComponentHealth::degraded(
                                    "Vault responding slowly".to_string(),
                                    Some(elapsed),
                                );
                            }

                            let mut details = HashMap::new();
                            details.insert("address".to_string(), serde_json::json!(vault_address));
                            details
                                .insert("status_code".to_string(), serde_json::json!(status_code));

                            if let Ok(body) = response.json::<serde_json::Value>().await {
                                if let Some(initialized) = body.get("initialized") {
                                    details.insert("initialized".to_string(), initialized.clone());
                                }
                                if let Some(sealed) = body.get("sealed") {
                                    details.insert("sealed".to_string(), sealed.clone());
                                }
                            }

                            health.with_details(details)
                        }
                        _ => {
                            tracing::warn!("Vault returned unexpected status: {}", status_code);
                            ComponentHealth::degraded(
                                format!("Vault optional service status: {}", status_code),
                                Some(elapsed),
                            )
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("Vault health check failed: {:?}", e);
                    ComponentHealth::degraded(
                        format!("Vault optional service unavailable: {}", e),
                        None,
                    )
                }
            },
            Err(e) => {
                tracing::error!("Failed to create HTTP client for Vault: {:?}", e);
                ComponentHealth::degraded(format!("HTTP client error: {}", e), None)
            }
        }
    }

    #[tracing::instrument(name = "Check User Service health", skip(self))]
    async fn check_user_service(&self) -> ComponentHealth {
        let user_service_url = &self.settings.user_service_url;
        let health_url = format!("{}/plans/info/", user_service_url);

        let start = Instant::now();
        match reqwest::Client::builder()
            .timeout(Duration::from_secs(3))
            .http1_only()
            .build()
        {
            Ok(client) => match client.get(&health_url).send().await {
                Ok(response) => {
                    let elapsed = start.elapsed().as_millis() as u64;
                    let status_code = response.status().as_u16();

                    match status_code {
                        200 => {
                            let mut health = ComponentHealth::healthy(elapsed);

                            if elapsed > SLOW_RESPONSE_THRESHOLD_MS {
                                health = ComponentHealth::degraded(
                                    format!("User Service slow ({} ms)", elapsed),
                                    Some(elapsed),
                                );
                            }

                            let mut details = HashMap::new();
                            details.insert(
                                "url".to_string(),
                                serde_json::Value::String(user_service_url.clone()),
                            );
                            details.insert(
                                "response_time_ms".to_string(),
                                serde_json::Value::from(elapsed),
                            );

                            health.with_details(details)
                        }
                        _ => ComponentHealth::degraded(
                            format!(
                                "User Service returned status: {} (optional service)",
                                status_code
                            ),
                            Some(elapsed),
                        ),
                    }
                }
                Err(e) => {
                    tracing::warn!("User Service health check failed: {:?}", e);
                    ComponentHealth::degraded(
                        format!("User Service optional service unavailable: {}", e),
                        None,
                    )
                }
            },
            Err(e) => {
                tracing::warn!("Failed to create HTTP client for User Service: {:?}", e);
                ComponentHealth::degraded(format!("HTTP client error: {}", e), None)
            }
        }
    }

    #[tracing::instrument(name = "Check Install Service health", skip(self))]
    async fn check_install_service(&self) -> ComponentHealth {
        // Install service runs on http://install:4400/health
        let install_url = "http://install:4400/health";

        let start = Instant::now();
        match reqwest::Client::builder()
            .timeout(Duration::from_secs(3))
            .http1_only()
            .build()
        {
            Ok(client) => match client.get(install_url).send().await {
                Ok(response) => {
                    let elapsed = start.elapsed().as_millis() as u64;
                    let status_code = response.status().as_u16();

                    match status_code {
                        200 => {
                            let mut health = ComponentHealth::healthy(elapsed);

                            if elapsed > SLOW_RESPONSE_THRESHOLD_MS {
                                health = ComponentHealth::degraded(
                                    format!("Install Service slow ({} ms)", elapsed),
                                    Some(elapsed),
                                );
                            }

                            let mut details = HashMap::new();
                            details.insert(
                                "url".to_string(),
                                serde_json::Value::String(install_url.to_string()),
                            );
                            details.insert(
                                "response_time_ms".to_string(),
                                serde_json::Value::from(elapsed),
                            );

                            health.with_details(details)
                        }
                        _ => ComponentHealth::degraded(
                            format!(
                                "Install Service returned status: {} (optional service)",
                                status_code
                            ),
                            Some(elapsed),
                        ),
                    }
                }
                Err(e) => {
                    tracing::warn!("Install Service health check failed: {:?}", e);
                    ComponentHealth::degraded(
                        format!("Install Service optional service unavailable: {}", e),
                        None,
                    )
                }
            },
            Err(e) => {
                tracing::warn!("Failed to create HTTP client for Install Service: {:?}", e);
                ComponentHealth::degraded(format!("HTTP client error: {}", e), None)
            }
        }
    }
}
