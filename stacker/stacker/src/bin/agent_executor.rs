//! Agent Executor — standalone AMQP consumer for pipe/DAG step execution.
//!
//! Receives `StepCommand` messages from Stacker via RabbitMQ, executes steps
//! using the shared step_executor module (no DB dependencies), and publishes
//! `StepResultMsg` back. Includes in-memory circuit breaker + exponential backoff.
//!
//! Usage:
//!   agent-executor --amqp-url amqp://guest:guest@localhost:5672 --deployment-hash deploy-abc

use chrono::Utc;
use clap::Parser;
use futures_lite::stream::StreamExt;
use lapin::options::*;
use lapin::types::FieldTable;
use lapin::{BasicProperties, Channel, Connection, ConnectionProperties, ExchangeKind};
use std::sync::Arc;
use std::time::Instant;
use tokio::signal;
use tokio::sync::Notify;
use tracing::{error, info};

use stacker::models::agent_protocol::{routing, StepCommand, StepResultMsg, StepStatus};
use stacker::services::resilience_engine::{
    execute_with_resilience, CircuitBreakerConfig, InMemoryCircuitBreaker,
};

#[derive(Parser, Debug)]
#[command(name = "agent-executor", about = "Pipe step executor agent")]
struct Args {
    /// AMQP connection URL
    #[arg(
        long,
        env = "AMQP_URL",
        default_value = "amqp://guest:guest@localhost:5672"
    )]
    amqp_url: String,

    /// Deployment hash to scope this executor to
    #[arg(long, env = "DEPLOYMENT_HASH")]
    deployment_hash: String,

    /// Channel prefetch count (QoS)
    #[arg(long, default_value = "10")]
    prefetch: u16,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    info!(
        deployment_hash = %args.deployment_hash,
        prefetch = args.prefetch,
        "Starting agent-executor"
    );

    // Connect to RabbitMQ
    let conn = Connection::connect(&args.amqp_url, ConnectionProperties::default()).await?;
    info!("Connected to AMQP broker");

    let channel = conn.create_channel().await?;

    // Declare exchange
    channel
        .exchange_declare(
            routing::EXCHANGE,
            ExchangeKind::Topic,
            ExchangeDeclareOptions {
                durable: true,
                ..Default::default()
            },
            FieldTable::default(),
        )
        .await?;

    // Declare durable queue for this deployment
    let queue_name = routing::agent_queue(&args.deployment_hash);
    channel
        .queue_declare(
            &queue_name,
            QueueDeclareOptions {
                durable: true,
                ..Default::default()
            },
            FieldTable::default(),
        )
        .await?;

    // Bind to execute routing key
    let routing_key = routing::execute_key(&args.deployment_hash);
    channel
        .queue_bind(
            &queue_name,
            routing::EXCHANGE,
            &routing_key,
            QueueBindOptions::default(),
            FieldTable::default(),
        )
        .await?;

    // Set QoS
    channel
        .basic_qos(args.prefetch, BasicQosOptions::default())
        .await?;

    info!(queue = %queue_name, routing_key = %routing_key, "Listening for step commands");

    // Create publish channel (separate from consume channel)
    let publish_channel = conn.create_channel().await?;
    let publish_channel = Arc::new(publish_channel);

    // Circuit breaker (in-memory, per-process)
    let circuit_breaker = Arc::new(tokio::sync::Mutex::new(InMemoryCircuitBreaker::new(
        CircuitBreakerConfig {
            failure_threshold: 5,
            recovery_timeout: std::time::Duration::from_secs(30),
            half_open_max_requests: 2,
        },
    )));

    // Graceful shutdown
    let shutdown = Arc::new(Notify::new());
    let shutdown_clone = shutdown.clone();
    tokio::spawn(async move {
        let _ = signal::ctrl_c().await;
        info!("Received shutdown signal");
        shutdown_clone.notify_one();
    });

    // Start consuming
    let mut consumer = channel
        .basic_consume(
            &queue_name,
            &format!("agent-executor-{}", &args.deployment_hash),
            BasicConsumeOptions::default(),
            FieldTable::default(),
        )
        .await?;

    let result_routing_key = routing::result_key(&args.deployment_hash);

    loop {
        tokio::select! {
            _ = shutdown.notified() => {
                info!("Shutting down gracefully");
                break;
            }
            delivery = consumer.next() => {
                match delivery {
                    Some(Ok(delivery)) => {
                        let payload = delivery.data.clone();
                        let pub_ch = publish_channel.clone();
                        let result_rk = result_routing_key.clone();
                        let cb = circuit_breaker.clone();

                        // Process in spawned task for concurrency
                        tokio::spawn(async move {
                            let result_msg = process_step(&payload, cb).await;

                            // Publish result
                            if let Err(e) = publish_result(&pub_ch, routing::EXCHANGE, &result_rk, &result_msg).await {
                                error!(error = %e, "Failed to publish step result");
                            }

                            // ACK the delivery
                            if let Err(e) = delivery.ack(BasicAckOptions::default()).await {
                                error!(error = %e, "Failed to ACK delivery");
                            }
                        });
                    }
                    Some(Err(e)) => {
                        error!(error = %e, "Consumer error");
                        break;
                    }
                    None => {
                        info!("Consumer stream ended");
                        break;
                    }
                }
            }
        }
    }

    info!("Agent executor stopped");
    Ok(())
}

/// Process a single step command, returning the result message.
async fn process_step(
    payload: &[u8],
    circuit_breaker: Arc<tokio::sync::Mutex<InMemoryCircuitBreaker>>,
) -> StepResultMsg {
    let start = Instant::now();

    // Deserialize command
    let cmd: StepCommand = match serde_json::from_slice(payload) {
        Ok(cmd) => cmd,
        Err(e) => {
            error!(error = %e, "Failed to deserialize StepCommand");
            return StepResultMsg {
                execution_id: uuid::Uuid::nil(),
                step_id: uuid::Uuid::nil(),
                status: StepStatus::Failed,
                output_data: None,
                error: Some(format!("Deserialization error: {}", e)),
                duration_ms: start.elapsed().as_millis() as i64,
                timestamp: Utc::now(),
            };
        }
    };

    info!(
        execution_id = %cmd.execution_id,
        step_id = %cmd.step_id,
        step_type = %cmd.step_type,
        step_name = %cmd.step_name,
        "Processing step"
    );

    // Execute with resilience (retry + backoff + circuit breaker)
    let retry_policy = cmd.retry_policy.clone().unwrap_or_default();

    let mut cb = circuit_breaker.lock().await;
    let result = execute_with_resilience(
        &cmd.step_type,
        &cmd.config,
        &cmd.input_data,
        &retry_policy,
        &mut cb,
    )
    .await;
    drop(cb);

    let duration_ms = start.elapsed().as_millis() as i64;

    match result {
        Ok(output) => {
            info!(
                execution_id = %cmd.execution_id,
                step_id = %cmd.step_id,
                duration_ms,
                "Step completed successfully"
            );
            StepResultMsg::success(cmd.execution_id, cmd.step_id, output, duration_ms)
        }
        Err(e) => {
            error!(
                execution_id = %cmd.execution_id,
                step_id = %cmd.step_id,
                error = %e,
                duration_ms,
                "Step failed after retries"
            );
            StepResultMsg::failure(cmd.execution_id, cmd.step_id, e, duration_ms)
        }
    }
}

/// Publish a StepResultMsg to the AMQP exchange.
async fn publish_result(
    channel: &Channel,
    exchange: &str,
    routing_key: &str,
    result: &StepResultMsg,
) -> Result<(), String> {
    let payload = serde_json::to_vec(result).map_err(|e| format!("Serialize error: {}", e))?;
    channel
        .basic_publish(
            exchange,
            routing_key,
            BasicPublishOptions::default(),
            &payload,
            BasicProperties::default()
                .with_content_type("application/json".into())
                .with_delivery_mode(2), // persistent
        )
        .await
        .map_err(|e| format!("Publish error: {}", e))?
        .await
        .map_err(|e| format!("Confirm error: {}", e))?;
    Ok(())
}
