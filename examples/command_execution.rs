/// Example: Command execution with timeout monitoring
///
/// This demonstrates how to use CommandExecutor with TimeoutStrategy
/// to execute commands with multi-phase timeout handling.
///
/// Run with: cargo run --example command_execution
use status_panel::commands::executor::CommandExecutor;
use status_panel::commands::timeout::TimeoutStrategy;
use status_panel::transport::Command;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    // Create a command to execute
    let command = Command {
        id: "example-1".to_string(),
        command_id: "example-1".to_string(),
        name: "echo Hello from CommandExecutor!".to_string(),
        params: serde_json::json!({}),
        deployment_hash: None,
        app_code: None,
    };

    // Create executor with progress callback
    let executor = CommandExecutor::new().with_progress_callback(|phase, elapsed| {
        tracing::info!("⏱️  Command in {:?} phase after {}s", phase, elapsed);
    });

    // Use quick strategy for demonstration (10 second timeout)
    let strategy = TimeoutStrategy::quick_strategy(10);

    tracing::info!("🚀 Starting command execution: {}", command.name);

    // Execute the command
    let result = executor.execute(&command, strategy).await?;

    // Display results
    tracing::info!("✅ Command completed with status: {:?}", result.status);
    tracing::info!("📊 Exit code: {:?}", result.exit_code);
    tracing::info!("⏲️  Duration: {}s", result.duration_secs);

    if !result.stdout.is_empty() {
        tracing::info!("📤 stdout:\n{}", result.stdout);
    }

    if !result.stderr.is_empty() {
        tracing::info!("📤 stderr:\n{}", result.stderr);
    }

    // Convert to CommandResult for transport
    let command_result = result.to_command_result();
    tracing::info!(
        "📦 Transport payload: {}",
        serde_json::to_string_pretty(&command_result)?
    );

    Ok(())
}
